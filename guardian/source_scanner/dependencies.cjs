// Review each file as text. Module specifiers are evidence, never imports by the scanner.
const ts = require("typescript");
const { isBuiltin } = require("node:module");
const readline = require("node:readline");
const { localChecker, member, dottedName } = require("./scan.cjs");

function literal(n) {
  return n && ts.isStringLiteralLike(n) ? n.text : undefined;
}

function inspect({ file, owner, text }) {
  const ast = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const imports = [], findings = [];
  const line = node => ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
  let checker;
  function declaration(n) {
    checker ??= localChecker(ast);
    return checker.getSymbolAtLocation(n)?.valueDeclaration ?? checker.getSymbolAtLocation(n)?.declarations?.[0];
  }
  function required(n) {
    return n && ts.isCallExpression(n) && ts.isIdentifier(n.expression) &&
      n.expression.text === "require" && !declaration(n.expression) ? literal(n.arguments[0]) : undefined;
  }
  // Resolve the binding, including lexical shadowing and renamed imports.
  function binding(n, seen = new Set()) {
    if (!n || seen.has(n)) return;
    seen.add(n);
    const spec = required(n);
    if (spec) return { spec, api: "" };
    if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
      const base = binding(n.expression, seen);
      if (base && ["", "default"].includes(base.api) && member(n)) return { spec: base.spec, api: member(n) };
    }
    if (!ts.isIdentifier(n)) return;
    const decl = declaration(n);
    if (!decl) return;
    if (ts.isImportSpecifier(decl)) {
      return { spec: literal(decl.parent.parent.parent.moduleSpecifier), api: (decl.propertyName ?? decl.name).text };
    }
    if (ts.isImportClause(decl) || ts.isNamespaceImport(decl)) {
      const clause = ts.isImportClause(decl) ? decl : decl.parent;
      return { spec: literal(clause.parent.moduleSpecifier), api: "" };
    }
    if (ts.isImportEqualsDeclaration(decl) && ts.isExternalModuleReference(decl.moduleReference)) {
      return { spec: literal(decl.moduleReference.expression), api: "" };
    }
    if (ts.isVariableDeclaration(decl) && (decl.parent.flags & ts.NodeFlags.Const)) {
      return binding(decl.initializer, seen);
    }
    if (ts.isBindingElement(decl) && ts.isObjectBindingPattern(decl.parent)) {
      const variable = decl.parent.parent;
      if (ts.isVariableDeclaration(variable) && (variable.parent.flags & ts.NodeFlags.Const)) {
        const base = binding(variable.initializer, seen);
        if (base) return { spec: base.spec, api: (decl.propertyName ?? decl.name).text };
      }
    }
  }
  function option(obj, key) {
    if (!obj || !ts.isObjectLiteralExpression(obj)) return;
    // Stop at a later spread or computed key that could override the literal.
    for (const prop of [...obj.properties].reverse()) {
      if (ts.isSpreadAssignment(prop) || (prop.name && ts.isComputedPropertyName(prop.name))) return;
      if (prop.name?.text === key) return prop.initializer;
    }
  }
  function record(node, spec, kind) {
    if (spec !== undefined && (/^(\.|\/|#|[a-z]+:)/i.test(spec) && !isBuiltin(spec))) return;
    imports.push({ spec: spec ?? null, line: line(node), kind, builtin: !!spec && isBuiltin(spec) });
  }
  function finding(node, spec, rule, cwe, message, remediation) {
    findings.push({ line: line(node), spec, rule, cwe, message, remediation });
  }
  // Follow values from the parameters of public functions into interpreters.
  // This works for a previously unseen package, independent of its name/version.
  const publicFunctions = new Set();
  function markPublic(n) {
    if (!n) return;
    if (ts.isIdentifier(n)) {
      const decl = declaration(n);
      if (decl && ts.isFunctionDeclaration(decl)) publicFunctions.add(decl);
      if (decl && ts.isVariableDeclaration(decl) && decl.initializer && ts.isFunctionLike(decl.initializer)) {
        publicFunctions.add(decl.initializer);
      }
    } else if (ts.isFunctionLike(n)) publicFunctions.add(n);
    else if (ts.isObjectLiteralExpression(n)) {
      for (const prop of n.properties) {
        if (ts.isMethodDeclaration(prop)) publicFunctions.add(prop);
        else markPublic(prop.initializer ?? (ts.isShorthandPropertyAssignment(prop) ? prop.name : undefined));
      }
    }
  }
  function collectExports(n) {
    if (ts.isFunctionDeclaration(n) && n.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) {
      publicFunctions.add(n);
    } else if (ts.isVariableStatement(n) && n.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) {
      for (const decl of n.declarationList.declarations) markPublic(decl.initializer);
    } else if (ts.isExportAssignment(n)) markPublic(n.expression);
    else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
             /^(module\.exports(?:\.|$)|exports\.)/.test(dottedName(n.left))) markPublic(n.right);
    ts.forEachChild(n, collectExports);
  }
  function parameter(n, seen = new Set()) {
    if (!n || seen.has(n)) return;
    seen.add(n);
    if (ts.isIdentifier(n)) {
      const decl = declaration(n);
      if (decl && ts.isParameter(decl) && publicFunctions.has(decl.parent)) return decl;
      if (decl && ts.isVariableDeclaration(decl) && (decl.parent.flags & ts.NodeFlags.Const)) {
        return parameter(decl.initializer, seen);
      }
    } else if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n) ||
               ts.isAsExpression(n) || ts.isParenthesizedExpression(n)) return parameter(n.expression, seen);
    else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return parameter(n.left, seen) ?? parameter(n.right, seen);
    } else if (ts.isTemplateExpression(n)) {
      for (const span of n.templateSpans) {
        const found = parameter(span.expression, seen);
        if (found) return found;
      }
    }
  }
  function checkCall(n) {
    const args = n.arguments ?? [];
    // Only resolve symbols for calls with an argument shape relevant to a rule.
    const options = args.filter(ts.isObjectLiteralExpression);
    const pbkdf = args[2] && ts.isNumericLiteral(args[2]) && +args[2].text < 1000;
    const label = member(n.expression) ?? n.expression.text;
    if (["bypassSecurityTrustHtml", "bypassSecurityTrustResourceUrl", "bypassSecurityTrustScript"].includes(label) &&
        ts.isPropertyAccessExpression(n.expression) && args[0] && !ts.isStringLiteralLike(args[0])) {
      const receiver = n.expression.expression;
      const variable = declaration(ts.isPropertyAccessExpression(receiver) ? receiver.name : receiver);
      const init = variable?.initializer;
      let type;
      if (variable?.type && ts.isTypeReferenceNode(variable.type)) type = binding(variable.type.typeName);
      if (init && ts.isCallExpression(init)) {
        const factory = binding(init.expression);
        if (factory?.spec === "@angular/core" && factory.api === "inject") type = binding(init.arguments[0]);
      }
      if (type?.spec === "@angular/platform-browser" && type.api === "DomSanitizer") {
        finding(n, type.spec, "angular-trust-bypass", "CWE-79",
          "A DomSanitizer trust-bypass call marks a nonliteral value as trusted. Review its origin and rendering context.",
          "Prefer Angular's normal sanitization and trace the value to a trusted source before bypassing it.");
      }
    }
    if (owner && label === "allocUnsafe" && n.parent &&
        (ts.isReturnStatement(n.parent) || (ts.isArrowFunction(n.parent) && n.parent.body === n))) {
      let scope = n.parent;
      while (scope && !ts.isFunctionLike(scope)) scope = scope.parent;
      const receiver = n.expression.expression;
      if (publicFunctions.has(scope) && receiver && ts.isIdentifier(receiver) && receiver.text === "Buffer" &&
          !declaration(receiver)) {
        finding(n, null, "public-uninitialized-buffer", "CWE-908",
          "The public function returns an uninitialized Node buffer directly. Check if its bytes are exposed before filling.",
          "Initialize the buffer before returning it across a trust boundary.");
      }
    }
    if (publicFunctions.size && ["eval", "Function", "exec", "execSync", "runInNewContext", "runInThisContext"].includes(label)) {
      const bound = binding(n.expression);
      const globalEval = ts.isIdentifier(n.expression) && ["eval", "Function"].includes(label) && !declaration(n.expression);
      const shell = ["child_process", "node:child_process"].includes(bound?.spec) && ["exec", "execSync"].includes(bound.api);
      const vm = ["vm", "node:vm"].includes(bound?.spec) && ["runInNewContext", "runInThisContext"].includes(bound.api);
      const input = parameter(label === "Function" ? args.at(-1) : args[0]);
      if ((globalEval || shell || vm) && input) {
        finding(n, null, shell ? "public-input-to-shell" : "public-input-to-evaluator",
          shell ? "CWE-78" : "CWE-95",
          "A public function parameter flows into " + label + ". Review whether callers can supply untrusted input.",
          shell ? "Use a fixed executable and pass validated arguments without a shell." :
            "Avoid interpreting externally controlled text as code.");
        findings.at(-1).source_line = line(input);
      }
    }
    const weakCost = args[1] && ts.isNumericLiteral(args[1]) && +args[1].text >= 4 && +args[1].text < 8;
    const shortKey = literal(args[1]);
    if (!options.length && !pbkdf && !weakCost && !(shortKey && shortKey.length < 32) &&
        !(owner && args.length === 2)) return;
    const fn = binding(n.expression);
    if (!fn?.spec) return;
    const pkg = fn.spec.replace(/^node:/, "");
    const report = (rule, cwe, message, fix) => finding(n, fn.spec, rule, cwe, message, fix);
    if (["bcrypt", "bcryptjs"].includes(pkg) && ["hash", "hashSync"].includes(fn.api) && weakCost) {
      report("low-bcrypt-cost", "CWE-916", "The bcrypt call explicitly uses a work factor below 8.",
        "Calibrate a higher work factor for the deployment and rehash existing passwords during authentication.");
    }
    if (pkg === "jsonwebtoken" && ["sign", "verify"].includes(fn.api) && shortKey && shortKey.length < 32 &&
        literal(option(args[2], "algorithm")) !== "none") {
      report("embedded-jwt-key", "CWE-321", "The JWT call uses a short signing or verification key embedded in code.",
        "Load a strong signing key from a secret store and rotate previously exposed keys.");
    }
    if (owner && pkg === "crypto") {
      if (["pbkdf2", "pbkdf2Sync"].includes(fn.api) && pbkdf) {
        report("weak-pbkdf2-iterations", "CWE-916", "PBKDF2 uses fewer than 1,000 iterations.",
          "Review password-derived keys and increase the work factor or use a memory-hard KDF.");
      } else if (["createCipher", "createDecipher"].includes(fn.api)) {
        report("legacy-password-cipher", "CWE-916", "The package uses the legacy password-based cipher API.",
          "Use an explicit KDF with a random salt and an authenticated cipher with an appropriate IV.");
      }
    }
    if (owner && (pkg === "https" || pkg === "tls") && ["request", "get", "Agent", "connect"].includes(fn.api) &&
        options.some(o => option(o, "rejectUnauthorized")?.kind === ts.SyntaxKind.FalseKeyword)) {
      report("disabled-peer-verification", "CWE-295", "The dependency disables TLS peer verification.",
        "Enable certificate verification and configure the trusted CA.");
    }
    if (pkg === "jsonwebtoken" && fn.api === "sign" && literal(option(args[2], "algorithm")) === "none") {
      report("unsigned-jwt", "CWE-347", "The dependency call explicitly creates unsigned tokens.",
        "Use a signing algorithm and verify signatures before trusting claims.");
    }
    if (pkg === "jsonwebtoken" && fn.api === "verify") {
      const algs = option(args[2], "algorithms");
      if (algs && ts.isArrayLiteralExpression(algs) && algs.elements.some(a => literal(a) === "none")) {
        report("unsigned-jwt-accepted", "CWE-347", "JWT verification explicitly allows unsigned tokens.",
          "Restrict the allowed algorithms to the expected signature algorithm.");
      }
    }
    if (pkg === "request" && options.some(o => option(o, "strictSSL")?.kind === ts.SyntaxKind.FalseKeyword)) {
      report("request-tls-disabled", "CWE-295", "The request call explicitly disables certificate verification.",
        "Enable strictSSL and configure the trusted CA.");
    }
    if (pkg === "pg" && ["Client", "Pool"].includes(fn.api) &&
        option(option(args[0], "ssl"), "rejectUnauthorized")?.kind === ts.SyntaxKind.FalseKeyword) {
      report("postgres-tls-disabled", "CWE-295", "The PostgreSQL client disables TLS peer verification.",
        "Enable peer verification and configure the database CA.");
    }
  }
  function visit(n) {
    if (ts.isImportDeclaration(n) || (ts.isExportDeclaration(n) && n.moduleSpecifier)) {
      record(n, literal(n.moduleSpecifier), ts.isExportDeclaration(n) ? "export" : "import");
    } else if (ts.isImportEqualsDeclaration(n) && ts.isExternalModuleReference(n.moduleReference)) {
      record(n, literal(n.moduleReference.expression), "import");
    } else if (ts.isImportTypeNode(n) && ts.isLiteralTypeNode(n.argument)) {
      record(n, literal(n.argument.literal), "type import");
    } else if (ts.isCallExpression(n) || ts.isNewExpression(n)) {
      if (ts.isCallExpression(n)) {
        const name = dottedName(n.expression);
        if (n.expression.kind === ts.SyntaxKind.ImportKeyword) record(n, literal(n.arguments[0]), "dynamic import");
        else if (name === "require" || name === "require.resolve") {
          const id = name === "require" ? n.expression : n.expression.expression;
          if (!declaration(id)) record(n, literal(n.arguments[0]), name);
        }
      }
      checkCall(n);
    } else if (owner && ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        dottedName(n.left) === "process.env.NODE_TLS_REJECT_UNAUTHORIZED" && literal(n.right) === "0") {
      finding(n, null, "process-tls-disabled", "CWE-295", "Package code disables TLS verification process-wide.",
        "Remove the override and configure the trusted CA.");
    }
    ts.forEachChild(n, visit);
  }
  // Keep recoverable import evidence from malformed fragments, suppress their security matches.
  if (owner) collectExports(ast);
  visit(ast);
  const err = ast.parseDiagnostics[0];
  return { file, owner, imports, findings: err ? [] : findings,
    diagnostic: err ? ts.flattenDiagnosticMessageText(err.messageText, " ") : null };
}

(async () => {
  for await (const row of readline.createInterface({ input: process.stdin, crlfDelay: Infinity })) {
    const input = JSON.parse(row);
    try {
      process.stdout.write(JSON.stringify(inspect(input)) + "\n");
    } catch (err) {
      process.stdout.write(JSON.stringify({ file: input.file, owner: input.owner, imports: [], findings: [],
        diagnostic: err.message }) + "\n");
    }
  }
})().catch(err => { console.error(err.message); process.exitCode = 1; });
