// Parse target files as data. Only Guardian's pinned parser is loaded.
const fs = require("node:fs");
const path = require("node:path");
const ts = require("typescript");

const rules = {
  "input-to-sql": ["CWE-89", "high", "External input reaches the SQL statement.",
    "Use a fixed SQL statement and supply values through bound parameters."],
  "input-to-eval": ["CWE-95", "high", "External input reaches JavaScript evaluation.",
    "Replace dynamic evaluation with a fixed set of allowed operations."],
  "input-to-html": ["CWE-79", "high", "External input reaches an HTML insertion point.",
    "Use textContent for plain text or sanitize HTML before insertion."],
  "tls-verification-disabled": ["CWE-295", "medium", "The Node process disables TLS certificate verification.",
    "Keep certificate verification enabled and configure the trusted CA."],
};

function member(node) {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) {
    return node.argumentExpression.text;
  }
}

function dottedName(node) {
  if (ts.isIdentifier(node)) return node.text;
  const key = member(node);
  if (key !== undefined) return dottedName(node.expression) + "." + key;
  return "";
}

function localChecker(parsed) {
  const file = parsed.fileName;
  // Bind lexical names locally without reading imports, tsconfig, or ambient types.
  const options = { allowJs: true, noLib: true, noResolve: true, types: [], noEmit: true };
  const host = ts.createCompilerHost(options);
  host.getSourceFile = name => name === file ? parsed : undefined;
  host.fileExists = name => name === file;
  host.readFile = name => name === file ? parsed.text : undefined;
  return ts.createProgram([file], options, host).getTypeChecker();
}

function inspectFile(file, text, result) {
  const parsed = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  if (parsed.parseDiagnostics.length) {
    const first = parsed.parseDiagnostics[0];
    const line = parsed.getLineAndCharacterOfPosition(first.start ?? 0).line + 1;
    result.diagnostics.push(file + ":" + line + " — " + ts.flattenDiagnosticMessageText(first.messageText, " "));
    return;
  }
  const checker = localChecker(parsed);
  const origins = new Map();

  function position(node) {
    const pos = parsed.getLineAndCharacterOfPosition(node.getStart(parsed));
    return { line: pos.line + 1, column: pos.character + 1 };
  }

  function origin(node) {
    if (!node) return undefined;
    if (origins.has(node)) return origins.get(node);
    origins.set(node, undefined); // Break cycles between aliases.
    const found = trace(node);
    origins.set(node, found);
    return found;
  }

  function trace(node) {
    if (ts.isIdentifier(node)) {
      const decl = checker.getSymbolAtLocation(node)?.valueDeclaration;
      if (decl && ts.isVariableDeclaration(decl) && (decl.parent.flags & ts.NodeFlags.Const)) {
        return origin(decl.initializer);
      }
      if (decl && ts.isBindingElement(decl) && ts.isObjectBindingPattern(decl.parent)) {
        const variable = decl.parent.parent;
        if (ts.isVariableDeclaration(variable) && (variable.parent.flags & ts.NodeFlags.Const)) {
          return origin(variable.initializer);
        }
      }
    } else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = dottedName(node);
      if (/^(req|request)\.(body|query|params|headers)$/.test(name) ||
          /^(window\.)?location\.(search|hash)$/.test(name)) return node;
      return origin(node.expression);
    } else if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) ||
               ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node)) {
      return origin(node.expression);
    } else if (ts.isBinaryExpression(node) && [
      ts.SyntaxKind.PlusToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken,
    ].includes(node.operatorToken.kind)) {
      return origin(node.left) || origin(node.right);
    } else if (ts.isTemplateExpression(node)) {
      for (const span of node.templateSpans) {
        const found = origin(span.expression);
        if (found) return found;
      }
    } else if (ts.isConditionalExpression(node)) {
      return origin(node.whenTrue) || origin(node.whenFalse);
    } else if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
               ["trim", "trimStart", "trimEnd", "slice", "substring", "toLowerCase", "toUpperCase"]
                 .includes(node.expression.name.text)) {
      return origin(node.expression.expression);
    }
  }

  function emit(rule, sink, source) {
    const [cwe, severity, message, remediation] = rules[rule];
    result.findings.push({ rule, cwe, severity, file, ...position(sink), message, remediation,
      source_line: source ? position(source).line : null,
      source: source ? dottedName(source) : null });
  }

  function visit(node) {
    let rule, input;
    if (ts.isCallExpression(node)) {
      const name = dottedName(node.expression);
      if (name === "eval" && !checker.getSymbolAtLocation(node.expression)?.valueDeclaration) {
        rule = "input-to-eval";
        input = node.arguments[0];
      } else if (/^(db|pool|connection|sequelize|[\w.]+\.sequelize)\.query$/.test(name)) {
        rule = "input-to-sql";
        input = node.arguments[0];
      } else if (member(node.expression) === "insertAdjacentHTML") {
        rule = "input-to-html";
        input = node.arguments[1];
      }
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (["innerHTML", "outerHTML"].includes(member(node.left))) {
        rule = "input-to-html";
        input = node.right;
      } else if (dottedName(node.left) === "process.env.NODE_TLS_REJECT_UNAUTHORIZED" &&
                 ts.isStringLiteralLike(node.right) && node.right.text === "0") {
        emit("tls-verification-disabled", node);
      }
    }
    if (rule) {
      const source = origin(input);
      if (source) emit(rule, node, source);
    }
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  result.files_scanned++;
}

module.exports = { localChecker, member, dottedName };

if (require.main === module) main();
function main() {
  const root = path.resolve(process.argv[2]);
  const output = path.resolve(process.argv[3]);
  const result = { files_scanned: 0, findings: [], diagnostics: [] };
  const ignored = new Set([".git", ".venv", "node_modules", "coverage", "dist", "build", ".angular", ".next"]);
  function scanDirectory(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name, "en"))) {
      const full = path.join(dir, entry.name);
      const file = path.relative(root, full).split(path.sep).join("/");
      try {
        if (entry.isDirectory()) {
          if (full !== output && !ignored.has(entry.name)) scanDirectory(full);
        } else if (entry.isFile() && /\.(?:[cm]?[jt]s|[jt]sx)$/i.test(file) &&
                   !/\.(?:min\.[cm]?js|d\.[cm]?ts)$/i.test(file)) {
          if (fs.statSync(full).size > 2 * 1024 * 1024) {
            result.diagnostics.push(file + " — skipped file larger than 2 MiB");
            continue;
          }
          inspectFile(file, fs.readFileSync(full, "utf8"), result);
        }
      } catch (err) {
        result.diagnostics.push(file + " — " + err.message);
      }
    }
  }
  scanDirectory(root);
  process.stdout.write(JSON.stringify(result));
}
