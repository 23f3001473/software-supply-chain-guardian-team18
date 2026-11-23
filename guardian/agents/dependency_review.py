"""Offline npm dependency discovery and source review. Target code is never imported."""
import base64
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

OUTPUT = "dependency_review.json"
SCANNER = Path(__file__).resolve().parents[1] / "source_scanner" / "dependencies.cjs"
SKIP = {".git", ".venv", ".angular", ".next", ".cache", "__pycache__", "coverage"}
FIELDS = ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies")
JS = re.compile(r"\.(?:[cm]?[jt]s|[jt]sx)$", re.I)
PACKAGE = re.compile(r"^(?:@[^/@\\:\s]+/)?[^./@\\:\s][^/@\\:\s]*(?:/|$)")
FILE_LIMIT = 2 * 1024 * 1024
ARCHIVE_LIMIT = 64 * 1024 * 1024


def package_name(spec):
    match = PACKAGE.match(spec)
    return match.group().rstrip("/") if match else None


def module_owner(path):
    """The nearest installed package, including its scope and nesting."""
    parts = PurePosixPath(path).parts
    if "node_modules" not in parts:
        return None
    start = len(parts) - 1 - parts[::-1].index("node_modules") + 1
    if start >= len(parts) or parts[start].startswith("."):
        return None
    end = start + (2 if parts[start].startswith("@") else 1)
    return "/".join(parts[:end]) if end <= len(parts) else None


def default_cache():
    configured = os.getenv("GUARDIAN_NPM_CACHE") or os.getenv("npm_config_cache")
    if configured:
        return Path(configured)
    if os.name == "nt" and os.getenv("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "npm-cache"
    return Path.home() / ".npm"


def cached_archive(cache, integrity):
    for token in (integrity or "").split():
        algorithm, _, encoded = token.partition("-")
        if algorithm not in ("sha512", "sha384", "sha256", "sha1"):
            continue
        try:
            digest = base64.b64decode(encoded, validate=True).hex()
        except ValueError:
            continue
        if len(digest) != hashlib.new(algorithm).digest_size * 2:
            continue
        path = cache / "_cacache" / "content-v2" / algorithm / digest[:2] / digest[2:4] / digest[4:]
        if path.is_file():
            if path.stat().st_size > ARCHIVE_LIMIT:
                raise ValueError("cached archive exceeds size limit")
            raw = path.read_bytes()
            if hashlib.new(algorithm, raw).hexdigest() != digest:
                raise ValueError("cached archive fails lockfile integrity verification")
            return raw
    return None


class Review:
    def __init__(self, repo, out, cache):
        self.repo, self.out, self.cache = repo, out, cache
        self.packages = {}
        self.manifests = []
        self.declarations = []
        self.files = []
        self.imports = []
        self.findings = []
        self.diagnostics = []
        self.workspaces = {}
        self.project_manifests = {}
        self.app_files = 0

    def package(self, slot):
        if slot not in self.packages:
            self.packages[slot] = {
                "path": slot, "name": slot.rsplit("node_modules/", 1)[-1], "version": None,
                "source": "missing", "locked_version": None, "files_reviewed": 0, "files_skipped": 0,
                "declared_by": [], "application_imports": 0,
            }
        return self.packages[slot]

    def note(self, file, message, owner=None):
        self.diagnostics.append({"file": file, "message": str(message)})
        if owner:
            self.package(owner)["files_skipped"] += 1

    def manifest(self, file, data, owner):
        folder = str(PurePosixPath(file).parent)
        if owner and folder == owner:
            p = self.package(owner)
            p.update(name=data.get("name") or p["name"], version=data.get("version"), source="installed")
        if not owner:
            self.manifests.append(file)
            self.project_manifests[folder] = data
        if owner and folder != owner:
            return
        for field in FIELDS:
            if owner and field == "devDependencies":
                continue
            for name, spec in (data.get(field) or {}).items():
                if package_name(name) == name:
                    self.declarations.append((folder, name, file, field, spec, owner))

    def lock(self, file, data):
        self.manifests.append(file)
        if not isinstance(data.get("packages"), dict):
            self.note(file, "Expected npm lockfile v2/v3 packages map")
            return
        base = PurePosixPath(file).parent
        for key, info in data["packages"].items():
            relative = PurePosixPath(key)
            if relative.is_absolute() or ".." in relative.parts or "\\" in key or ":" in key:
                self.note(file, "Ignored invalid installation path")
                continue
            slot = str(base / relative)
            if not key or ("node_modules" not in relative.parts and not relative.is_absolute()):
                for field in FIELDS:
                    for name, spec in (info.get(field) or {}).items():
                        if package_name(name) == name:
                            self.declarations.append((slot, name, file, field, spec, None))
            if not key or module_owner(slot) != slot:
                continue
            p = self.package(slot)
            p["locked_version"] = info.get("version")
            if p["source"] != "installed":
                p.update(name=info.get("name") or p["name"], version=info.get("version"))
            p["integrity"] = info.get("integrity")
            if info.get("link"):
                target = PurePosixPath(info.get("resolved", ""))
                if not target.is_absolute() and ".." not in target.parts and target.parts:
                    self.workspaces[str(base / target)] = slot
            for field in FIELDS[:3]:
                for name, spec in (info.get(field) or {}).items():
                    if package_name(name) == name:
                        self.declarations.append((slot, name, file, field, spec, slot))

    def discover(self):
        for directory, dirs, files in os.walk(self.repo, onerror=lambda e: self.note(str(e.filename), e)):
            parent = Path(directory)
            rel = parent.relative_to(self.repo).as_posix()
            owner = module_owner(rel)
            dirs[:] = sorted(d for d in dirs if d not in SKIP and not (parent / d).is_symlink()
                             and (parent / d).resolve().is_relative_to(self.repo)
                             and (parent / d) != self.out and
                             not (parent.name == "node_modules" and d.startswith(".")) and
                             not (not owner and d in ("build", "dist")))
            for name in sorted(files):
                path = parent / name
                file = path.relative_to(self.repo).as_posix()
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    if name == "package.json":
                        self.manifest(file, json.loads(path.read_text(encoding="utf-8-sig")), owner)
                    elif not owner and name in ("package-lock.json", "npm-shrinkwrap.json"):
                        self.lock(file, json.loads(path.read_text(encoding="utf-8-sig")))
                    elif JS.search(name):
                        self.files.append((path, file, owner))
                except (ValueError, OSError, TypeError, AttributeError) as err:
                    self.note(file, err, owner)
        for folder, slot in self.workspaces.items():
            if folder in self.project_manifests:
                manifest = self.project_manifests[folder]
                p = self.package(slot)
                p.update(source="workspace", version=manifest.get("version"), name=manifest.get("name") or p["name"])
        for p in self.packages.values():
            if p["source"] == "installed" and p["locked_version"] and p["version"] != p["locked_version"]:
                self.note(p["path"], f"Installed version {p['version']} differs from lockfile {p['locked_version']}")

    def resolve(self, folder, name):
        folder = PurePosixPath(folder)
        for parent in (folder, *folder.parents):
            if parent.name == "node_modules":
                continue
            slot = str(parent / "node_modules" / name)
            if slot in self.packages and self.packages[slot]["source"] != "unresolved":
                return slot
        # Keep unresolved references visible without assigning them an invented version.
        slot = "unresolved:" + name
        self.package(slot).update(name=name, source="unresolved")
        return slot

    def analyze(self):
        node = shutil.which("node")
        if not node or not (SCANNER.parent / "node_modules" / "typescript").is_dir():
            raise RuntimeError("The offline scanner requires Node.js and Guardian's installed TypeScript parser.")
        workspace_paths = sorted(self.workspaces, key=len, reverse=True)
        with tempfile.TemporaryFile() as requests, tempfile.TemporaryFile() as responses:
            def submit(file, owner, raw):
                if len(raw) > FILE_LIMIT:
                    self.note(file, "File exceeds 2 MiB scan limit", owner)
                    return
                text = raw.decode("utf-8-sig")
                requests.write(json.dumps(dict(file=file, owner=owner, text=text), ensure_ascii=True).encode() + b"\n")

            for path, file, owner in self.files:
                if not owner:
                    folder = next((w for w in workspace_paths if file.startswith(w + "/")), None)
                    if folder:
                        owner = self.workspaces[folder]
                if owner and self.package(owner)["source"] == "missing":
                    self.package(owner).update(source="installed without manifest", version=None)
                    self.note(owner, "Local code has no readable package manifest. Version is unverified.")
                try:
                    with path.open("rb") as stream:
                        submit(file, owner, stream.read(FILE_LIMIT + 1))
                except (OSError, UnicodeError) as err:
                    self.note(file, err, owner)
            for slot, p in list(self.packages.items()):
                if p["source"] != "missing":
                    continue
                try:
                    raw = cached_archive(self.cache, p.get("integrity"))
                    if raw is None:
                        continue
                    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                        payload = gz.read(ARCHIVE_LIMIT + 1)
                    if len(payload) > ARCHIVE_LIMIT:
                        raise ValueError("Expanded archive exceeds size limit")
                    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
                        for item in archive:
                            parts = PurePosixPath(item.name).parts
                            if (not item.isfile() or len(parts) < 2 or parts[0] != "package" or ".." in parts
                                    or "node_modules" in parts or not JS.search(item.name)):
                                continue
                            file = "/".join([slot, *parts[1:]])
                            if item.size > FILE_LIMIT:
                                self.note(file, "File exceeds 2 MiB scan limit", slot)
                                continue
                            try:
                                submit(file, slot, archive.extractfile(item).read())
                            except UnicodeError as err:
                                self.note(file, err, slot)
                    p["source"] = "verified npm cache"
                except (OSError, EOFError, ValueError, tarfile.TarError) as err:
                    self.note(slot, err, slot)
            requests.seek(0)
            proc = subprocess.run([node, str(SCANNER)], cwd=SCANNER.parent,
                                  stdin=requests, stdout=responses, stderr=subprocess.PIPE, timeout=1200)
            if proc.returncode:
                raise RuntimeError(proc.stderr.decode(errors="replace")[-1200:])
            responses.seek(0)
            for row in responses:
                self.collect(json.loads(row))

    def collect(self, row):
        owner, file = row["owner"], row["file"]
        folder = PurePosixPath(file).parent
        if row["diagnostic"]:
            self.note(file, row["diagnostic"], owner)
        elif re.search(r"\.d\.[cm]?ts$", file, re.I):
            pass  # Imports still count, declarations contain no runtime implementation.
        elif owner:
            self.package(owner)["files_reviewed"] += 1
        else:
            self.app_files += 1
        for ref in row["imports"]:
            spec = ref["spec"]
            name = package_name(spec) if spec and not ref["builtin"] else None
            slot = self.resolve(folder, name) if name else None
            self.imports.append({"file": file, "owner": owner, "dependency": slot, **ref})
            if not owner and slot:
                self.package(slot)["application_imports"] += 1
        for hit in row["findings"]:
            spec = hit.pop("spec")
            # Built-in APIs only produce findings inside a third-party implementation.
            builtin = spec is None or spec.removeprefix("node:") in ("crypto", "tls", "https")
            dep = owner if builtin else self.resolve(folder, package_name(spec))
            if dep:
                kind = "package implementation" if owner == dep else "dependency API usage" if owner else "application usage"
                test = bool(re.search(r"(?:^|/)(?:tests?|__tests__|fixtures)/|\.(?:spec|test)\.[cm]?[jt]sx?$", file, re.I))
                self.findings.append({"file": file, "dependency": dep, "owner": owner, "kind": kind,
                                      "test_file": test,
                                      "package": self.package(dep)["name"], "version": self.package(dep)["version"],
                                      "evidence_source": "Offline rules", **hit})

    def run(self):
        self.discover()
        self.analyze()
        for folder, name, file, field, spec, owner in self.declarations:
            slot = self.resolve(folder, name)
            entry = {"file": file, "owner": owner, "field": field, "requested": spec}
            declared = self.package(slot)["declared_by"]
            if entry not in declared:
                declared.append(entry)
        for p in self.packages.values():
            p.pop("integrity", None)
            p["direct"] = bool(p["application_imports"] or any(d["owner"] is None for d in p["declared_by"]))
        packages = sorted(self.packages.values(), key=lambda p: p["path"])
        counts = dict(Counter(p["source"] for p in packages))
        dynamic = sum(r["spec"] is None for r in self.imports)
        reviewed = sum(p["files_reviewed"] > 0 for p in packages)
        return {"status": "partial" if self.diagnostics or dynamic or reviewed < len(packages) else "complete",
                "manifests": sorted(self.manifests), "packages": packages, "imports": self.imports,
                "findings": self.findings, "diagnostics": self.diagnostics,
                "coverage": {"packages": len(packages), "packages_reviewed": reviewed, "sources": counts,
                             "application_files": self.app_files, "dynamic_references": dynamic,
                             "dependency_files": sum(p["files_reviewed"] for p in packages)}}


def scan(repo, out, cache=None):
    repo, out = Path(repo).resolve(), Path(out).resolve()
    result = {"repo": str(repo), "generated_at": datetime.now(timezone.utc).isoformat()}
    try:
        if not repo.is_dir():
            raise ValueError(f"Missing repository {repo}")
        result.update(Review(repo, out, Path(cache) if cache else default_cache()).run())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as err:
        result.update(status="error", diagnostics=[{"file": str(repo), "message": str(err)}])
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=out, delete=False, mode="w", encoding="utf-8") as tmp:
        json.dump(result, tmp, ensure_ascii=True, separators=(",", ":"))
    try:
        os.replace(tmp.name, out / OUTPUT)
    finally:
        Path(tmp.name).unlink(missing_ok=True)
    return result
