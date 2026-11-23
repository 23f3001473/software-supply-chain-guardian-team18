"""Local API and React dashboard for Software Supply Chain Guardian."""

import io
import json
import logging
import subprocess
import zipfile
from itertools import islice
from mimetypes import guess_type
from pathlib import Path
from threading import Lock, Thread
from typing import Literal
from urllib.parse import quote
from uuid import uuid4

import networkx as nx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from guardian import vuln_graph
from guardian.agents.dependency_review import OUTPUT as OFFLINE_REPORT
from guardian.repo_fetch import TARGETS, FetchError, fetch, out_dir_for, parse_github_url
from guardian.workflow import run_stream

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
DIST = ROOT / "frontend" / "dist"
ARTIFACTS = {
    "evidence_report.json", "evidence_report.md", "inventory.json",
    "dependency_inventory.json", "dependency_graph.json", "dependency_graph.html",
    "vulnerability_graph.svg", "vulnerability_findings.json", "fix_recommendations.json",
    "fix_recommendations.csv", "suspicious_changes.json", "history.jsonl",
    OFFLINE_REPORT,
}
app = FastAPI(title="Guardian")
lock = Lock()
job = None
logger = logging.getLogger(__name__)


class Inspection(BaseModel):
    repository: str | None = None
    github_url: str | None = Field(default=None, max_length=2048)
    refresh: bool = False
    baseline: str = "HEAD"
    scanner: Literal["auto", "osv", "npm-audit"] = "auto"


def load(directory, filename, default=None):
    path = artifact(directory, filename)
    return json.loads(path.read_text(encoding="utf-8")) if path else default


def repositories():
    sources = {}
    if TARGETS.is_dir():
        sources = {
            p.name: p for p in sorted(TARGETS.iterdir())
            if p.resolve().parent == TARGETS and (p / "package.json").is_file()
        }
    if (REPORTS / "evidence_report.json").is_file():
        sources.setdefault("juice-shop", None)
    if REPORTS.is_dir():
        for p in REPORTS.iterdir():
            if p.resolve().parent == REPORTS and (p / "evidence_report.json").is_file():
                sources.setdefault(p.name, None)
    return sources


def repository(name):
    sources = repositories()
    if name not in sources:
        raise HTTPException(404, "Repository not found.")
    source = sources[name]
    out = out_dir_for(TARGETS / name)
    if out.resolve() != out:
        raise HTTPException(404, "Report directory not found.")
    return source, out


def commits(source):
    head = [{"ref": "HEAD", "label": "Latest commit (uncommitted changes only)"}]
    if source is None:
        return []
    result = subprocess.run(
        ["git", "-C", str(source), "log", "-n200", "--date=short", "--format=%h|%ad|%s"],
        capture_output=True, encoding="utf-8", errors="replace", timeout=15,
    )
    for line in result.stdout.splitlines()[1:]:
        ref, date, subject = line.split("|", 2)
        head.append({"ref": ref, "label": f"{date} · {subject}"})
    return head


def artifact(out, name):
    path = out / name
    return path if path.is_file() and path.resolve().parent == out else None


def require_idle():
    if job and job["status"] == "running":
        raise HTTPException(409, "An inspection is running. Try again when it finishes.")


@app.get("/api/repositories")
def list_repositories():
    with lock:
        require_idle()
        result = []
        for name in sorted(repositories()):
            source, out = repository(name)
            report = load(out, "evidence_report.json") or {}
            result.append({"name": name, "local": source is not None,
                           "inspected": report.get("generated_at"), "metrics": report.get("metrics")})
        return result


@app.get("/api/repositories/{name}")
def dashboard(name: str):
    with lock:
        require_idle()
        source, out = repository(name)
        report = load(out, "evidence_report.json")
        inventory = load(out, "inventory.json", {})
        offline_summary = (report or {}).get("offline_review")
        offline_findings = []
        if offline_summary and offline_summary["status"] != "error":
            offline_findings = load(out, OFFLINE_REPORT, {}).get("findings", [])
        bom = f"{name}-sbom.json"
        return {
            "report": report,
            "commits": commits(source),
            "infrastructure": [c for c in inventory.get("components", [])
                               if c.get("ecosystem") in {"docker", "github-actions"}],
            "vulnerabilities": load(out, "vulnerability_findings.json", {}),
            "offlineFindings": offline_findings,
            "changes": load(out, "suspicious_changes.json", {}),
            "artifacts": sorted(n for n in ARTIFACTS | {bom} if artifact(out, n)),
            "sbomFile": bom if artifact(out, bom) else None,
        }


@app.get("/api/repositories/{name}/artifacts/{filename}")
def download(name: str, filename: str, inline: bool = False):
    with lock:
        require_idle()
        _, out = repository(name)
        allowed = ARTIFACTS | {f"{name}-sbom.json"}
        headers = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
        if filename == "bundle.zip" and artifact(out, "evidence_report.json"):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
                candidates = list(out.iterdir())
                raw = out / "raw"
                if raw.is_dir() and raw.resolve() == raw:
                    candidates.extend(raw.iterdir())
                for path in sorted(candidates):
                    if path.is_file() and path.resolve().parent == path.parent:
                        archive.write(path, path.relative_to(out))
            headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(name, safe='')}-guardian.zip"
            return Response(buf.getvalue(), media_type="application/zip", headers=headers)
        path = artifact(out, filename) if filename in allowed else None
        if path is None:
            raise HTTPException(404, "Artifact not found.")
        if inline:
            headers["Content-Security-Policy"] = (
                "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; img-src data:"
            )
        disposition = "inline" if inline else "attachment"
        headers["Content-Disposition"] = f"{disposition}; filename*=UTF-8''{quote(filename, safe='')}"
        return Response(path.read_bytes(), media_type=guess_type(path)[0] or "application/octet-stream", headers=headers)


@app.get("/api/repositories/{name}/history")
def inspection_history(name: str):
    with lock:
        require_idle()
        _, out = repository(name)
        path = artifact(out, "history.jsonl")
        if path is None:
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def dependency_graph(out):
    graph = load(out, "dependency_graph.json")
    g = nx.DiGraph()
    if graph:
        g.add_nodes_from((n["id"], n) for n in graph["nodes"])
        g.add_edges_from((e["from"], e["to"]) for e in graph["edges"])
    if "ROOT" not in g:
        raise HTTPException(404, "Dependency graph not available.")
    return g


@app.get("/api/repositories/{name}/dependency-paths")
def dependency_paths(name: str, node: str):
    with lock:
        require_idle()
        _, out = repository(name)
        graph = dependency_graph(out)
    if node not in graph or node == "ROOT":
        raise HTTPException(404, "Package not found in the dependency graph.")
    try:
        paths = nx.shortest_simple_paths(graph, "ROOT", node)
        return [[graph.nodes[h]["label"] for h in path] for path in islice(paths, 3)]
    except nx.NetworkXNoPath:
        return []


@app.get("/api/repositories/{name}/vulnerability-map")
def vulnerability_map(name: str, routes: int = Query(default=1, ge=1, le=3)):
    with lock:
        require_idle()
        _, out = repository(name)
        graph = dependency_graph(out)
        findings = load(out, "vulnerability_findings.json", {}).get("findings", [])
    labels = {f"{v['package']}@{v['installed_version']}" for v in findings}
    vulnerable_nodes = {node for node, entry in graph.nodes(data=True) if entry.get("label") in labels}
    svg = vuln_graph.radial_svg(graph, vulnerable_nodes, per_node=routes)
    return Response(svg, media_type="image/svg+xml", headers={
        "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
        "X-Content-Type-Options": "nosniff",
    })


def run_inspection(request, source, current):
    def log(entry):
        with lock:
            current["log"].append(entry)

    def fetch_log(message):
        log({"agent": "Repository fetch", "status": "info", "message": message})

    error = None
    try:
        if request.github_url:
            source = fetch(request.github_url, request.refresh, log=fetch_log)
        with lock:
            current["repository"] = source.name
        final = None
        for event, value in run_stream(str(source), str(out_dir_for(source)), request.baseline, request.scanner):
            if event == "log":
                log(value.model_dump())
            else:
                final = value
        if not final or not final.get("report"):
            error = "The inspection did not produce a report. Review the agent log."
        elif final.get("errors"):
            error = "The inspection finished with agent errors. Review the agent log."
    except (FetchError, subprocess.TimeoutExpired) as exc:
        error = str(exc)
    except Exception:
        logger.exception("Inspection failed")
        error = "The inspection stopped unexpectedly. See the server log for details."
    finally:
        with lock:
            current.update(status="error" if error else "complete", error=error)


@app.post("/api/inspections", status_code=202)
def start_inspection(request: Inspection):
    global job
    with lock:
        require_idle()
        if bool(request.github_url) == bool(request.repository):
            raise HTTPException(400, "Supply either a GitHub link or a local repository.")
        source = None
        if request.github_url:
            try:
                parse_github_url(request.github_url)
            except FetchError as exc:
                raise HTTPException(400, str(exc)) from exc
            if request.baseline != "HEAD":
                raise HTTPException(400, "Use the latest commit when fetching a repository.")
        else:
            source, _ = repository(request.repository)
            if source is None:
                raise HTTPException(400, "Fetch the repository before inspecting it again.")
            if request.baseline not in {commit["ref"] for commit in commits(source)}:
                raise HTTPException(400, "Choose a baseline from the repository's recent commits.")
        job = {"id": uuid4().hex, "status": "running", "repository": request.repository,
               "error": None, "log": []}
        Thread(target=run_inspection, args=(request, source, job), daemon=True).start()
        return {"id": job["id"]}


@app.get("/api/inspections")
def latest_inspection():
    with lock:
        return inspection_status()


@app.get("/api/inspections/{inspection_id}")
def inspect_status(inspection_id: str):
    with lock:
        if not job or job["id"] != inspection_id:
            raise HTTPException(404, "Inspection not found.")
        return inspection_status()


def inspection_status():
    return {**job, "log": list(job["log"])} if job else None


if DIST.joinpath("assets").is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")


@app.get("/", response_class=HTMLResponse)
def frontend():
    index = DIST / "index.html"
    if index.is_file():
        return FileResponse(index)
    return HTMLResponse("Build the dashboard with npm --prefix frontend ci and npm --prefix frontend run build.",
                        status_code=503)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8501)
