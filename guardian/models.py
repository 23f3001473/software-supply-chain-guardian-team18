from typing import Optional
from pydantic import BaseModel, Field


class Component(BaseModel):
    name: str
    version: str
    ecosystem: str  # npm, docker, github-actions
    direct: bool = False
    scope: str = "prod"  # prod, dev, optional
    lock_path: str = ""  # node_modules/... path in package-lock.json
    declared_range: Optional[str] = None
    pinning: str = "exact"  # exact, range, tag, digest, sha, branch
    resolved: Optional[str] = None
    integrity: Optional[str] = None
    has_install_script: bool = False
    license: Optional[str] = None
    source_file: str = ""


class Manifest(BaseModel):
    path: str
    kind: str  # manifest, lockfile, container, ci
    ecosystem: str


class Inventory(BaseModel):
    repo: str
    app_name: str
    app_version: str
    commit: Optional[str] = None
    manifests: list[Manifest] = []
    components: list[Component] = []
    declared_not_locked: list[str] = []

    def npm(self):
        return [c for c in self.components if c.ecosystem == "npm"]


class SbomSummary(BaseModel):
    path: str
    tool: str
    format: str
    spec_version: str
    component_count: int
    npm_component_count: int
    matched_inventory: int
    sbom_only: list[str] = []
    note: str = ""


class GraphSummary(BaseModel):
    json_path: str
    html_path: str
    nodes: int
    edges: int
    direct: int
    transitive: int
    unresolved_edges: list[str] = []


class Vulnerability(BaseModel):
    id: str
    aliases: list[str] = []
    package: str
    installed_version: str
    severity: str
    affected_range: Optional[str] = None
    fixed_version: Optional[str] = None
    fixed_version_source: Optional[str] = None
    title: str = ""
    direct: bool
    scope: str
    dependency_path: list[str] = []
    introduced_via: list[str] = []
    evidence_source: str
    reference: Optional[str] = None


class SuspiciousFinding(BaseModel):
    id: str
    category: str
    severity: str
    file: str
    title: str
    before: Optional[str] = None
    after: Optional[str] = None
    why_suspicious: str
    evidence: dict = Field(default_factory=dict)
    kind: str = "change"  # change (git diff) or baseline (static posture)


class AgentLog(BaseModel):
    agent: str
    status: str
    message: str
