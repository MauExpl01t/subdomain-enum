"""Modelos de datos compartidos. Mismo patrón que WebScan: Finding/Severity
para lo que está mal, y un ScanResult que además guarda el inventario de
subdominios descubiertos (que no son "hallazgos": la mayoría no tiene nada
malo, son el mapa del terreno)."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {0: "Informativo", 1: "Baja", 2: "Media", 3: "Alta", 4: "Crítica"}[int(self)]


@dataclass
class Finding:
    """Un problema de seguridad encontrado (aviso de wildcard, takeover)."""

    check: str
    title: str
    severity: Severity
    description: str
    recommendation: str = ""
    evidence: str = ""
    reference: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["severity_label"] = self.severity.label
        return d


@dataclass
class Subdomain:
    """Un subdominio descubierto. No es un hallazgo: es un dato del inventario."""

    host: str
    source: str  # "pasiva" | "fuerza_bruta"
    ips: list[str] = field(default_factory=list)
    alive: bool = False
    scheme: str = ""          # "https" | "http" | ""
    status: int | None = None
    title: str = ""
    server: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    domain: str
    started_at: str
    finished_at: str = ""
    subdomains: list[Subdomain] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    wildcard_ips: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.check))

    def sorted_subdomains(self) -> list[Subdomain]:
        return sorted(self.subdomains, key=lambda s: (not s.alive, s.host))

    def summary(self) -> dict[str, int]:
        counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "wildcard_ips": self.wildcard_ips,
            "summary": self.summary(),
            "subdomains": [s.to_dict() for s in self.sorted_subdomains()],
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }
