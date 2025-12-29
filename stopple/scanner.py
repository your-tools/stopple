from dataclasses import dataclass
from stopple.repository import Repository
from stopple.nvd.api import Cve
from stopple.vulnerabilities import Range

from rpm_vercmp import vercmp


@dataclass
class Diagnostic:
    package: str
    vulnerable: bool
    cves: list[Cve]
    upgrade: Range | None = None


class Scanner:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def get_diagnostic(self, package: str, version: str) -> Diagnostic:
        res = []
        cve_ids = set()
        best_version = None
        vulnerable = False
        vulnerabilities = self.repository.get_vulnerabilities(package)
        for vulnerability in vulnerabilities:
            range = vulnerability.range
            if not range:
                continue

            cmp1 = vercmp(range.start, version)
            cmp2 = vercmp(range.end, version)

            if cmp1 <= 0 and cmp2 > 0:
                res.append(vulnerability)
                vulnerable = True
                cve_ids.add(vulnerability.cve_id)
                if not best_version or vercmp(range.end, best_version) == 1:
                    best_version = range.end

        cves = [self.repository.get_cve_by_id(id) for id in cve_ids]
        if vulnerable:
            assert best_version
            upgrade = Range(version, best_version)
        else:
            upgrade = None
        return Diagnostic(
            package=package, upgrade=upgrade, cves=cves, vulnerable=vulnerable
        )
