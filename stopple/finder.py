from stopple.repository import Repository
from stopple.vulnerabilities import Vulnerability
from rpm_vercmp import vercmp


class Finder:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def find_vulnerabilities(self, package: str, version: str) -> list[Vulnerability]:
        res = []
        vulnerabilities = self.repository.get_vulnerabilities(package)
        for vulnerability in vulnerabilities:
            range = vulnerability.range
            if not range:
                continue

            cmp1 = vercmp(range.start, version)
            cmp2 = vercmp(range.end, version)

            if cmp1 <= 0 and cmp2 > 0:
                res.append(vulnerability)

        return res
