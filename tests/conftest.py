from datetime import datetime
from stopple.nvd.api import Cve
from stopple.repository import Repository
from stopple.vulnerabilities import Vulnerability


class FakeRepository(Repository):
    def __init__(self) -> None:
        self.cves: list[Cve] = []
        self.success_date: datetime | None = None
        self.sync_index: int | None = None
        self.vulnerabilities: list[Vulnerability] = []

    def cve_count(self) -> int:
        return len(self.cves)

    def get_sync_index(self) -> int | None:
        return self.sync_index

    def save_sync_index(self, index: int) -> None:
        self.sync_index = index

    def save_cves(self, cves: list[Cve]) -> None:
        saved_ids = [cve.id for cve in self.cves]
        for cve in cves:
            if cve.id not in saved_ids:
                self.cves.append(cve)

    def get_cve_page(self, start: int, end: int) -> list[Cve]:
        return self.cves[start:end]

    def get_vulnerabilities(self, package: str) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.matches(package)]

    def save_vulnerabilities(
        self, cve: Cve, vulnerabilities: list[Vulnerability]
    ) -> None:
        saved_ids = [v.cve_id for v in self.vulnerabilities]
        for vulnerability in vulnerabilities:
            if vulnerability.cve_id not in saved_ids:
                self.vulnerabilities.append(vulnerability)

    def delete_vulnerabilities(self) -> None:
        self.vulnerabilities = []
