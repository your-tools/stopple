from datetime import datetime
from stopple.nvd.api import NvdCve
from stopple.repository import Repository
from stopple.vulnerabilities import Vulnerability


class FakeRepository(Repository):
    def __init__(self) -> None:
        self.cves: list[NvdCve] = []
        self.success_date: datetime | None = None
        self.sync_index: int | None = None
        self.vulnerabilities: list[Vulnerability] = []

    def cve_count(self) -> int:
        return len(self.cves)

    def get_sync_index(self) -> int | None:
        return self.sync_index

    def save_sync_index(self, index: int) -> None:
        self.sync_index = index

    def save_cves(self, cves: list[NvdCve]) -> None:
        saved_ids = [cve.id for cve in self.cves]
        for cve in cves:
            if cve.id not in saved_ids:
                self.cves.append(cve)

    def get_vulnerabilities(self, package: str) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.matches(package)]
