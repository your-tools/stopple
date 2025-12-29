from datetime import datetime

import pytest
from stopple.nvd.api import Cve
from stopple.repository import Repository
from stopple.vulnerabilities import Range, Severity, Vulnerability
from tests.nvd.conftest import make_cve


class FakeRepository(Repository):
    def __init__(self) -> None:
        self.cves: dict[str, Cve] = {}
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
        for cve in cves:
            self.cves[cve.id] = cve

    def get_cve_page(self, start: int, end: int) -> list[Cve]:
        return list(self.cves.values())[start:end]

    def get_cve_by_id(self, id: str) -> Cve:
        if id not in self.cves:
            pytest.fail(f"No CVE with id  {id}")

        return self.cves[id]

    def get_vulnerabilities(self, package: str) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.matches(package)]

    def save_vulnerabilities(self, batch: dict[str, list[Vulnerability]]) -> None:
        saved_ids = [v.cve_id for v in self.vulnerabilities]
        for _cve, vulnerabilities in batch.items():
            for vulnerability in vulnerabilities:
                if vulnerability.cve_id not in saved_ids:
                    self.vulnerabilities.append(vulnerability)

    def delete_vulnerabilities(self) -> None:
        self.vulnerabilities = []

    def make_vulnerability(
        self,
        *,
        cve_id: str,
        package_id: str,
        start: str,
        end: str,
        severity: Severity,
    ) -> tuple[Cve, Vulnerability]:
        cve = self.ensure_cve(
            cve_id, package_id=package_id, severity=severity, start=start, end=end
        )
        range = Range(start, end)
        return (
            cve,
            Vulnerability(
                cve_id=cve_id,
                package_id=package_id,
                range=range,
                description="test vulnerability",
            ),
        )

    def ensure_cve(
        self, cve_id: str, package_id: str, severity: Severity, start: str, end: str
    ) -> Cve:
        cve = self.cves.get(cve_id)
        if cve:
            return cve

        cve = make_cve(
            id=cve_id, package_id=package_id, severity=severity, start=start, end=end
        )
        self.cves[cve_id] = cve
        return cve
