import json
from pathlib import Path
from unittest import mock
from unittest.mock import _Call

import pytest

from stopple.nvd.api import NvdApi, Cve, PaginatedResponse
from stopple.vulnerabilities import Severity


def make_cve(
    id: str,
    severity: Severity,
    package_id: str,
    start: str,
    end: str,
    description: str | None = None,
) -> Cve:
    json_template_path = Path("tests/nvd/cve_template.json")
    json_template = json_template_path.read_text()

    description = description or f"vulnerability #{id} for {package_id}"

    context = {
        "severity": severity,
        "package_id": package_id,
        "start": start,
        "end": end,
        "description": description,
    }
    for key, value in context.items():
        json_template = json_template.replace(f"@{key}@", value)

    details = json.loads(json_template)
    return Cve(id=id, details=details, description=description, severity=severity)


class FakeNvdClient(NvdApi):
    def __init__(self) -> None:
        self.cves: list[Cve] = []
        self.results_per_page = 0
        self.calls: list[_Call] = []

    def set_cves(self, cves: list[Cve]) -> None:
        self.cves = cves

    def set_results_per_page(self, count: int) -> None:
        self.results_per_page = count

    def reset_calls(self) -> None:
        self.calls.clear()

    def get_cves(
        self,
        *,
        start_index: int | None = None,
        package_name: str | None = None,
        results_per_page: int | None = None,
    ) -> PaginatedResponse:
        if results_per_page:
            pytest.fail("Use self.set_results_per_page instead")
        call = mock.call(start_index=start_index)
        self.calls.append(call)
        start = start_index or 0
        end = start + self.results_per_page
        cves = self.cves[start:end]
        return PaginatedResponse(
            results_per_page=self.results_per_page,
            total_results=len(self.cves),
            cves=cves,
        )
