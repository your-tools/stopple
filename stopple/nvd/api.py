from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Any

from stopple.vulnerabilities import Severity


@dataclass
class Cve:
    id: str
    description: str
    details: dict[str, Any]
    severity: Severity | None = None

    def __repr__(self) -> str:
        return f"NvdCve(id={self.id}, description={self.description})"


@dataclass
class PaginatedResponse:
    results_per_page: int
    total_results: int
    cves: list[Cve]


class NvdApi(metaclass=ABCMeta):
    @abstractmethod
    def get_cves(
        self,
        *,
        start_index: int | None = None,
        package_name: str | None = None,
        results_per_page: int | None = None,
    ) -> PaginatedResponse:
        pass
