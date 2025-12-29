from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class NvdCve:
    id: str
    description: str
    details: dict[str, Any]


@dataclass
class PaginatedResponse:
    results_per_page: int
    total_results: int
    cves: list[NvdCve]


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
