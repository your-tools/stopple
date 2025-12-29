from abc import ABCMeta, abstractmethod

from stopple.nvd.api import Cve
from stopple.vulnerabilities import Vulnerability


class Repository(metaclass=ABCMeta):
    @abstractmethod
    def get_sync_index(self) -> int | None:
        pass

    @abstractmethod
    def save_sync_index(self, index: int) -> None:
        pass

    @abstractmethod
    def save_cves(self, cves: list[Cve]) -> None:
        pass

    @abstractmethod
    def get_cve_page(self, start: int, end: int) -> list[Cve]:
        pass

    @abstractmethod
    def cve_count(self) -> int:
        pass

    @abstractmethod
    def save_vulnerabilities(
        self, cve: Cve, vulnerabilities: list[Vulnerability]
    ) -> None:
        pass

    @abstractmethod
    def delete_vulnerabilities(self) -> None:
        pass
