from abc import ABCMeta, abstractmethod

from stopple.nvd.api import NvdCve


class Repository(metaclass=ABCMeta):
    @abstractmethod
    def get_sync_index(self) -> int | None:
        pass

    @abstractmethod
    def save_sync_index(self, index: int) -> None:
        pass

    @abstractmethod
    def save_cves(self, cves: list[NvdCve]) -> None:
        pass

    @abstractmethod
    def cve_count(self) -> int:
        pass
