from time import sleep
from stopple.nvd.api import NvdApi
from stopple.repository import Repository


class Syncer:
    def __init__(self, nvd_api: NvdApi, repository: Repository):
        self.api = nvd_api
        self.repository = repository
        self.current_index: int | None = None
        self.sleeping_time = 0
        self.results_per_page: int | None = None

    def sync(self) -> None:
        done = self._sync_once()
        while not done:
            done = self._sync_once()

    def _sync_once(self) -> bool:
        current_index = self.repository.get_sync_index() or 0
        response = self.api.get_cves(
            start_index=current_index, results_per_page=self.results_per_page
        )
        total_results = response.total_results
        if not response.cves:
            return True

        self.repository.save_cves(response.cves)

        current_index += response.results_per_page
        self.repository.save_sync_index(current_index)

        saved = self.repository.cve_count()
        percent = saved * 100 // total_results
        print(f"Done: {saved}/{total_results} {percent}%")
        if self.sleeping_time:
            print(f"Sleeping for {self.sleeping_time} seconds ...")
            sleep(self.sleeping_time)

        return saved >= total_results
