from stopple.nvd.client import parse
from stopple.repository import Repository


class Indexer:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository
        self.batch_size = 0

    def index(self) -> None:
        print("Indexing ...")
        total = self.repository.cve_count()
        start = 0
        end = self.batch_size
        while start <= total:
            percent = start * 100 // total
            print(f"Done: {start}/{total} - {percent:02}%\r", flush=True, end="")
            page = self.repository.get_cve_page(start=start, end=end)
            for cve in page:
                vulnerabilities = parse(cve)
                self.repository.save_vulnerabilities(cve, vulnerabilities)
            start += self.batch_size
            end = start + self.batch_size
