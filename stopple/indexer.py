from stopple.nvd.client import parse
from stopple.repository import Repository


class Indexer:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository
        self.batch_size = 0

    def index(self) -> None:
        print("Indexing ...")
        self.repository.delete_vulnerabilities()
        total = self.repository.cve_count()
        start = 0
        end = self.batch_size
        while start <= total:
            percent = start * 100 // total
            print(f"Done: {start}/{total} - {percent:02}%\r", flush=True, end="")
            page = self.repository.get_cve_page(start=start, end=end)
            to_save = {}
            for cve in page:
                vulnerabilities = parse(cve)
                to_save[cve.id] = vulnerabilities
            self.repository.save_vulnerabilities(to_save)
            start += self.batch_size
            end = start + self.batch_size
        print("Done - happy queries !")
