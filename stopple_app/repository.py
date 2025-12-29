import json
from stopple.nvd.api import NvdCve
from stopple.repository import Repository
from stopple.vulnerabilities import Vulnerability
from stopple_app.models import Syncer, Cve
from django.db import transaction


class DjangoRepository(Repository):
    def get_sync_index(self) -> int | None:
        row = Syncer.objects.first()
        if row:
            return row.sync_index

        return None

    def save_sync_index(self, index: int) -> None:
        Syncer.objects.all().delete()
        Syncer.objects.create(sync_index=index)

    @transaction.atomic
    def save_cves(self, cves: list[NvdCve]) -> None:
        print(f":: Saving {len(cves)} cves ...")
        for cve in cves:
            Cve.objects.update_or_create(
                id=cve.id, description=cve.description, raw_json=json.dumps(cve.details)
            )
        print(f":: Done: {len(cves)} saved")

    def cve_count(self) -> int:
        return Cve.objects.count()

    def get_vulnerabilities(self, package: str) -> list[Vulnerability]:
        return []
