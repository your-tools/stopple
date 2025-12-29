import json
from stopple.nvd.api import Cve
from stopple.repository import Repository
from stopple.vulnerabilities import Range, Severity, Vulnerability
from stopple_app.models import (
    Vulnerability as VulnerabilityTable,
    Syncer,
    Cve as CveTable,
)
from django.db import transaction


def to_cve(row: CveTable) -> Cve:
    severity = Severity(row.severity) if row.severity else None
    return Cve(
        id=row.id,
        description=row.description,
        details=json.loads(row.raw_json),
        severity=severity,
    )


def to_vulnerability(row: VulnerabilityTable) -> Vulnerability:
    if row.start and row.end:
        range = Range(row.start, row.end)
    else:
        range = None
    return Vulnerability(
        cve_id=row.cve.id,
        description=row.cve.description,
        package_id=row.package_id,
        range=range,
    )


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
    def save_cves(self, cves: list[Cve]) -> None:
        print(f":: Saving {len(cves)} cves ...")
        for cve in cves:
            CveTable.objects.update_or_create(
                id=cve.id,
                description=cve.description,
                raw_json=json.dumps(cve.details),
                severity=cve.severity,
            )
        print(f":: Done: {len(cves)} saved")

    def cve_count(self) -> int:
        return CveTable.objects.count()

    def get_cve_page(self, start: int, end: int) -> list[Cve]:
        rows = CveTable.objects.all()[start:end]
        return [to_cve(row) for row in rows]

    def get_cve_by_id(self, id: str) -> Cve:
        row = CveTable.objects.get(id=id)
        return to_cve(row)

    @transaction.atomic
    def save_vulnerabilities(self, to_save: dict[str, list[Vulnerability]]) -> None:
        for cve, vulnerabilities in to_save.items():
            stored_cve = CveTable.objects.get(id=cve)
            for vulnerability in vulnerabilities:
                range = vulnerability.range
                start = range.start if range else None
                end = range.end if range else None
                VulnerabilityTable.objects.create(
                    cve=stored_cve,
                    package_id=vulnerability.package_id,
                    start=start,
                    end=end,
                )

    def get_vulnerabilities(self, package: str) -> list[Vulnerability]:
        pattern = f":{package}"
        rows = VulnerabilityTable.objects.filter(
            package_id__iendswith=pattern
        ).order_by("-cve")
        return [to_vulnerability(row) for row in rows]

    def delete_vulnerabilities(self) -> None:
        VulnerabilityTable.objects.all().delete()
