from unittest.mock import call
from stopple.vulnerabilities import Severity
from tests.nvd.conftest import FakeNvdClient, make_cve


def test_fake_client_returns_paginated_data() -> None:
    fake_client = FakeNvdClient()

    django_1 = make_cve("CVE-001", Severity.High, "djangoproject:django", "5.0", "5.1")
    django_2 = make_cve("CVE-002", Severity.High, "djangoproject:django", "5.3", "5.4")
    requests = make_cve("CVE-003", Severity.High, "requests:requests", "2.0", "2.3")

    cves = [django_1, django_2, requests]

    fake_client.set_cves(cves)

    fake_client.set_results_per_page(2)

    response = fake_client.get_cves()

    assert response.results_per_page == 2
    assert response.total_results == 3
    returned_ids = [cve.id for cve in response.cves]
    assert returned_ids == ["CVE-001", "CVE-002"]

    response = fake_client.get_cves(start_index=2)
    returned_ids = [cve.id for cve in response.cves]
    assert returned_ids == ["CVE-003"]

    response = fake_client.get_cves(start_index=4)
    assert response.cves == []

    assert fake_client.calls == [
        call(start_index=None),
        call(start_index=2),
        call(start_index=4),
    ]
