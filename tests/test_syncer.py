import pytest
from stopple.nvd.syncer import Syncer
from stopple.vulnerabilities import Severity
from tests.conftest import FakeRepository
from tests.nvd.conftest import FakeNvdClient, make_cve


@pytest.fixture
def fake_client() -> FakeNvdClient:
    fake_client = FakeNvdClient()

    django_1 = make_cve("CVE-001", Severity.High, "djangoproject:django", "5.0", "5.1")
    django_2 = make_cve("CVE-002", Severity.High, "djangoproject:django", "5.3", "5.4")
    requests = make_cve("CVE-003", Severity.High, "requests:requests", "2.0", "2.3")

    cves = [django_1, django_2, requests]

    fake_client.set_cves(cves)
    fake_client.set_results_per_page(3)
    return fake_client


def test_sync_repository_from_scratch_no_pagination(fake_client: FakeNvdClient) -> None:
    fake_repository = FakeRepository()

    syncer = Syncer(nvd_api=fake_client, repository=fake_repository)

    syncer.sync()

    assert fake_repository.cve_count() == 3


def test_sync_repository_from_scratch_with_pagination(
    fake_client: FakeNvdClient,
) -> None:
    fake_client.set_results_per_page(2)

    fake_repository = FakeRepository()

    syncer = Syncer(nvd_api=fake_client, repository=fake_repository)

    syncer.sync()

    assert fake_repository.cve_count() == 3
