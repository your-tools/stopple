import pytest

from stopple.vulnerabilities import Range, Severity, Vulnerability
from stopple_app.repository import DjangoRepository

from tests.nvd.conftest import make_cve


@pytest.mark.django_db
def test_sync_index() -> None:
    repository = DjangoRepository()
    assert repository.get_sync_index() is None

    repository.save_sync_index(2)

    assert repository.get_sync_index() == 2

    repository.save_sync_index(3)
    assert repository.get_sync_index() == 3


@pytest.mark.django_db
def test_save_cves() -> None:
    repository = DjangoRepository()

    django_1 = make_cve("CVE-001", Severity.High, "djangoproject:django", "5.0", "5.1")
    django_2 = make_cve("CVE-002", Severity.High, "djangoproject:django", "5.3", "5.4")
    requests = make_cve("CVE-003", Severity.High, "requests:requests", "2.0", "2.3")

    repository.save_cves([django_1, django_2, requests])

    assert repository.cve_count() == 3


@pytest.mark.django_db
def test_save_vulnerabilities() -> None:

    django = make_cve(
        "CVE-001",
        Severity.High,
        "djangoproject:django",
        "5.0",
        "5.1",
        description="test description",
    )
    requests = make_cve("CVE-003", Severity.High, "requests:requests", "2.0", "2.3")

    v1 = Vulnerability(
        cve_id="CVE-001",
        package_id="djangoproject:django",
        description="test description",
        range=Range("5.0", "5.1"),
        severity=Severity.High,
    )

    repository = DjangoRepository()

    repository.save_cves([django, requests])

    repository.save_vulnerabilities({django.id: [v1]})

    found = repository.get_vulnerabilities("django")

    assert found == [v1]
