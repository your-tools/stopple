from stopple.indexer import Indexer
from stopple.vulnerabilities import Severity
from tests.conftest import FakeRepository
from tests.nvd.conftest import make_cve


def test_parse_cves_and_store_them() -> None:
    django_1 = make_cve("CVE-001", Severity.High, "djangoproject:django", "5.0", "5.1")
    django_2 = make_cve("CVE-002", Severity.High, "djangoproject:django", "5.3", "5.4")
    requests = make_cve("CVE-003", Severity.High, "requests:requests", "2.0", "2.3")

    fake_repository = FakeRepository()
    fake_repository.save_cves([django_1, django_2, requests])

    indexer = Indexer(fake_repository)
    indexer.batch_size = 2
    indexer.index()

    found = fake_repository.get_vulnerabilities("django")

    ids = [v.cve_id for v in found]
    assert ids == ["CVE-001", "CVE-002"]
