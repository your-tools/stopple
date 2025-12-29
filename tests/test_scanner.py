from stopple.scanner import Scanner
from stopple.vulnerabilities import Range, Severity
from tests.conftest import FakeRepository


def test_find_vulnerabilities() -> None:
    fake_repository = FakeRepository()
    cve1, v1 = fake_repository.make_vulnerability(
        cve_id="CVE-123",
        package_id="djangoproject:django",
        start="4.0",
        end="4.2",
        severity=Severity.Critical,
    )

    cve2, v2 = fake_repository.make_vulnerability(
        cve_id="CVE-456",
        package_id="djangoproject:django",
        start="5.0",
        end="5.3",
        severity=Severity.Medium,
    )

    fake_repository.save_vulnerabilities(
        {
            cve1.id: [v1],
            cve2.id: [v2],
        }
    )

    scanner = Scanner(fake_repository)

    diagnostic = scanner.get_diagnostic("django", "5.2")

    assert diagnostic.vulnerable
    assert diagnostic.cves == [cve2]
    assert diagnostic.upgrade == Range("5.2", "5.3")
