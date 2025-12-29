import json
import os
from pathlib import Path

import pytest

from stopple.nvd.api import Cve
from stopple.nvd.client import NvdClient
from stopple.nvd.client import parse
from stopple.vulnerabilities import Range, Severity, Vulnerability

from tests.nvd.conftest import make_cve


def test_can_query_django_cves() -> None:
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        pytest.skip("NVD_API_KEY not found in environment, skipping test")
    client = NvdClient(api_key=api_key)

    found = client.get_cves(package_name="django")

    assert found

    nvd_cve = found.cves[0]

    assert nvd_cve.id
    assert nvd_cve.description
    assert nvd_cve.details["metrics"]


def test_parse_ok() -> None:
    nvd_cve = make_cve(
        "CVE-001",
        Severity.High,
        "djangoproject:django",
        "5.0",
        "5.1",
        description="test description",
    )

    actual = parse(nvd_cve)

    assert actual == [
        Vulnerability(
            cve_id="CVE-001",
            severity=Severity.High,
            description="test description",
            package_id="djangoproject:django",
            range=Range(start="5.0", end="5.1"),
        )
    ]


def test_parse_metrics_v2() -> None:
    raw_json = Path("tests/nvd/cve_sendmail.json").read_text()
    cve = Cve(
        id="CVE-1999-0095", details=json.loads(raw_json), description="test description"
    )

    parse(cve)
