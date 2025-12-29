import os

import pytest
from stopple.nvd.client import NvdClient


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
