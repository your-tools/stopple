from dataclasses import dataclass
from typing import Any, Iterator, TypedDict, cast
from httpx import Client

from stopple.nvd.api import NvdApi, Cve, PaginatedResponse
from stopple.vulnerabilities import Range, Severity, Vulnerability

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class ClientError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message

    def __str__(self) -> str:
        return f"Request failed with status {self.status_code}:{self.message}"


class Description(TypedDict):
    lang: str
    value: str


class NvdCve(TypedDict):
    id: str
    descriptions: list[Description]


class NvdVulnerability(TypedDict):
    cve: NvdCve


class NvdResponse(TypedDict):
    vulnerabilities: list[NvdVulnerability]
    resultsPerPage: int
    totalResults: int


class NvdClient(NvdApi):
    def __init__(self, api_key: str) -> None:
        self.client = Client(base_url=NVD_BASE_URL, headers={"apiKey": api_key})

    def get_cves(
        self,
        *,
        package_name: str | None = None,
        start_index: int | None = None,
        results_per_page: int | None = None,
    ) -> PaginatedResponse:
        params = {"keywordSearch": package_name}
        if start_index:
            params["startIndex"] = str(start_index)
        if results_per_page:
            params["resultsPerPage"] = str(results_per_page)

        print("-> GET", params)
        response = self.client.get("/", params=params)

        status_code = response.status_code
        message = response.headers.get("message")
        if not response.status_code == 200:
            raise ClientError(status_code=status_code, message=message)

        body: NvdResponse = response.json()
        total_results = body["totalResults"]
        results_per_page = body["resultsPerPage"]

        print(f"<- total : {total_results}, per page: {results_per_page}")

        cves = [
            self.extract_cve(vulnerability) for vulnerability in body["vulnerabilities"]
        ]
        return PaginatedResponse(
            total_results=total_results, results_per_page=results_per_page, cves=cves
        )

    def extract_cve(self, vulnerability: NvdVulnerability) -> Cve:
        cve = vulnerability["cve"]
        details = cast(dict[str, Any], cve)
        id = cve["id"]
        cve_description = ""
        for description in cve["descriptions"]:
            if description["lang"] == "en":
                cve_description = description["value"]
                break

        return Cve(id=id, description=cve_description, details=details)


def parse(cve: Cve) -> list[Vulnerability]:
    try:
        return _parse(cve)
    except Exception:
        raise Exception(f"Could not parse cve {cve.id}")


def _parse(cve: Cve) -> list[Vulnerability]:
    id = cve.id
    description = cve.description
    details = cve.details

    severity_str = get_severity(details).lower()
    severity = Severity(severity_str) if severity_str else None

    return [
        Vulnerability(
            cve_id=id,
            package_id=cpe_match.package_id,
            description=description,
            severity=severity,
            range=cpe_match.range,
        )
        for cpe_match in get_matches(cve.details)
    ]


def get_severity(details: dict[str, Any]) -> str:
    metrics = details.get("metrics", {})
    v2 = metrics.get("cvssMetricV2", [])
    if v2:
        for element in v2:
            v2_severity: str = element.get("baseSeverity", "")
            return v2_severity

    keys = ["cvssMetricV30", "cvssMetricV31", "cvssMetricV40"]
    for key in keys:
        data = metrics.get(key, [])
        for element in data:
            cvss_data = element.get("cvssData")
            if cvss_data:
                severity: str = cvss_data.get("baseSeverity", "")
                return severity

    return ""


@dataclass
class CpeMatch:
    package_id: str
    range: Range | None = None


def get_matches(details: dict[str, Any]) -> Iterator[CpeMatch]:
    for configuration in details.get("configurations", []):
        for node in configuration.get("nodes", []):
            for cpe_match in node.get("cpeMatch"):
                start = cpe_match.get("versionStartIncluding")
                end = cpe_match.get("versionEndExcluding")
                criteria: str = cpe_match.get("criteria")
                parts = criteria.split(":")
                vendor = parts[3]
                package = parts[4]
                package_id = f"{vendor}:{package}"
                if start and end:
                    range = Range(start, end)
                else:
                    range = None
                yield CpeMatch(range=range, package_id=package_id)
