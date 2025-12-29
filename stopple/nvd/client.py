from typing import Any, TypedDict, cast
from httpx import Client

from stopple.nvd.api import NvdApi, NvdCve, PaginatedResponse

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


class Cve(TypedDict):
    id: str
    descriptions: list[Description]


class Vulnerability(TypedDict):
    cve: Cve


class NvdResponse(TypedDict):
    vulnerabilities: list[Vulnerability]
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

    def extract_cve(self, vulnerability: Vulnerability) -> NvdCve:
        cve = vulnerability["cve"]
        details = cast(dict[str, Any], cve)
        id = cve["id"]
        cve_description = ""
        for description in cve["descriptions"]:
            if description["lang"] == "en":
                cve_description = description["value"]
                break

        return NvdCve(id=id, description=cve_description, details=details)
