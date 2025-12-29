from enum import StrEnum
from dataclasses import dataclass


class Severity(StrEnum):
    Low = "low"
    Medium = "medium"
    High = "high"
    Critical = "critical"


@dataclass
class Range:
    start: str
    end: str


@dataclass
class Vulnerability:
    cve_id: str
    package_id: str
    description: str
    range: Range | None = None
    severity: Severity | None = None

    def matches(self, package: str) -> bool:
        return self.package_id.endswith(":" + package)
