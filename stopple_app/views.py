from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from stopple.finder import Finder
from stopple_app.models import Cve, Vulnerability
from stopple_app.repository import DjangoRepository


def index(request: HttpRequest) -> HttpResponse:
    return redirect(vulnerabilities)


def vulnerabilities(request: HttpRequest) -> HttpResponse:
    repository = DjangoRepository()
    cve_count = Cve.objects.count()
    vulnerabilities_count = Vulnerability.objects.count()
    package = request.GET.get("package")  # Coming from search form
    package_version = request.GET.get("package_version")
    vulnerabilities = []
    if package:
        if package_version:
            finder = Finder(repository)
            vulnerabilities = finder.find_vulnerabilities(package, package_version)

        else:
            vulnerabilities = repository.get_vulnerabilities(package)
    return render(
        request,
        "stopple/vulnerabilities.html",
        {
            "cve_count": cve_count,
            "vulnerabilities_count": vulnerabilities_count,
            "package": package,
            "package_version": package_version,
            "vulnerabilities": vulnerabilities,
        },
    )


def cve_details(request: HttpRequest, cve_id: str) -> HttpResponse:
    cve = get_object_or_404(Cve, id=cve_id)
    vulnerabilities = cve.vulnerability_set.all()
    return render(
        request,
        "stopple/cve_details.html",
        {"cve": cve, "vulnerabilities": vulnerabilities},
    )
