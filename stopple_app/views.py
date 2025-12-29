import json
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from stopple.scanner import Scanner
from stopple_app.models import Cve, Vulnerability
from stopple_app.repository import DjangoRepository


def index(request: HttpRequest) -> HttpResponse:
    return redirect(database)


def database(request: HttpRequest) -> HttpResponse:
    cve_count = Cve.objects.count()
    vulnerabilities_count = Vulnerability.objects.count()
    return render(
        request,
        "stopple/pages/database.html",
        {
            "cve_count": cve_count,
            "vulnerabilities_count": vulnerabilities_count,
        },
    )


def diagnostics(request: HttpRequest) -> HttpResponse:
    repository = DjangoRepository()

    package = request.GET.get("package")
    package_version = request.GET.get("package_version")
    diagnostic = None
    if package and package_version:
        scanner = Scanner(repository)
        diagnostic = scanner.get_diagnostic(package, package_version)
    return render(
        request,
        "stopple/pages/diagnostics.html",
        {
            "package": package,
            "package_version": package_version,
            "diagnostic": diagnostic,
        },
    )


def cve_details(request: HttpRequest) -> HttpResponse:
    cve_id = request.GET.get("id")
    cve = get_object_or_404(Cve, id=cve_id)
    details = json.loads(cve.raw_json)
    vulnerabilities = cve.vulnerability_set.all()
    return render(
        request,
        "stopple/cve_details.html",
        {"cve": cve, "vulnerabilities": vulnerabilities, "details": details},
    )


def settings(request: HttpRequest) -> HttpResponse:
    return HttpResponse("to do - settings")


def sign_out(request: HttpRequest) -> HttpResponse:
    return HttpResponse("to do - sign out")
