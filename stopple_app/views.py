from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from stopple_app.models import Cve


def index(request: HttpRequest) -> HttpResponse:
    return redirect(vulnerabilities)


def vulnerabilities(request: HttpRequest) -> HttpResponse:
    vulnerabilities_count = Cve.objects.count()
    return render(
        request,
        "stopple/vulnerabilities.html",
        {"vulnerabilities_count": vulnerabilities_count},
    )
