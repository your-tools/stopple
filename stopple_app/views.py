from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render


def index(request: HttpRequest) -> HttpResponse:
    return redirect(vulnerabilities)


def vulnerabilities(request: HttpRequest) -> HttpResponse:
    return render(request, "stopple/vulnerabilities.html")
