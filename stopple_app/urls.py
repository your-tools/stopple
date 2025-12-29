from django.urls import path

from stopple_app import views


urlpatterns = [
    path("", views.index),
    path("cve/<cve_id>", views.cve_details, name="cve_details"),
    path("vulnerabilities", views.vulnerabilities),
]
