from django.urls import path

from stopple_app import views


urlpatterns = [
    path("", views.index),
    path("cve", views.cve_details, name="cve_details"),
    path("database", views.database, name="database"),
    path("diagnostic", views.diagnostic, name="diagnostic"),
    path("settings", views.settings, name="settings"),
    path("sign_out", views.sign_out, name="sign_out"),
]
