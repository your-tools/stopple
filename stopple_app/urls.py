from django.urls import path

from stopple_app import views


urlpatterns = [
    path("", views.index),
    path("vulnerabilities", views.vulnerabilities),
]
