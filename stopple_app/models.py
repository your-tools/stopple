from django.db import models


class Cve(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    raw_json = models.TextField(null=False)
    description = models.TextField(null=False)
