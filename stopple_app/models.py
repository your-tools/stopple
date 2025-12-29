from django.db import models


class Cve(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    raw_json = models.TextField(null=False)
    description = models.TextField(null=False)
    severity = models.CharField(max_length=20, null=True)


class Vulnerability(models.Model):
    package_id = models.TextField(null=False)
    start = models.TextField(null=True)
    end = models.TextField(null=True)
    cve = models.ForeignKey(Cve, on_delete=models.CASCADE)


class Syncer(models.Model):
    sync_index = models.IntegerField()
