from argparse import ArgumentParser
import os
from typing import Any
from django.core.management.base import BaseCommand

from stopple.nvd.client import NvdClient
from stopple.nvd.syncer import Syncer
from stopple_app.repository import DjangoRepository


class Command(BaseCommand):
    help = "Synchronize NVD database"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--results-per-page", type=int)

    def handle(self, *args: str, **options: Any) -> None:
        api_key = os.environ["NVD_API_KEY"]
        nvd_api = NvdClient(api_key)
        results_per_page: int = options["results_per_page"]

        repository = DjangoRepository()

        syncer = Syncer(nvd_api=nvd_api, repository=repository)

        syncer.sleeping_time = 10  # complying with best practices
        if results_per_page:
            syncer.results_per_page = results_per_page

        syncer.sync()
