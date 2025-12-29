from argparse import ArgumentParser
from typing import Any
from django.core.management.base import BaseCommand

from stopple.indexer import Indexer
from stopple_app.repository import DjangoRepository


class Command(BaseCommand):
    help = "Rebuild NVD database index"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--batch-size", type=int)

    def handle(self, *args: str, **options: Any) -> None:
        batch_size = options["batch_size"]
        repository = DjangoRepository()

        indexer = Indexer(repository)
        indexer.batch_size = batch_size

        indexer.index()
