import os

os.environ["DJANGO_SECRET_KEY"] = "test_secret"

from stopple_web.settings import *  # noqa: F403
