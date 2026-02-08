"""Sphinx configuration for python-veracrypt."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(".."))

project = "python-veracrypt"
author = "srich"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
]

autosummary_generate = True

exclude_patterns = ["_build"]

html_theme = "alabaster"

napoleon_google_docstring = False
napoleon_numpy_docstring = False
