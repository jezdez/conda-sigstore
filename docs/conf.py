"""Sphinx configuration for conda-sigstore documentation."""

from __future__ import annotations

import os
import re
import sys

from docutils import nodes

sys.path.insert(0, os.path.abspath("../src"))

project = html_title = "conda-sigstore"
copyright = "2026, Jannis Leidel"
author = "Jannis Leidel"

extensions = [
    "myst_parser",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinx_sitemap",
]

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "tasklist",
]

myst_url_schemes = {
    "http": None,
    "https": None,
    "mailto": None,
    "ftp": None,
}

GITHUB_REF_RE = re.compile(r"(?<![\w/])#([0-9]+)\b")
GITHUB_ISSUE_URL = "https://github.com/jezdez/conda-sigstore/issues/"


def link_changelog_github_refs(
    app,
    doctree: nodes.document,
    docname: str,
) -> None:
    """Link bare issue references in the included changelog."""
    if docname != "changelog":
        return

    for text_node in list(doctree.findall(nodes.Text)):
        parent = text_node.parent
        while parent is not None:
            if isinstance(
                parent,
                (nodes.reference, nodes.literal, nodes.literal_block, nodes.raw),
            ):
                break
            parent = parent.parent
        else:
            text = text_node.astext()
            matches = list(GITHUB_REF_RE.finditer(text))
            if not matches:
                continue

            replacements: list[nodes.Node] = []
            cursor = 0
            for match in matches:
                if match.start() > cursor:
                    replacements.append(nodes.Text(text[cursor : match.start()]))
                ref_text = match.group(0)
                replacements.append(
                    nodes.reference(
                        "",
                        ref_text,
                        refuri=f"{GITHUB_ISSUE_URL}{match.group(1)}",
                        classes=["github"],
                    )
                )
                cursor = match.end()
            if cursor < len(text):
                replacements.append(nodes.Text(text[cursor:]))
            text_node.parent.replace(text_node, replacements)


html_theme = "conda_sphinx_theme"

html_theme_options = {
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/jezdez/conda-sigstore",
            "icon": "fa-brands fa-square-github",
            "type": "fontawesome",
        },
    ],
}

html_context = {
    "github_user": "jezdez",
    "github_repo": "conda-sigstore",
    "github_version": "main",
    "doc_path": "docs",
}

html_extra_path = ["robots.txt"]
html_baseurl = "https://jezdez.github.io/conda-sigstore/"
exclude_patterns = ["_build"]


def setup(app) -> None:
    """Register documentation build hooks."""
    app.connect("doctree-resolved", link_changelog_github_refs)
