# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`RootFileLinks` in docs/source/conf.py links an included file to its page.

Section 2 of the organization's standard, *The documentation*, is the rule
these tests hold `RootFileLinks` to. They run the transform on a
hand-made doctree, so each case is checked whether or not a page of the
tree holds it: a fragment, and a page other than an included one.

Executing conf.py imports sphinx, which the `test` group carries and
`harness` alone does not: there the fixture skips.
"""

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

_CONF = Path(__file__).parents[1] / "docs" / "source" / "conf.py"


@pytest.fixture(scope="module")
def conf() -> ModuleType:
    """Return docs/source/conf.py, executed as a module."""
    pytest.importorskip(
        "sphinx",
        reason=(
            "sphinx is not installed here, and conf.py imports it: the"
            " `test` group carries it, `harness` alone does not"
        ),
    )
    spec = importlib.util.spec_from_file_location("docs_conf", _CONF)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(conf: ModuleType, node: Any, docname: str = "readme_link") -> Any:
    """Run `RootFileLinks` on a page holding `node`; return its replacement.

    Args:
        conf: the conf.py module.
        node: the link, as myst makes it.
        docname: the page the link is on.

    Returns:
        The node in the link's place once the transform has run.
    """
    utils = importlib.import_module("docutils.utils")
    document = utils.new_document("<test>")
    document.settings.env = SimpleNamespace(docname=docname)
    paragraph = conf.nodes.paragraph()
    paragraph += node
    document += paragraph
    conf.RootFileLinks(document).run()
    return paragraph[0]


def _url(conf: ModuleType, url: str) -> Any:
    """Return the reference myst makes from a link to an external `url`.

    Args:
        conf: the conf.py module.
        url: the link's destination.

    Returns:
        The reference, its text the url.
    """
    return conf.nodes.reference(url, url, refuri=url)


@pytest.mark.parametrize("docname", ["readme_link", "btclib"])
@pytest.mark.parametrize("fragment", ["", "#reporting-a-vulnerability"])
def test_blob_link_to_an_included_file_is_its_page(
    conf: ModuleType, docname: str, fragment: str
) -> None:
    """A `BLOB` link to an included file, on any page, becomes that page."""
    url = f"{conf.BLOB}SECURITY.md{fragment}"
    node = _run(conf, _url(conf, url), docname)
    assert isinstance(node, conf.pending_xref)
    assert node["reftype"] == "myst"
    assert node["refdomain"] == "doc"
    assert node["reftarget"] == conf.INCLUDED["SECURITY.md"]
    assert node["reftargetid"] == (fragment.removeprefix("#") or None)
    assert node["refexplicit"]
    assert node["refdoc"] == docname
    assert node.astext() == url


@pytest.mark.parametrize("fragment", ["", "#reporting-a-vulnerability"])
def test_blob_and_relative_links_give_the_same_xref(
    conf: ModuleType, fragment: str
) -> None:
    """A `BLOB` link and a relative one to the same file resolve alike."""
    relative = conf.pending_xref(
        "",
        conf.nodes.inline("", "SECURITY.md"),
        reftype="myst",
        refdomain=None,
        reftarget=f"./SECURITY.md{fragment}",
        refdoc="readme_link",
    )
    from_relative = _run(conf, relative)
    from_blob = _run(conf, _url(conf, f"{conf.BLOB}SECURITY.md{fragment}"))
    for key in ("reftype", "refdomain", "reftarget", "reftargetid", "refdoc"):
        assert from_blob[key] == from_relative[key], key


@pytest.mark.parametrize(
    "path",
    [
        # BLOB plus a file of the tree no shim includes
        "LICENSE",
        # BLOB plus a path that is not a file of the tree
        "NO-SUCH-FILE.md",
    ],
)
def test_blob_link_to_a_file_not_included_stays_on_github(
    conf: ModuleType, path: str
) -> None:
    """A `BLOB` link to a file no page renders is left as it is."""
    assert path not in conf.INCLUDED
    url = f"{conf.BLOB}{path}"
    node = _run(conf, _url(conf, url))
    assert isinstance(node, conf.nodes.reference)
    assert node["refuri"] == url


@pytest.mark.parametrize(
    "url",
    [
        # another repository's file of the same name
        "https://github.com/btclib-org/.github/blob/main/SECURITY.md",
        # this repository's file, on a branch other than main
        "https://github.com/btclib-org/btclib/blob/other/SECURITY.md",
    ],
)
def test_github_link_other_than_blob_is_left(conf: ModuleType, url: str) -> None:
    """A GitHub link that is not `BLOB` plus a path is left as it is."""
    assert not url.startswith(conf.BLOB)
    node = _run(conf, _url(conf, url))
    assert isinstance(node, conf.nodes.reference)
    assert node["refuri"] == url
