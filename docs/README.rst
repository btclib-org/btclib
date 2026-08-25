Generate btclib documentation with Sphinx
=========================================

Sphinx is a powerful documentation generator that
has many great features for writing technical documentation.

Quick start
-----------

uv installs sphinx, the theme, and btclib itself. That last part is the
one that matters: every directive under ``source/`` is an ``automodule``,
so sphinx imports the library in order to document it, and produces a bare
heading for every module it cannot import.

.. sourcecode:: bash

    $ uv sync

Build from the project root, exactly as ``.readthedocs.yaml`` does:

.. sourcecode:: bash

    $ uv run --locked --no-default-groups --group docs \
          sphinx-build -n -W --keep-going -b html docs/source docs/build/html

Open ``docs/build/html/index.html`` in a browser to see the result. The
``Makefile`` and ``make.bat`` here drive the same build, from within this
directory and without the flags:

.. sourcecode:: bash

    $ cd docs
    $ uv run --locked --no-default-groups --group docs make clean html

``-W`` is not decoration: without it a module that fails to import is a
warning and nothing more, and the published documentation silently has no
API in it. Read the docs builds with the same flag, so a build that is
green here is green there.

Adding or removing a module
---------------------------

Edit the ``rst`` file by hand. Do **not** run ``sphinx-apidoc -f -o
docs/source src/btclib/``: ``-f`` regenerates every page from the template,
discarding the hand-tuned ``index.rst`` and ``modules.rst`` and the
``myst`` links to README, RELEASE_NOTES, CONTRIBUTING and SECURITY. Point
it at a scratch directory if you want the boilerplate for a new module,
then copy the stanza across.

Forgetting the edit is what ``tests/docs_test.py`` is for: it compares the
modules under ``src/btclib/`` against the directives in ``docs/source/``
and fails naming whichever is missing. This note is the convenience; the
test is the guarantee.

Dependencies
------------

There is no ``docs/requirements.txt``, and there is no place for one: the
build, locally and on read the docs alike, is uv with ``--locked``, so
the ``docs`` dependency group in ``pyproject.toml`` is the single
declaration and ``uv.lock`` pins it. A requirements file would be a
second copy, kept in step by hand and read by nothing.

External resources
------------------

Here are some external resources to help you learn more about Sphinx.

* `Sphinx documentation`_
* `RestructuredText primer`_
* `An introduction to Sphinx and Read the Docs for technical writers`_
* `Read the docs`_

.. _Sphinx documentation: https://www.sphinx-doc.org/
.. _RestructuredText primer: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
.. _An introduction to Sphinx and Read the Docs for technical writers: https://ericholscher.com/blog/2016/jul/1/sphinx-and-rtd-for-writers/
.. _Read the docs: https://docs.readthedocs.io/en/latest/intro/getting-started-with-sphinx.html
