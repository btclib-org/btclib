Generate btclib documentation with Sphinx
=========================================

Sphinx is a powerful documentation generator that
has many great features for writing technical documentation.

Quick start
-----------

Assuming you have Python already, `install Sphinx`_:

.. sourcecode:: bash

    $ python -m pip install --upgrade sphinx


Move into the btclib directory and autogenerate docs:

.. sourcecode:: bash

    $ cd /path/to/btclibdirectory
    $ sphinx-apidoc -f -o ./docs/source ./btclib

Perform the above sphinx-apidoc step everytime files are added/removed.

Then, move into the docs directory and build the docs to see how they look:

.. sourcecode:: bash

    $ cd docs
    $ make html

Your ``index.rst`` has been built into ``index.html``
in the output subdirectory (``build/html/index.html``).
Open this file in your web browser to see your docs.

Edit your files and rebuild until you like what you see, then commit
your changes and push to your public repository.

External resources
------------------

Here are some external resources to help you learn more about Sphinx.

* `Sphinx documentation`_
* `RestructuredText primer`_
* `An introduction to Sphinx and Read the Docs for technical writers`_
* `Read the docs`_

.. _install Sphinx: http://sphinx-doc.org/install.html
.. _reStructuredText: http://sphinx-doc.org/rest.html
.. _Sphinx documentation: http://www.sphinx-doc.org/
.. _RestructuredText primer: http://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
.. _An introduction to Sphinx and Read the Docs for technical writers: http://ericholscher.com/blog/2016/jul/1/sphinx-and-rtd-for-writers/
.. _Read the docs: https://docs.readthedocs.io/en/latest/intro/getting-started-with-sphinx.html
