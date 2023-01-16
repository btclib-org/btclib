# Release

1. Run tox to verify that your code pass all tests
   (at least on your OS with your python version)

1. Set appropriate version inside btclib/\_\_init\_\_.py and docs/source/conf.py

1. Follow docs/README.rst and test that
   the documentation builds without problems

1. Add every major changes since the previous version to HISTORY.md,
   if they were not already there.

1. Push to GitHub.

   Verify that the documentation builds without failing on
   [read the docs](https://readthedocs.org/projects/btclib/builds/).

   Also check that the [website](https://btclib.org) and the
   [documentation](https://btclib.readthedocs.io/en/latest/)
   are displayed correctly in a browser.

1. Build the package distribution files:

   ```shell
   rm -r btclib.egg-info/ build/ dist/
   python setup.py sdist bdist_wheel
   ```

1. Push the package files to PyPi:

   ```shell
   twine upload dist/*
   ```

1. Create a new release on GitHub:

   Use the version as the title, and the history as the description.
   Also upload the files in the dist/ folder as release attachments.

1. Prepare for a new generic version:

   Choose a new version without specifying the day (e.g., if the previous
   release was 2022.2.9, choose 2022.3). Then set this new version
   in btclib/__init__.py and docs/source/conf.py.
   Also, update HISTORY.md with this new version.
