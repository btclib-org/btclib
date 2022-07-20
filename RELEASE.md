# Release

1. Run tox to verify that we pass all the tests (at least on our local machine)

2. Set appropriate version inside btclib/__init__.py and docs/source/conf.py

3. Follow docs/README.rst and test that the documentation builds without problems

4. Add every major change since the previous version to HISTORY.md, if it wasn't already added.

5. Push to Github. Verify that the documentation builds without failing on [read the docs](https://readthedocs.org/projects/btclib/builds/).   
  Also check that the [website](https://btclib.org) and the [documentation](https://btclib.readthedocs.io/en/latest/) are displayed correctly in a browser

6. Build the package distribution files:

   ```rm -r btclib.egg-info/ build/ dist/ && python setup.py sdist bdist_wheel```
   
7. Push the package files to PyPi:

    ```twine upload dist/*```

8. Create a new release on Github:

    Use the version as the title, and the history as the description. Also upload the files in the dist/ folder 
    as the release attachments
    
9. Prepare for a new generic version:

    Choose a new version without specifying the day (es. if the previous release was 2022.2.9, choose 2022.3)\
    Then set the version in btclib/__init__.py and docs/source/conf.py to this new version. \
    Use this new version name in HISTORY.md, specifying that it is in development