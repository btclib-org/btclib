from setuptools import setup, find_packages
import btclib

with open('README.md', 'r') as fh:
    longdescription = fh.read()

setup(
    name = btclib.name,
    version = btclib.__version__,
    url = 'http://github.com/dginst/btclib',
    license = btclib.__license__,
    author = 'Digital Gold Institute',
    description = 'A bitcoin cryptography library.',
    long_description = longdescription,
    long_description_content_type = 'text/markdown',
    packages = find_packages(exclude=['tests']),
    include_package_data = True,
    keywords = 'bitcoin cryptography elliptic-curves dsa schnorr RFC-6979 bip32 bip39 electrum base58',
    python_requires = '>=3.6',
    classifiers = [
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',

        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Intended Audience :: Education',

        'License :: OSI Approved :: MIT License',

        'Natural Language :: English',

        'Operating System :: OS Independent',

        'Topic :: Security :: Cryptography',
        'Topic :: Scientific/Engineering',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
