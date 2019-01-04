from setuptools import setup, find_packages
import btclib

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name = btclib.name,
    version = btclib.__version__,
    url = 'https://github.com/dginst/btclib',
    license = 'MIT License',
    author = 'Ferdinando M. Ametrano',
    author_email = 'ferdinando@ametrano.net',
    description = 'A bitcoin cryptography library.',
    long_description = 'Type annotated library intended for teaching and demonstration of the cryptography used in bitcoin.',
    long_description_content_type = 'text/markdown',
    packages = find_packages(),
    keywords = 'bitcoin cryptography elliptic-curves ecdsa schnorr rfc-6979 bip32 bip39 electrum base58',
    python_requires = '>=3.6',
    classifiers = [
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
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
