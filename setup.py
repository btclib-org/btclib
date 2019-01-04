from setuptools import setup, find_packages
import btclib

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name = btclib.name,
    version = btclib.__version__,
    url = 'https://github.com/dginst/BitcoinBlockchainTechnology',
    license = 'MIT License',
    author = 'Ferdinando M. Ametrano',
    author_email = 'ferdinando@ametrano.net',
    description = 'A bitcoin cryptography library.',
    long_description = 'Type annotated library intended for teaching and demonstration of the cryptography used in bitcoin.',
    long_description_content_type = 'text/markdown',
    packages = find_packages(),
    keywords = 'bitcoin cryptography elliptic-curves ecdsa schnorr elliptic-curve-diffie-hellman bip32 bip39 base58 electrum rfc-6979 pedersen-commitment',
    python_requires = '>=3.6',
    classifiers = [
        'Programming Language :: Python :: 3 :: Only',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Education',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: Scientific/Engineering',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
