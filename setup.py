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
    keywords = 'bitcoin cryptography cryptocurrency elliptic-curves ecdsa schnorr',
    python_requires = '>=3.6',
    classifiers = [
        'Programming Language :: Python :: 3 :: Only',
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Education',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
