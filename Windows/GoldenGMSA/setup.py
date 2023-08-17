
from setuptools import find_packages
from setuptools import setup
from os import path

import GoldenGMSA

cwd = path.abspath(path.dirname(__file__))

with open(path.join(cwd, "README.md")) as f:
    long_description = f.read()

with open(path.join(cwd, "requirements.txt")) as f:
    requirements = f.read()


setup(
    name="GoldenGMSA",
    version=GoldenGMSA.__version__,
    description="Abuse Group Managed Service Accounts (gMSA) in Active Directory.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AetherBlack/GoldenGMSA",
    author="athr",
    classifiers=[
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9"
    ],
    keywords="ActiveDirectory AD gMSA Group Managed Service Accounts",
    packages=find_packages(),
    python_requires=">=3.6, <4",
    install_requires=requirements,
    entry_points={
        "console_scripts": ["GoldenGMSA=GoldenGMSA.__main__:main"]
    }
)
