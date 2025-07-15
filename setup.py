#!/usr/bin/env python
import os
import subprocess
from setuptools import setup, find_packages

CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "License :: BMW Proprietary",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Topic :: Software Development :: Testing",
]

extra = {}

try:
    version_git = (
        os.getenv("GITPKGVTAG", None) or subprocess.check_output(["git", "rev-parse", "--short", "HEAD"]).rstrip()
    )
except (subprocess.CalledProcessError, OSError):
    version_git = "unknown"

extra["install_requires"] = open("requirements.txt").read().splitlines()

setup(
    name="diagnose",
    version="0.1",
    description="UDS (diagnosis) framework written in python",
    long_description=open("README.txt").read(),
    author="Braden Kjell <Kjell.Braden@bmw.de>",
    license="BMW proprietary",
    platforms="any",
    classifiers=CLASSIFIERS,
    packages=find_packages(),
    setup_requires=["setuptools_scm"],
    use_scm_version=True,
    entry_points={
        "console_scripts": ["hsfz-ident = diagnose.hsfz:main"],
        "diagnose.connector": ["hsfz = diagnose.hsfz"],
    },
    **extra
)
