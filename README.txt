python-diagnose
===============
Author: Kjell Braden
Language: Python 3.5
svn: https://asc-repo.bmwgroup.net/gerrit/ascgit182.tools.diagnose

Dependencies
============
Debian-based systems may install python-six through apt:
	apt-get install python-six

all other packages through pip, automatically:
	pip3 install -r

if you want to use the boilerplate you need to install additional packages:
    pip3 install ipython
    pip3 install progress

complete the installation executing the following command:
    pip3 install --editable .

Summary
=======
Python-diagnose is a UDS (diagnosis) framework written in python. This means
it provides a few classes for abstraction of UDS and underlying transport protocols.

Implemented protocols are UDS on HSFZ-external as well as UDS on CAN/ISO-TP.

Usage
=====
Check out diagnose/boilerplate.py. For an interactive shell, run:

	python3 -m diagnose.interactive hsfz

Get help using --help, e.g., the following command will list help for the HSFZ connector.

	python3 -m diagnose.interactive hsfz --help
