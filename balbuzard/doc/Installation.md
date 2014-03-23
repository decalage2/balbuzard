Balbuzard Installation
======================

## Pre-Requisites

### Python

Balbuzard requires a [Python 2.x](http://www.python.org/downloads/) interpreter. Python 2.7 or 2.6 are recommended, to enable all features.

Python 3 is not supported yet. Please [contact me](http://www.decalage.info/contact) if you are interested by Python 3 support.

### Yara

[Yara-python](http://plusvic.github.io/yara/) is optional but highly recommended. It is necessary for [[balbuzard]] to support Yara signatures, in order to detect many more patterns in malware.


## Install

### If you plan to use the Balbuzard scripts as command line tools:

Just unzip the archive in any folder, and run the scripts from that folder.
You may also add that folder to your PATH so that you can run them from anywhere.


### If you plan to import this package in your python applications:

On Windows, double-click on **install.bat**.

On all platforms, open a shell and run:

	:::text
	python setup.py install

If you have setuptools or pip installed, you may also use "easy_install balbuzard" or "pip install balbuzard" to download and install the latest version of Balbuzard automatically, but I have not tested it yet.

----------

## Documentation pages

- [[Home]]
- [[Installation]]
- [[Demo]]
- [[balbuzard]]
- [[bbcrack]]
- [[bbharvest]]
- [[bbtrans]]

## Quick links: 

- [Balbuzard home page](http://www.decalage.info/python/balbuzard)
- [Download](http://bitbucket.org/decalage/balbuzard/downloads) 
- [Documentation](https://bitbucket.org/decalage/balbuzard/wiki) 
- [Contact](http://www.decalage.info/contact) 
- [Report issues](https://bitbucket.org/decalage/balbuzard/issues?status=new&status=open) 
- [Updates on Twitter](https://twitter.com/decalage2)
