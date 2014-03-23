bbtrans
=======

bbtrans can apply any of the transforms from [[bbcrack]] (XOR, ROL, ADD and various combinations) to a file.

It is part of the [Balbuzard](http://www.decalage.info/python/balbuzard) tools.

## Usage

	:::text
	Usage: bbtrans.py [options] <filename>
	
	Options:
	  -h, --help            show this help message and exit
	  -t TRANSFORM, --transform=TRANSFORM
	                        transform to be applied (or "-t list" to display all
	                        available transforms)
	  -p PARAMS, --params=PARAMS
	                        parameters for transform (comma separated list)
	  -z ZIP_PASSWORD, --zip=ZIP_PASSWORD
	                        if the file is a zip archive, open first file from it,
	                        using the provided password (requires Python 2.6+)
	
## How to select input files

See [[balbuzard]].


## How to select transforms

Use the option -t, followed by the transform short name: see [[bbcrack]].

## How to specify parameters

Use the option -p, followed by one or several parameters corresponding to the transform. Parameters must be written in hexadecimal. If there are several parameters, use commas to separate them, without space.

Output files will be created with the same name as input files, with the short name of the transform including parameters.

Examples:

	:::text
	bbtrans.py sample.exe -t xor -p 4F

This will produce a file named sample_xor4F.exe.

	:::text
	bbtrans.py sample.exe -t xor_rol -p 4F,3

This will produce a file named sample_xor4F_rol3.exe.


## How to extend the list of patterns and transforms

See [[bbcrack]]. Transforms and plugins are shared between [[bbcrack]], [[bbharvest]] and bbtrans.


## How to use bbtrans in your python applications

TODO



----------------------------------------------------------------------------------

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
