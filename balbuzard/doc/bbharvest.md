bbharvest
=========

bbharvest extracts all patterns of interest found when applying transforms such as XOR, ROL, ADD and various combinations, trying all possible keys. It is especially useful when several keys or several transforms are used in a single file.

bbharvest is part of the [Balbuzard](http://www.decalage.info/python/balbuzard) tools.

## Features

- uses the [[balbuzard]] engine and patterns, and [[bbcrack]] transforms
- search for string or regular expression patterns
- default set of patterns for malware analysis: IP addresses, e-mail addresses, URLs, typical EXE strings, common file headers, various malware strings
- provided with a large number of obfuscation transforms such as XOR, ROL, ADD (including combined transforms)
- supports fast character-based transforms, or any file transform
- transforms easily extensible by python scripts
- effective on malware with multiple obfuscations/keys
- options to select which transforms to check
- CSV output
- can open malware in password-protected zip files without writing to disk
- pure python 2.x, no dependency or compilation 

Coming soon:

- patterns and transforms easily extensible by python scripts
- optional use of the Yara engine and Yara rules as patterns
- CSV and HTML outputs
- batch analysis of multiple files/folders
- Python 3.x support


## How does it work?

While [[bbcrack]] is great for malware obfuscated with a single transform and a single key, it might not be effective on malware using several transforms and/or several keys to obfuscate different parts or strings in a single file. For example a malware may use a different XOR key for each string. bbcrack may also fail if only specific strings are obfuscated, such as IP addresses.

bbharvest is designed to address these cases, by trying all transforms and all keys, extracting specific patterns of interest that can be found. This way, even if a URL or an IP address is obfuscated with a transform and key used only once, it should be reported by bbharvest.

However, bbharvest may return a lot of false positives. It is therefore necessary to analyze the results manually in order to extract meaningful data. 

By default the search is limited to level 1 transforms, for time reasons. You may increase the scope using the options -l or -i. 

## Usage

	:::text
	Usage: bbharvest.py [options] <filename>
	
	Options:
	  -h, --help            show this help message and exit
	  -l LEVEL, --level=LEVEL
	                        select transforms level 1, 2 or 3
	  -i INCLEVEL, --inclevel=INCLEVEL
	                        select transforms only with level 1, 2 or 3
	                        (incremental)
	  -c CSV, --csv=CSV     export results to a CSV file
	  -t TRANSFORM, --transform=TRANSFORM
	                        only check specific transforms (comma separated list,
	                        or "-t list" to display all available transforms)
	  -z ZIP_PASSWORD, --zip=ZIP_PASSWORD
	                        if the file is a zip archive, open first file from it,
	                        using the provided password (requires Python 2.6+)
	  -p                    profiling: measure time spent on each pattern.

Here is an example, using a sample file containing random bytes and several patterns obfuscated with various transforms:

	:::text
	>bbharvest.py sample_multiple_transforms.bin

	Opening file sample_multiple_transforms.bin
	*** WARNING: harvest mode may return a lot of false positives!
	xor_BE: EXE MZ followed by PE at index C29, string='MZ\x90\x00\x03\x00\x00\x00\x
	04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\
	x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
	x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x0e\x1f\xba\x0e\x00\
	xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x
	00\x00\x00\x00\x009$7\xdd}EY\x8e}EY\x8e}EY\x8eZ\x83"\x8e~EY\x8e}EX\x8e|EY\x8et=\
	xda\x8e|EY\x8et=\xc8\x8e|EY\x8eRich}EY\x8e\x00\x00\x00\x00\x00\x00\x00\x00PE\x00
	\x00'
	xor_BE: Executable filename at index EBF, string='USER32.dll'
	xor_BE: EXE: section name at index DE1, string='.text'
	xor_BE: EXE: section name at index E31, string='.data'
	xor_BE: EXE: section name at index E09, string='.rdata'
	xor84_rol3: Executable filename at index 15B, string='k.Js'
	xor88_rol5: IP address at index 400, string='198.168.17.42'
	xorDB_rol2: e-mail address at index 5B9, string='o@9j.Ky'
	rol3_addD6: URL (http/https/ftp) at index 80E, string='http://www.mybotnet.com/cc\x00'
	rol3_addD6: Executable filename at index 819, string='mybotnet.com'

In this example it appears that the file contains an embedded executable file obfuscated with XOR 0xBE, an IP address with XOR 88 ROL 5, and a URL with ROL 3 ADD D6.

See also the 5 minutes [[Demo]] for another example.


## How to select input files

See [[balbuzard]].


## CSV output

Because bbharvest may find a lot of matching strings, often including false positives, it is very useful to write all results to a CSV file. Then it is easier to use a spreadsheet application to filter the results and highlight interesting strings. Example:

	:::text
	bbharvest.py sample.exe -c output.csv


## How to select transforms

See [[bbcrack]].


## How to extend the list of patterns and transforms

See bbcrack above. Transforms and plugins are shared between [[bbcrack]], bbharvest and [[bbtrans]].


## Are there other similar tools?

For now, I haven't come across tools similar to bbharvest. If you find one, please [contact me](http://www.decalage.info/contact).

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
