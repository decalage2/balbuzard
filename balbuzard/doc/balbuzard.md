balbuzard
=========

balbuzard is a malware analysis tool to extract patterns of interest from malicious files, such as IP addresses, URLs, typical EXE strings and common file headers. It is part of the [Balbuzard](http://www.decalage.info/python/balbuzard) tools.

The idea is simple: When I need to analyse a malicious/suspicious file, the first thing I do is to open it into a hex viewer, to see which type of file it is with my own eyes. Then I quickly browse the file, looking for specific items of interest such as text, URLs, IP addresses, other embedded files, etc. This is very useful to decide how to analyse the file further, but also to extract evidence or potential [indicators of compromise (IOCs)](http://www.openioc.org/). 

But as soon as a file is larger than a few kilobytes, this can become very tedious, and you can overlook key details. This is why I wrote a simple script in 2007 called [rescan](http://www.decalage.info/rescan) to search for a list of regular expressions matching specific patterns, published as open-source for the [SSTIC08 conference](http://www.decalage.info/sstic08). Since then I improved the tool significantly and renamed it to Balbuzard.

## Features

- search for string or regular expression patterns
- default set of patterns for malware analysis: IP addresses, e-mail addresses, URLs, typical EXE strings, common file headers, various malware strings
- optional use of the Yara engine and Yara rules as patterns
- includes Yara signatures from the [Malware Analyst's Cookbook](https://code.google.com/p/malwarecookbook) (capabilities, packer and magic), [signsrch](http://aluigi.altervista.org/mytoolz.htm#signsrch)/[clamsrch](http://code.google.com/p/clamsrch/) (standard encryption constants) and [AlienVault Labs](https://github.com/AlienVault-Labs/AlienVaultLabs) (malware signatures such as APT1).
- easily extensible with new patterns in python scripts and Yara rules
- CSV output
- batch analysis of multiple files/folders on disk or within zips
- command-line tool or python module
- can open malware in password-protected zip files without writing to disk
- pure python 2.x, no dependency or compilation

Coming soon:

- XML and HTML outputs
- Unicode support
- Python 3.x support

## How does it work?

Balbuzard looks for a number of patterns that correspond to items of interest when analyzing a malicious file. Each pattern can be a single string such as "This program cannot be run in DOS mode" which is present in most executable files on Windows, or a list of strings. It may also be a regular expression matching IP addresses, e-mail addresses or more complex patterns.

Each found pattern is reported with its position, its length and value. With the -v option, a short hex dump can be displayed with a few bytes around the pattern.

The list of patterns to look for can be easily extended by adding a python script in the plugins directory (see below).

## Usage

	:::text
	Usage: balbuzard.py [options] <filename> [filename2 ...]
	
	Options:
	  -h, --help            show this help message and exit
	  -c CSV, --csv=CSV     export results to a CSV file
	  -v                    verbose display, with hex view.
	  -r                    find files recursively in subdirectories.
	  -z ZIP_PASSWORD, --zip=ZIP_PASSWORD
	                        if the file is a zip archive, open first file from it,
	                        using the provided password (requires Python 2.6+)
	  -f ZIP_FNAME, --zipfname=ZIP_FNAME
	                        if the file is a zip archive, file(s) to be opened
	                        within the zip. Wildcards * and ? are supported.
	                        (default:*)
	
## How to select input files

You can specify one or several files to be analyzed:

	:::text
	balbuzard.py sample1.doc sample2.doc sample3.exe

Using wildcards, it is possible to scan several files in a folder:

	:::text
	balbuzard.py samples/*.bin

With the -r option, the search is recursive in all subfolders:

	:::text
	balbuzard.py malwarezoo/*.exe -r

When scanning several files at once, it is recommended to use the CSV output (see below).

As many malware samples are stored in password-protected zip files, balbuzard is able to extract such files in memory to analyze them without writing to disk. This avoids being blocked by an antivirus. Use the option -z to specify the zip password:

	:::text
	balbuzard.py -z infected malwarezoo/sample123.zip

By default, all files in the zip archive are extracted and analyzed. You may use the option -f to select files within the zip archive. Wildcards are supported, and the search is recursive:

	:::text
	balbuzard.py -z infected malwarezoo/sample123.zip -f sample1.exe

For example, if you wanted to analyze all the [APT1 samples](http://contagiodump.blogspot.nl/2013/03/mandiant-apt1-samples-categorized-by.html) available on the Contagio website, you could run this command:

	:::text
	balbuzard.py -z *** APT1_MALWARE_FAMILIES_samples.zip -f *sample*

## CSV output

With the -c option, results can be written in a CSV file, suitable for further analysis:

	:::text
	balbuzard.py samples\*.bin -c results.csv


## Verbose output

With the -v option, each matched string is displayed with a hexadecimal dump:

	:::text
	C:\balbuzard>balbuzard.py -v test.exe
	Loading plugin from plugins\bbz_sample_plugin.py
	Opening file test.exe
	Filetype according to magic: application/x-ms-dos-executable
	
	-------------------------------------------------------------------------------
	EXE PE DOS message:
	at 0000004E: 'This program cannot be run in DOS mode'
	0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
	0030   00 00 00 00 00 00 00 00 00 00 00 00 C0 00 00 00    ................
	0040   0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68    ........!..L.!Th
	0050   69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F    is program canno
	0060   74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20    t be run in DOS
	0070   6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00    mode....$.......
	0080   39 24 37 DD 7D 45 59 8E 7D 45 59 8E 7D 45 59 8E    9$7.}EY.}EY.}EY.
	0090   5A 83 22 8E 7E 45 59 8E 7D 45 58 8E 7C 45 59 8E    Z.".~EY.}EX.|EY.
	
	-------------------------------------------------------------------------------
	Executable filename:
	at 00000296: 'USER32.dll'
	0270   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
	0280   88 02 00 00 00 00 00 00 F8 01 4D 65 73 73 61 67    ..........Messag
	0290   65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C    eBoxA.USER32.dll
	02A0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
	02B0   54 69 6E 79 20 45 58 45 00 00 00 00 54 68 69 73    Tiny EXE....This


## How to extend the library of patterns

Additional patterns can be provided by creating plugin scripts written in Python: each script needs to be named bbz*.py, and placed in the plugins folder. Each plugin script should add a list of Pattern objects to the patterns list, for example:

	:::python
		patterns += [
		    # example: a pattern with a simple case-INsensitive string
		    Pattern("EXE PE DOS message", "This program cannot be run in DOS mode", nocase=True),
		    # example: a pattern with a list of strings
		    Pattern("EXE: section name", [".text", ".data", ".rdata", ".rsrc"])
		    # example: a pattern with a regular expression, case-insensitive
		    Pattern_re("Executable filename", r"\w+\.(EXE|COM|VBS|JS|VBE|JSE|BAT|CMD|DLL|SCR)", nocase=True),
		    ]

See bbz\_sample\_plugin.py in the plugins folder for more examples.

If [yara-python](http://code.google.com/p/yara-project/downloads/list) is installed, you may also use Yara rules as patterns for Balbuzard. For this, simply copy Yara rules as .yara files in the plugins directory. See capabilities.yara as an example.

To disable a plugin (python or yara), you can simply rename the file with an extension such as ".disabled".

If you develop useful plugin scripts and you would like me to reference them, or if you think about additional transforms that bbcrack should include, please [contact me](http://www.decalage.info/contact).


## How to use the balbuzard engine in your python applications

TODO


## What are the differences with Yara?

Balbuzard may look similar to [Yara](http://code.google.com/p/yara-project), which is also a tool to search specific patterns into malicious files. 
First, Balbuzard is simpler than Yara. Balbuzard's patterns are simple strings or regular expressions, whereas Yara supports more complex rules. Balbuzard is a simple and portable pure python script, whereas Yara contains C code that needs to be compiled or installed as a library.
Second, Yara's original purpose is to "identify and classify malware
families" aimed at detection, whereas Balbuzard is to extract specific patterns from files that are already known as malicious. 
So in the end I would say that both tools are complementary.

Of course, it is possible to implement Balbuzard's set of patterns using Yara rules, and I plan to use the Yara engine as an option in the near future. It is already possible to use Yara rules to extend Balbuzard patterns. 

Back in 2007-2008 when I started developing this tool as rescan, Yara was not yet published. And since then, I kept it like this because I preferred to have a lightweight pure python script to develop other tools without requiring the installation of Yara.

## Other similar tools

Besides Yara, the following tools may also be used to search specific patterns within files: [signsrch](http://aluigi.altervista.org/mytoolz.htm#signsrch), [clamsrch](http://code.google.com/p/clamsrch/), [binwalk](http://code.google.com/p/binwalk/).


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
