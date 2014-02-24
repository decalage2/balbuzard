Balbuzard
=========

[Balbuzard](http://www.decalage.info/python/balbuzard) is a package of open-source python tools for malware analysis: 

- **balbuzard** is a tool to extract patterns of interest from malicious files, such as IP addresses, URLs, embedded files and typical malware strings. It is easily extensible with new  patterns, regular expressions and Yara rules.
- **bbcrack** uses a new algorithm based on patterns of interest to bruteforce typical malware obfuscation such as XOR, ROL, ADD and various combinations, in order to guess which algorithms/keys have been used. 
- **bbharvest** extracts all patterns of interest found when applying typical malware obfuscation transforms such as XOR, ROL, ADD and various combinations, trying all possible keys. It is especially useful when several keys or several transforms are used in a single file.
- **bbtrans** can apply any of the transforms from bbcrack (XOR, ROL, ADD and various combinations) to a file.

When to use these tools:

- If you need to analyze a new malicious file, you can first try balbuzard to extract patterns of interest and detect embedded files in cleartext.
- Then if you think the malicious file might use an obfuscation algorithm such as XOR to hide interesting data, try bbcrack to find the algorithm and the key(s).
- Alternatively, if bbcrack is not successful, or if you think the file may use several algorithms and/or keys, try bbharvest.

Important note: while balbuzard and bbharvest are straightforward and readily usable, bbcrack is still an experimental tool and it has not been tested on many samples yet. Please [contact me](http://www.decalage.info/contact) if you test these tools on malware samples to tell me if it works or not.

See <http://www.decalage.info/python/balbuzard> for more info.

----------------------------------------------------------------------------------

News
----

Follow all updates and news on Twitter: <https://twitter.com/decalage2>

- 2014-02-24 v0.17: Initial release of Balbuzard tools
- 2013-03-15: added harvest mode (bbharvest)
- 2011-05-06: added bruteforce functions (bbcrack)
- 2008-06-06: first public release as rescan for SSTIC08
- 2007-07-11: first versions of rescan
- see changelog in source code for more info.


Download:
---------

The archive is available on [the project page on Bitbucket](https://bitbucket.org/decalage/balbuzard/downloads).

----------------------------------------------------------------------------------

5 Minutes Demo
--------------

Open a shell or a cmd.exe, go to the directory where you unzipped balbuzard. First, let's try balbuzard:

	balbuzard.py samples/sample1.doc

Output:

	at 00007040: IPv4 address - '12.34.56.78'
	at 000034CB: URL (http/https/ftp) - 'http://schemas.openxmlf...g/drawingml/2006/main"'
	at 0000704C: URL (http/https/ftp) - 'http://www.ccserver.com\x00'
	at 00007064: e-mail address - 'target@acme.com'
	at 00006C00: EXE MZ followed by PE - "MZ\x90\x00\x03\x00\x00\...\x00\x00\x00PE\x00\x00"
	at 00006C4E: EXE PE DOS message - 'This program cannot be run in DOS mode'
	at 00006FD8: Executable filename - 'KERNEL32.dll'
	at 00006FF4: Executable filename - 'USER32.dll'
	at 00007030: Executable filename - 'ADVAPI32.dll'
	at 00007057: Executable filename - 'ccserver.com'
	at 0000706B: Executable filename - 'acme.com'
	at 00007074: Executable filename - 'payload.dll'
	at 00006DC0: EXE: section name - '.text'
	at 00006E10: EXE: section name - '.data'
	at 00006DE8: EXE: section name - '.rdata'
	at 00006FBA: EXE: interesting Win32 function names - 'IsDebuggerPresent'
	at 00007010: EXE: interesting Win32 function names - 'RegSetValue'
	at 000070F7: Interesting registry keys - 'CurrentVersion\\Run'
	at 00000000: Possible OLE2 header (e.g. MS Office documents) - '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'


Obviously this is a MS Office document (magic at offset 0000), containing a MS Windows executable file located at offset 6C00. Balbuzard detects a number of interesting strings:

- an IP address: '12.34.56.78'
- a URL: http://www.ccserver.com
- an e-mail address: target@acme.com
- an executable filename: payload.dll
- a function to detect a debugger: 'IsDebuggerPresent'
- a function to write a registry value: 'RegSetValue'
- a registry key name used by malware to run at startup: 'CurrentVersion\\Run'

All this information may be very useful when analyzing this file further with other tools (sandbox, debugger, disassembler, etc).

Let's try balbuzard on a second sample:

	balbuzard.py samples/sample2.doc

This time, balbuzard only sees a MS Office document, but nothing else. However, when looking at the file with a hex viewer, there is an area at the end which looks suspicious. Let's use bbcrack to check if a known obfuscation algorithm has been used to hide data:

	bbcrack.py -l 1 samples/sample2.doc

Output:

	STAGE 1: quickly counting simple patterns for all transforms
	Best score so far: identity, stage 1 score=977315
	Best score so far: xor67_rol3, stage 1 score=1420985
	Checked 5873 transforms in 11.608649 seconds - 505.915900 transforms/s
	
	TOP 20 SCORES stage 1:
	          xor67_rol3: 1420985
	            identity: 977315
	               xor20: 867215
	          xor63_rol3: 500885
	[...]
	HIGHEST SCORES (>0):
	xor67_rol3: score 633404
	saving to file samples/sample2_xor67_rol3.doc
	identity: score 330686
	saving to file samples/sample2_identity.doc
	rol6_add57: score 18086
	saving to file samples/sample2_rol6_add57.doc
	[...]

bbcrack runs all known transforms (XOR, ROL, ADD and many combinations) with all their possible keys. Then a score is computed for each, based on the patterns of interest found in the transformed file. By default, the ten best scores are written to disk.

Here if we check the best score obtained with "xor67_rol3" in a hex viewer or with balbuzard, it turns out to be an executable file that was hidden within the document, obfuscated with a XOR+ROL algorithm:

	balbuzard.py samples/sample2_xor67_rol3.doc
	
	at 00006F30: IPv4 address - '12.34.56.78'
	at 00006F3C: URL (http/https/ftp) - 'http://www.ccserver.com\x00'
	at 00006F54: e-mail address - 'target@acme.com'
	at 00006C00: EXE MZ followed by PE - "MZ\x90\x00\x03\x00\x00\...\x00\x00\x00PE\x00\x00"
	at 00006C4E: EXE PE DOS message - 'This program cannot be run in DOS mode'
	[...]
	at 00006EEE: EXE: interesting Win32 function names - 'IsDebuggerPresent'

Now, let's check the third sample:

	balbuzard.py samples/sample3.exe
	
	at 00000000: EXE MZ followed by PE - 'MZ\x90\x00\x03\x00\x00\...\x00\x00\x00PE\x00\x00'
	at 0000004E: EXE PE DOS message - 'This program cannot be run in DOS mode'

This is an executable file, but there is no interesting string in clear text. If we run bbcrack, there is no useful result either. However, we know this small file is suspicious, and there seem to be obfuscated strings in it. Let's try bbharvest to look for obfuscated patterns of interest:

	bbharvest.py samples/sample3.exe
	
	*** WARNING: harvest mode may return a lot of false positives!
	identity: at 00000000 EXE MZ followed by PE, string='MZ\x90\x00\x03\x00\x00\...\x00\x00\x00PE\x00\x00'
	identity: at 0000004E EXE PE DOS message, string='This program cannot be run in DOS mode'
	[...]
	xor11: at 000002F0 e-mail address, string='target@acme.nl'
	xor88_rol5: at 000002D0 IPv4 address, string='173.194.67.99'
	rol3_addD6: at 000002E0 IPv4 address, string='74.125.136.94'

This time, bbharvest found three strings obfuscated with different transforms and keys:

- an e-mail address obfuscated with XOR 11
- two IP addresses obfuscated with XOR 88 + ROL 5, and ROL 3 + ADD D6

This is the end of this short demo. The next sections explain how to use the tools with more details and other examples.

----------------------------------------------------------------------------------

balbuzard:
----------

balbuzard is a malware analysis tool to extract patterns of interest from malicious files, such as IP addresses, URLs, typical EXE strings and common file headers.

The idea is simple: When I need to analyse a malicious/suspicious file, the first thing I do is to open it into a hex viewer, to see which type of file it is with my own eyes. Then I quickly browse the file, looking for specific items of interest such as text, URLs, IP addresses, other embedded files, etc. This is very useful to decide how to analyse the file further, but also to extract evidence or potential [indicators of compromise (IOCs)](http://www.openioc.org/). 

But as soon as a file is larger than a few kilobytes, this can become very tedious, and you can overlook key details. This is why I wrote a simple script in 2007 called [rescan](http://www.decalage.info/rescan) to search for a list of regular expressions matching specific patterns, published as open-source for the [SSTIC08 conference](http://www.decalage.info/sstic08). Since then I improved the tool significantly and renamed it to Balbuzard.

### Features

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

### How does it work?

Balbuzard looks for a number of patterns that correspond to items of interest when analyzing a malicious file. Each pattern can be a single string such as "This program cannot be run in DOS mode" which is present in most executable files on Windows, or a list of strings. It may also be a regular expression matching IP addresses, e-mail addresses or more complex patterns.

Each found pattern is reported with its position, its length and value. With the -v option, a short hex dump can be displayed with a few bytes around the pattern.

The list of patterns to look for can be easily extended by adding a python script in the plugins directory (see below).

### Usage

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
	
### How to select input files

You can specify one or several files to be analyzed:

	balbuzard.py sample1.doc sample2.doc sample3.exe

Using wildcards, it is possible to scan several files in a folder:

	balbuzard.py samples/*.bin

With the -r option, the search is recursive in all subfolders:

	balbuzard.py malwarezoo/*.exe -r

When scanning several files at once, it is recommended to use the CSV output (see below).

As many malware samples are stored in password-protected zip files, balbuzard is able to extract such files in memory to analyze them without writing to disk. This avoids being blocked by an antivirus. Use the option -z to specify the zip password:

	balbuzard.py -z infected malwarezoo/sample123.zip

By default, all files in the zip archive are extracted and analyzed. You may use the option -f to select files within the zip archive. Wildcards are supported, and the search is recursive:

	balbuzard.py -z infected malwarezoo/sample123.zip -f sample1.exe

For example, if you wanted to analyze all the [APT1 samples](http://contagiodump.blogspot.nl/2013/03/mandiant-apt1-samples-categorized-by.html) available on the Contagio website, you could run this command:

	balbuzard.py -z *** APT1_MALWARE_FAMILIES_samples.zip -f *sample*

### CSV output

With the -c option, results can be written in a CSV file, suitable for further analysis:

	balbuzard.py samples\*.bin -c results.csv


### Verbose output

With the -v option, each matched string is displayed with a hexadecimal dump:

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


### How to extend the list of patterns

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


### What are the differences with Yara?

Balbuzard may look similar to [Yara](http://code.google.com/p/yara-project), which is also a tool to search specific patterns into malicious files. 
First, Balbuzard is simpler than Yara. Balbuzard's patterns are simple strings or regular expressions, whereas Yara supports more complex rules. Balbuzard is a simple and portable pure python script, whereas Yara contains C code that needs to be compiled or installed as a library.
Second, Yara's original purpose is to "identify and classify malware
families" aimed at detection, whereas Balbuzard is to extract specific patterns from files that are already known as malicious. 
So in the end I would say that both tools are complementary.

Of course, it is possible to implement Balbuzard's set of patterns using Yara rules, and I plan to use the Yara engine as an option in the near future. It is already possible to use Yara rules to extend Balbuzard patterns. 

Back in 2007-2008 when I started developing this tool as rescan, Yara was not yet published. And since then, I kept it like this because I preferred to have a lightweight pure python script to develop other tools without requiring the installation of Yara.

### Other similar tools

Besides Yara, the following tools may also be used to search specific patterns within files: [signsrch](http://aluigi.altervista.org/mytoolz.htm#signsrch), [clamsrch](http://code.google.com/p/clamsrch/), [binwalk](http://code.google.com/p/binwalk/).


----------------------------------------------------------------------------------

bbcrack:
--------

bbcrack (Balbucrack) is a tool to crack typical malware obfuscation such as XOR, ROL, ADD (and
many combinations), by bruteforcing all possible keys and and checking for
specific patterns (IP addresses, domain names, URLs, known file headers and
strings, etc) using the Balbuzard engine.
The main difference with similar tools is that it supports a large number of transforms, extensible with python scripts, and it uses a specific algorithm based on patterns of interest. 

### Features

- provided with a large number of obfuscation transforms such as XOR, ROL, ADD (including combined transforms)
- supports fast character-based transforms, or any file transform
- string or regular expression patterns (balbuzard engine)
- transforms easily extensible by python scripts
- options to select which transforms to check
- can open malware in password-protected zip files without writing to disk
- pure python 2.x, no dependency or compilation 

Coming soon:

- patterns easily extensible by python scripts
- optional use of the Yara engine and Yara rules as patterns
- CSV and HTML outputs
- batch analysis of multiple files/folders
- Python 3.x support


### How does it work?

bbcrack contains a number of **obfuscation transforms** that can be applied to data. Each transform may have one or several parameters. For example, the XOR transform has a parameter (key) that can vary from 0 to 255. Each byte (B) in data is transformed to B XOR key. 

The current version of bbcrack includes the following transforms among others: XOR, ADD, ROL, XOR+ROL, XOR+ADD, ADD+XOR, XOR with incrementing key, XOR chained, etc. Run "bbcrack.py -t list" to check the full list.

The goal is to find which transform and which parameters were used to obfuscate the data, if any. When the right transform is found, specific patterns should normally appear in cleartext.

For performance reasons, bbcrack uses a two-stages algorithm:

- **Stage 1**: all selected transforms are applied to data, with all possible parameters. For each transform, a score is computed by looking for simple strings that appear in many malicious files such as null bytes, whitespaces, end of lines, and "This program cannot be run in DOS mode". The score is based on the length of the matched string and a weight for each pattern. Only the best scores are kept for stage 2.
- **Stage 2**: for all selected transforms, a new score is computed by looking for more elaborate patterns using the Balbuzard engine, such as IP addresses, e-mail addresses, executable filenames, CamelCase words, etc. At the end, the best scores are saved to disk for further investigation. If the file was effectively obfuscated using one of those transforms, the content should now appear in cleartext.

### Usage

	Usage: bbcrack.py [options] <filename>
	
	Options:
	  -h, --help            show this help message and exit
	  -l LEVEL, --level=LEVEL
	                        select transforms with level 1, 2 or 3 and below
	  -i INCLEVEL, --inclevel=INCLEVEL
	                        select transforms only with level 1, 2 or 3
	                        (incremental)
	  -k KEEP, --keep=KEEP  number of transforms to keep after stage 1
	  -s SAVE, --save=SAVE  number of transforms to save to files after stage 2
	  -t TRANSFORM, --transform=TRANSFORM
	                        only check specific transforms (comma separated list,
	                        or "-t list" to display all available transforms)
	  -z ZIP_PASSWORD, --zip=ZIP_PASSWORD
	                        if the file is a zip archive, open first file from it,
	                        using the provided password (requires Python 2.6+)
	  -p                    profiling: measure time spent on each pattern.


### How to select input files

See balbuzard


### How to select transforms

Transforms are organized in three levels (1,2,3): Level 1 are the simplest/fastest transforms (such as XOR), level 2 are more complex transforms (such as XOR+ADD), and level 3 are less frequent or slower transforms. See below for the full list.

**Level 1:**

- identity: Identity Transformation, no change to data. Parameters: none.
- xor: XOR with 8 bits static key A. Parameters: A (1-FF).
- add: ADD with 8 bits static key A. Parameters: A (1-FF).
- rol: ROL - rotate A bits left. Parameters: A (1-7).
- xor_rol: XOR with static 8 bits key A, then rotate B bits left. Parameters: A (1-FF), B (1-7).
- add_rol: ADD with static 8 bits key A, then rotate B bits left. Parameters: A (1-FF), B (1-7).
- rol_add: rotate A bits left, then ADD with static 8 bits key B. Parameters: A (1-7), B (1-FF).

**Level 2:**

- xor_add: XOR with 8 bits static key A, then ADD with 8 bits static key B. Parameters: A (1-FF), B (1-FF).
- add_xor: ADD with 8 bits static key A, then XOR with 8 bits static key B. Parameters: A (1-FF), B (1-FF).
- xor_inc: XOR with 8 bits key A incrementing after each character. Parameters: A (0-FF).
- xor_dec: XOR with 8 bits key A decrementing after each character. Parameters: A (0-FF).
- sub_inc: SUB with 8 bits key A incrementing after each character. Parameters: A (0-FF).
- xor_chained: XOR with 8 bits key A chained with previous character. Parameters: A (1-FF).
- xor_rchained: XOR with 8 bits key A chained with next character (Reverse order from end to start). Parameters: A (1-FF).

**Level 3:**

- xor_inc_rol: XOR with 8 bits key A incrementing after each character, then rotate B bits left. Parameters: A (0-FF), B (1-7).
- xor_rchained_all: XOR Transform, chained from the right with all following cha
racters. Only works well with bbharvest.

**Options -l and -i**:

With the option -l, all the transforms up to the specified level are selected. The following command will check transforms of all levels 1, 2 and 3 at once:

	bbcrack.py -l 3 sample.exe

With the option -i, only the specified level is selected. This is useful if you try first level 1 for a quick check, then levels 2 or 3 without running level 1 again.

	bbcrack.py -i 1 sample.exe
	bbcrack.py -i 2 sample.exe


### A real-life example:

- Download [this sample](http://contagiodump.blogspot.nl/2010/02/feb-2-cve-2009-4324-rep-mike-castle.html) 
from Contagio (ask me or Mila for the zip password if you don't know the contagio scheme).
- The sample PDF contains in fact two PDFs (starting with "%PDF", ending with
"%EOF") and a binary blob in between, which looks obfuscated.
- In you favorite hex editor (e.g. FileInsight, PSPad, UltraEdit, etc), extract
the binary blob from offset 1000h to ACC7h (40136 bytes long) to a file named
payload.bin.
- Then run: 

		bbcrack.py -l 3 payload.bin 

- it may take an hour to run. Or if you are in a hurry, you can cheat with:

		bbcrack.py -t xor_inc_rol payload.bin

- In the end, the best score is for the transform xor00\_inc\_rol5 (XOR with incremental key starting at 0, then ROL 5 bits).
- open the file payload\_xor00\_inc\_rol5.bin in a hex viewer: it should be a malicious executable
file in cleartext.


### Tips:

- if you only have a couple minutes, run a quick bbcrack at level 1.
- if you have 5-10 minutes, run bbcrack at level 2, go for a coffee.
- if nothing found, run bbcrack at level 3 while you go for lunch or during the night.
- if you found nothing, run bbharvest at level 1 or 2, just to check if there are multiple transforms.
- if you found an executable file, run bbharvest on the decoded file. Some executables have strings hidden by multiple transforms, so they would be missed by bbcrack in normal mode.


### How to extend the list of patterns and transforms

It is possible to extend bbcrack with your own transforms, using simple Python scripts. For this, you need to write a class, inheriting either from Transform_char or Transform_string:

- Transform_char: for transforms that apply to each character/byte independently, not depending on the location of the character. (example: simple XOR)
- Transform_string: for all other transforms, that may apply to several characters at once, or taking into account the location of the character. (example: XOR with increasing key)

Transform plugin scripts must be stored in the plugins subfolder, with a name starting with "trans_". Read the contents of the provided script "trans_sample_plugin.py" for detailed explanations and sample transforms that you can reuse.

All transforms and plugins are shared by bbcrack, bbharvest and bbtrans.

If you develop useful plugin scripts and you would like me to reference them, or if you think about additional transforms that bbcrack should include, please [contact me](http://www.decalage.info/contact).

Coming soon: it will be possible to add new patterns for bbcrack using plugin scripts in python, similarly to balbuzard.

### What are the differences with XORSearch, XORStrings, xortool and others?

For a good introduction to a number of malware deobfuscation tools, see [Lenny Zeltser's article](http://computer-forensics.sans.org/blog/2013/05/14/tools-for-examining-xor-obfuscation-for-malware-analysis) or [this presentation](http://bit.ly/15bI47C) from Michael Barr.

- [XORSearch](http://blog.didierstevens.com/programs/xorsearch/): C program, looks for one or several strings, ASCII, hex or unicode, supports XOR, ROL, ROT or SHIFT with single one-byte key (no combinations). 
- [XORStrings](http://blog.didierstevens.com/?s=xorstrings): C program, counts how many strings appear for each transform, supports XOR, ROL or SHIFT with single one-byte key (no combinations).
- [xorBruteForcer](http://eternal-todo.com/var/scripts/xorbruteforcer): Python script, tries all 255 one-byte XOR keys, can search for one string.
- [iheartxor/brutexor](http://hooked-on-mnemonics.blogspot.nl/p/iheartxor.html): Python script, tries all 255 one-byte XOR keys, can search for one regular expression, by default any string between null bytes.
- [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR): TODO
- [unxor](https://github.com/tomchop/unxor/): TODO
- xortool: TODO


----------------------------------------------------------------------------------

bbharvest:
----------

bbharvest extracts all patterns of interest found when applying transforms such as XOR, ROL, ADD and various combinations, trying all possible keys. It is especially useful when several keys or several transforms are used in a single file.

### Features

- uses the balbuzard engine and patterns, and bbcrack transforms
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


### How does it work?

While bbcrack is great for malware obfuscated with a single transform and a single key, it might not be effective on malware using several transforms and/or several keys to obfuscate different parts or strings in a single file. For example a malware may use a different XOR key for each string. bbcrack may also fail if only specific strings are obfuscated, such as IP addresses.

bbharvest is designed to address these cases, by trying all transforms and all keys, extracting specific patterns of interest that can be found. This way, even if a URL or an IP address is obfuscated with a transform and key used only once, it should be reported by bbharvest.

However, bbharvest may return a lot of false positives. It is therefore necessary to analyze the results manually in order to extract meaningful data. 

By default the search is limited to level 1 transforms, for time reasons. You may increase the scope using the options -l or -i. 

### Usage

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

See also the 5 minutes demo above.

### How to select input files

See balbuzard above.

### CSV output

Because bbharvest may find a lot of matching strings, often including false positives, it is very useful to write all results to a CSV file. Then it is easier to use a spreadsheet application to filter the results and highlight interesting strings. Example:

	bbharvest.py sample.exe -c output.csv

### How to select transforms

See bbcrack above.


### How to extend the list of patterns and transforms

See bbcrack above. Transforms and plugins are shared between bbcrack, bbharvest and bbtrans.


### Are there other similar tools?

For now, I haven't come across tools similar to bbharvest. If you find one, please [contact me](http://www.decalage.info/contact).

----------------------------------------------------------------------------------

bbtrans:
--------

bbtrans can apply any of the transforms from bbcrack (XOR, ROL, ADD and various combinations) to a file.

### Usage

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
	
### How to select input files

See balbuzard above.


### How to select transforms

Use the option -t, followed by the transform short name: see bbcrack above.

### How to specify parameters

Use the option -p, followed by one or several parameters corresponding to the transform. Parameters must be written in hexadecimal. If there are several parameters, use commas to separate them, without space.

Output files will be created with the same name as input files, with the short name of the transform including parameters.

Examples:

	bbtrans.py sample.exe -t xor -p 4F

This will produce a file named sample_xor4F.exe.

	bbtrans.py sample.exe -t xor_rol -p 4F,3

This will produce a file named sample_xor4F_rol3.exe.


### How to extend the list of patterns and transforms

See bbcrack above. Transforms and plugins are shared between bbcrack, bbharvest and bbtrans.


----------------------------------------------------------------------------------

How to contribute / report bugs:
--------------------------------

These are open-source tools developed on my spare time. Any contribution such as code improvements, ideas, bug reports, additional patterns or transforms would be highly appreciated. You may contact me using [this online form](http://www.decalage.info/contact), by e-mail (decalage at laposte.net) or use the [issue page on Bitbucket](https://bitbucket.org/decalage/balbuzard/issues?status=new&status=open) to report bugs/ideas, or clone the project then send me pull requests to suggest changes.


License
-------

This license applies to the whole Balbuzard package including balbuzard, bbcrack, bbharvest and bbtrans, apart from the thirdparty and plugins folders which contain third-party files published with their own license.

The Balbuzard package is copyright (c) 2007-2014, Philippe Lagadec (http://www.decalage.info)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

