Balbuzard
=========

[Balbuzard](http://www.decalage.info/python/balbuzard) is a package of open-source python tools for malware analysis: 

- **balbuzard** is a tool to extract patterns of interest from malicious files, such as IP addresses, URLs and common file headers. It is easily extensible with patterns, regular expressions and Yara rules.
- **bbcrack** uses a new algorithm based on patterns of interest to bruteforce typical malware obfuscation such as XOR, ROL, ADD and various combinations. 
- **bbtrans** can apply any of the transforms from bbcrack (XOR, ROL, ADD and various combinations) to a file.

See <http://www.decalage.info/python/balbuzard> for more info.

----------------------------------------------------------------------------------

News
----

Follow all updates and news on Twitter: <https://twitter.com/decalage2>

- 2013-08-28 v0.12: Initial release of Balbuzard and bbcrack
- 2011-05-06: added bruteforce functions (bbcrack)
- 2008-06-06: first public release as rescan for SSTIC08
- 2007-07-11: first versions of rescan
- see changelog in source code for more info.


Download:
---------

The archive is available on [the project page on Bitbucket](https://bitbucket.org/decalage/balbuzard/downloads).

----------------------------------------------------------------------------------

balbuzard:
----------

balbuzard is a malware analysis tool to extract patterns of interest from malicious files, such as IP addresses, URLs and common file headers.

The idea is simple: When I need to analyse a malicious/suspicious file, the first thing I do is to open it into a hex viewer, to see which type of file it is with my own eyes. Then I quickly browse the file, looking for specific items of interest such as text, URLs, IP addresses, other embedded files, etc. This is very useful to decide how to analyse the file further, but also to extract evidence or potential [indicators of compromise (IOCs)](http://www.openioc.org/). 

But as soon as a file is larger than a few kilobytes, this can become very tedious, and you can overlook key details. This is why I wrote a simple script in 2007 called [rescan](http://www.decalage.info/rescan) to search for a list of regular expressions matching specific patterns, published as open-source for the [SSTIC08 conference](http://www.decalage.info/sstic08). Since then I improved the tool significantly and renamed it to Balbuzard.

### Features

- search for string or regular expression patterns
- default set of patterns for malware analysis
- easily extensible with new patterns in python scripts and Yara rules
- optional use of the Yara engine and Yara rules as patterns
- command-line tool or python module
- can open malware in password-protected zip files without writing to disk
- pure python 2.x, no dependency or compilation

Coming soon:

- CSV and HTML outputs
- batch analysis of multiple files/folders
- Unicode support

### How does it work?

Balbuzard looks for a number of patterns that correspond to items of interest when analyzing a malicious file. Each pattern can be a single string such as "This program cannot be run in DOS mode" which is present in most executable files on Windows, or a list of strings. It may also be a regular expression matching IP addresses, e-mail addresses or more complex patterns.

Each found pattern is reported with its position, its length and value. By default a short hex dump is displayed with a few bytes around the pattern.

The list of patterns to look for can be easily extended by adding a python script in the plugins directory (see below).

### Usage

	Usage: balbuzard.py [options] <filename>

	Options:
	  -h, --help            show this help message and exit
	  -s                    short display, without hex view.
	  -z ZIP_PASSWORD, --zip=ZIP_PASSWORD
	                        if the file is a zip archive, open first file from it,
	                        using the provided password (requires Python 2.6+)
	
Example:

	C:\balbuzard>balbuzard.py test.exe
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

### What are the differences with Yara?

Balbuzard may look similar to [Yara](http://code.google.com/p/yara-project), which is also a tool to search specific patterns into malicious files. 
First, Balbuzard is simpler than Yara. Balbuzard's patterns are simple strings or regular expressions, whereas Yara supports more complex rules. Balbuzard is a simple and portable pure python script, whereas Yara contains C code that needs to be compiled or installed as a library.
Second, Yara's original purpose is to "identify and classify malware
families" aimed at detection, whereas Balbuzard is to extract specific patterns from files that are already known as malicious. 
So in the end I would say that both tools are complementary.

Of course, it is possible to implement Balbuzard's set of patterns using Yara rules, and I plan to use the Yara engine as an option in the near future. It is already possible to use Yara rules to extend Balbuzard patterns. 

Back in 2007-2008 when I started developing this tool Yara was not yet published. And since then, I kept it like this because I prefer to have a lightweight pure python script in most cases.

### Other similar tools

Besides Yara, the following tools may also be used to search specific patterns within files: [signsrch](http://aluigi.altervista.org/mytoolz.htm#signsrch), [clamsrch](http://code.google.com/p/clamsrch/), [binwalk](http://code.google.com/p/binwalk/).


----------------------------------------------------------------------------------

bbcrack:
--------

bbcrack (Balbucrack) is a tool to crack malware obfuscation such as XOR, ROL, ADD (and
many combinations), by bruteforcing all possible keys and and checking for
specific patterns (IP addresses, domain names, URLs, known file headers and
strings, etc) using the Balbuzard engine.
The main difference with similar tools is that it supports a large number of transforms and it uses a  specific algorithm based on patterns of interest. 

### Features

- provided with a large number of obfuscation transforms such as XOR, ROL, ADD (including combined transforms)
- supports fast character-based transforms, or any file transform
- "harvest mode" for malware with multiple obfuscations/keys
- string or regular expression patterns
- options to select which transforms to check
- can open malware in password-protected zip files without writing to disk
- pure python 2.x, no dependency or compilation 

Coming soon:

- patterns and transforms easily extensible by python scripts
- optional use of the Yara engine and Yara rules as patterns
- CSV and HTML outputs
- batch analysis of multiple files/folders


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
	                        select transforms level 1, 2 or 3
	  -k KEEP, --keep=KEEP  number of transforms to keep after stage 1
	  -s SAVE, --save=SAVE  number of transforms to save to files after stage 2
	  -t TRANSFORM, --transform=TRANSFORM
	                        only check specific transforms (comma separated list,
	                        or "-t list" to display all available transforms)
	  -m                    harvest mode: will apply all transforms and extract
	                        patterns of interest. Slow, but useful when a file
	                        uses multiple transforms.
	  -z ZIP_PASSWORD, --zip=ZIP_PASSWORD
	                        if the file is a zip archive, open first file from it,
	                        using the provided password (requires Python 2.6+)
	  -p                    profiling: measure time spent on each pattern.
	

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

### Harvest mode

While bbcrack is great for malware obfuscated with a single transform and a single key, it might not be effective on malware using several transforms and/or several keys to obfuscate different parts or strings in a single file. For example a malware may use a different XOR key for each string.

The harvest mode is designed to address this case, by trying all transforms and all keys, extracting specific patterns of interest that can be found. This way, even if a URL or an IP address is obfuscated with a transform and key used only once, it should be reported in this mode.

However, this mode may return a lot of false positives. It is therefore necessary to analyze the results manually in order to extract meaningful data. 

It is recommended to add option "-l 1" in order to limit the search to level 1 transforms 

Here is an example, using a sample file containing random bytes and several patterns obfuscated with various transforms:

	>bbcrack.py -m -l 1 sample_multiple_transforms.bin

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

In future version the harvest mode will be moved to a separate tool in order to simplify command-line options. Additional filters will also be added to reduce the number of false positives. 

### Tips:

- if you only have a couple minutes, run a quick bbcrack at level 1.
- if you have 5-10 minutes, run bbcrack at level 2, go for a coffee.
- if nothing found, run bbcrack at level 3 while you go for lunch or during the night.
- if you found nothing, run bbcrack in harvest mode (option -m) at level 1 or 2, just to check if there are multiple transforms.
- if you found an executable file, run the harvest mode on the decoded file. Some executables have strings hidden by multiple transforms, so they would be missed by bbcrack in normal mode.


### How to extend the list of patterns and transforms

Coming soon: it will be possible to add new transforms and new patterns using plugin scripts in python, similarly to Balbuzard.

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

bbtrans:
--------

TODO

----------------------------------------------------------------------------------

How to contribute / report bugs:
--------------------------------

These are open-source tools developed on my spare time. Any contribution such as code improvements, ideas, bug reports, additional patterns or transforms would be highly appreciated. You may contact me using [this online form](http://www.decalage.info/contact), by e-mail (decalage at laposte.net) or use the [issue page on Bitbucket](https://bitbucket.org/decalage/balbuzard/issues?status=new&status=open) to report bugs/ideas, or clone the project then send me pull requests to suggest changes.


License
-------

This license applies to the Balbuzard package, apart from the thirdparty folder which contains third-party files published with their own license.

The Balbuzard package is copyright (c) 2007-2013, Philippe Lagadec (http://www.decalage.info)
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

