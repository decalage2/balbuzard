bbcrack:
========

bbcrack (Balbucrack) is a tool to crack typical malware obfuscation such as XOR, ROL, ADD (and
many combinations), by bruteforcing all possible keys and and checking for
specific patterns (IP addresses, domain names, URLs, known file headers and
strings, etc) using the [[balbuzard]] engine.
The main difference with similar tools is that it supports a large number of transforms, extensible with python scripts, and it uses a specific algorithm based on patterns of interest. bbcrack is part of the [Balbuzard](http://www.decalage.info/python/balbuzard) tools.

## Features

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


## How does it work?

bbcrack contains a number of **obfuscation transforms** that can be applied to data. Each transform may have one or several parameters. For example, the XOR transform has a parameter (key) that can vary from 0 to 255. Each byte (B) in data is transformed to B XOR key. 

The current version of bbcrack includes the following transforms among others: XOR, ADD, ROL, XOR+ROL, XOR+ADD, ADD+XOR, XOR with incrementing key, XOR chained, etc. Run "bbcrack.py -t list" to check the full list.

The goal is to find which transform and which parameters were used to obfuscate the data, if any. When the right transform is found, specific patterns should normally appear in cleartext.

For performance reasons, bbcrack uses a two-stages algorithm:

- **Stage 1**: all selected transforms are applied to data, with all possible parameters. For each transform, a score is computed by looking for simple strings that appear in many malicious files such as null bytes, whitespaces, end of lines, and "This program cannot be run in DOS mode". The score is based on the length of the matched string and a weight for each pattern. Only the best scores are kept for stage 2.
- **Stage 2**: for all selected transforms, a new score is computed by looking for more elaborate patterns using the Balbuzard engine, such as IP addresses, e-mail addresses, executable filenames, CamelCase words, etc. At the end, the best scores are saved to disk for further investigation. If the file was effectively obfuscated using one of those transforms, the content should now appear in cleartext.

## Usage

	:::text
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


## How to select input files

See [[balbuzard]]


## How to select transforms

Transforms are organized in three levels (1,2,3): Level 1 are the simplest/fastest transforms (such as XOR), level 2 are more complex transforms (such as XOR+ADD), and level 3 are less frequent or slower transforms. See below for the full list.

### Level 1:

- **identity**: Identity Transformation, no change to data. Parameters: none.
- **xor**: XOR with 8 bits static key A. Parameters: A (1-FF).
- **add**: ADD with 8 bits static key A. Parameters: A (1-FF).
- **rol**: ROL - rotate A bits left. Parameters: A (1-7).
- **xor_rol**: XOR with static 8 bits key A, then rotate B bits left. Parameters: A (1-FF), B (1-7).
- **add_rol**: ADD with static 8 bits key A, then rotate B bits left. Parameters: A (1-FF), B (1-7).
- **rol_add**: rotate A bits left, then ADD with static 8 bits key B. Parameters: A (1-7), B (1-FF).

### Level 2:

- **xor_add**: XOR with 8 bits static key A, then ADD with 8 bits static key B. Parameters: A (1-FF), B (1-FF).
- **add_xor**: ADD with 8 bits static key A, then XOR with 8 bits static key B. Parameters: A (1-FF), B (1-FF).
- **xor_inc**: XOR with 8 bits key A incrementing after each character. Parameters: A (0-FF).
- **xor_dec**: XOR with 8 bits key A decrementing after each character. Parameters: A (0-FF).
- **sub_inc**: SUB with 8 bits key A incrementing after each character. Parameters: A (0-FF).
- **xor_chained**: XOR with 8 bits key A chained with previous character. Parameters: A (1-FF).
- **xor_rchained**: XOR with 8 bits key A chained with next character (Reverse order from end to start). Parameters: A (1-FF).

### Level 3:

- **xor_inc_rol**: XOR with 8 bits key A incrementing after each character, then rotate B bits left. Parameters: A (0-FF), B (1-7).
- **xor_rchained_all**: XOR Transform, chained from the right with all following cha
racters. Only works well with bbharvest.

### Options -l and -i:

With the option -l, all the transforms up to the specified level are selected. The following command will check transforms of all levels 1, 2 and 3 at once:

	:::text
	bbcrack.py -l 3 sample.exe

With the option -i, only the specified level is selected. This is useful if you try first level 1 for a quick check, then levels 2 or 3 without running level 1 again.

	:::text
	bbcrack.py -i 1 sample.exe
	bbcrack.py -i 2 sample.exe


## A real-life example:

- Download [this sample](http://contagiodump.blogspot.nl/2010/02/feb-2-cve-2009-4324-rep-mike-castle.html) 
from Contagio (ask me or Mila for the zip password if you don't know the contagio scheme).
- The sample PDF contains in fact two PDFs (starting with "%PDF", ending with
"%EOF") and a binary blob in between, which looks obfuscated.
- In you favorite hex editor (e.g. FileInsight, PSPad, UltraEdit, etc), extract
the binary blob from offset 1000h to ACC7h (40136 bytes long) to a file named
payload.bin.

Then run: 

	:::text
	bbcrack.py -l 3 payload.bin 

It may take an hour to run. Or if you are in a hurry, you can cheat with:

	:::text
	bbcrack.py -t xor_inc_rol payload.bin

- In the end, the best score is for the transform xor00\_inc\_rol5 (XOR with incremental key starting at 0, then ROL 5 bits).
- open the file payload\_xor00\_inc\_rol5.bin in a hex viewer: it should be a malicious executable
file in cleartext.


## Tips:

- if you only have a couple minutes, run a quick bbcrack at level 1.
- if you have 5-10 minutes, run bbcrack at level 2, go for a coffee.
- if nothing found, run bbcrack at level 3 (option -i 3) while you go for lunch or during the night.
- if you found nothing, run [[bbharvest]] at level 1 or 2, just to check if there are multiple transforms.
- if you found an executable file, run [[bbharvest]] on the decoded file. Some executables have strings hidden by multiple transforms, so they would be missed by bbcrack in normal mode.


## How to extend the list of patterns and transforms

It is possible to extend bbcrack with your own transforms, using simple Python scripts. For this, you need to write a class, inheriting either from Transform_char or Transform_string:

- **Transform_char**: for transforms that apply to each character/byte independently, not depending on the location of the character. (example: simple XOR)
- **Transform_string**: for all other transforms, that may apply to several characters at once, or taking into account the location of the character. (example: XOR with increasing key)

Transform plugin scripts must be stored in the **plugins** subfolder, with a name starting with "trans_". Read the contents of the provided script "trans_sample_plugin.py" for detailed explanations and sample transforms that you can reuse.

All transforms and plugins are shared by bbcrack, [[bbharvest]] and [[bbtrans]].

If you develop useful plugin scripts and you would like me to reference them, or if you think about additional transforms that bbcrack should include, please [contact me](http://www.decalage.info/contact).

Coming soon: it will be possible to add new patterns for bbcrack using plugin scripts in python, similarly to [[balbuzard]].

## How to use the bbcrack engine in your python applications

TODO


## What are the differences with XORSearch, XORStrings, xortool and others?

For a good introduction to a number of malware deobfuscation tools, see [Lenny Zeltser's article](http://computer-forensics.sans.org/blog/2013/05/14/tools-for-examining-xor-obfuscation-for-malware-analysis), or [this presentation](http://bit.ly/15bI47C) from Michael Barr.

- [XORSearch](http://blog.didierstevens.com/programs/xorsearch/): C program, looks for one or several strings, ASCII, hex or unicode, supports XOR, ROL, ROT or SHIFT with single one-byte key (no combinations). 
- [XORStrings](http://blog.didierstevens.com/?s=xorstrings): C program, counts how many strings appear for each transform, supports XOR, ROL or SHIFT with single one-byte key (no combinations).
- [xorBruteForcer](http://eternal-todo.com/var/scripts/xorbruteforcer): Python script, tries all 255 one-byte XOR keys, can search for one string.
- [iheartxor/brutexor](http://hooked-on-mnemonics.blogspot.nl/p/iheartxor.html): Python script, tries all 255 one-byte XOR keys, can search for one regular expression, by default any string between null bytes.
- [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR): TODO
- [unxor](https://github.com/tomchop/unxor/): TODO
- xortool: TODO
- [xortools extended by hiddenillusion](https://github.com/hiddenillusion/yara-goodies): TODO
- [xor_poc](http://www.cloudshield.com/blog/advanced-malware/how-to-efficiently-detect-xor-encoded-content-part-1-of-2/): TODO


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
