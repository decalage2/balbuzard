5 Minutes Demo
==============

With this short demo you can test the [Balbuzard](http://www.decalage.info/python/balbuzard) tools by yourself in a few minutes using provided samples. Check the [[Installation]] page if you have not done it yet. The samples are located in the balbuzard/samples subfolder in the Balbuzard package.

Open a shell or a cmd.exe, go to the directory where you unzipped Balbuzard, in the balbuzard subdirectory where the python tools are located. 


Sample 1 - balbuzard
--------------------

First, let's try **[[balbuzard]]**:

	balbuzard.py samples/sample1.doc

Output:

	:::text
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


Obviously this is a [MS Office document](http://www.decalage.info/file_formats_security/office) (magic at offset 0000), containing a MS Windows executable file located at offset 6C00. [[balbuzard]] detects a number of interesting strings:

- an IP address: '12.34.56.78'
- a URL: http://www.ccserver.com
- an e-mail address: target@acme.com
- an executable filename: payload.dll
- a function to detect a debugger: 'IsDebuggerPresent'
- a function to write a registry value: 'RegSetValue'
- a registry key name used by malware to run at startup: 'CurrentVersion\\Run'

All this information may be very useful when analyzing this file further with other tools (sandbox, debugger, disassembler, etc).


Sample 2 - bbcrack
------------------

Let's try balbuzard on a second sample:

	balbuzard.py samples/sample2.doc

This time, balbuzard only sees a MS Office document, but nothing else. However, when looking at the file with a hex viewer, there is an area at the end which looks suspicious. Let's use **[[bbcrack]]** to check if a known obfuscation algorithm has been used to hide data:

	bbcrack.py -l 1 samples/sample2.doc

Output:

	:::text
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

[[bbcrack]] runs all known transforms (XOR, ROL, ADD and many combinations) with all their possible keys. Then a score is computed for each, based on the patterns of interest found in the transformed file. By default, the ten best scores are written to disk.

Here if we check the best score obtained with "xor67_rol3" in a hex viewer or with balbuzard, it turns out to be an executable file that was hidden within the document, obfuscated with a XOR+ROL algorithm:

	:::text
	balbuzard.py samples/sample2_xor67_rol3.doc

	at 00006F30: IPv4 address - '12.34.56.78'
	at 00006F3C: URL (http/https/ftp) - 'http://www.ccserver.com\x00'
	at 00006F54: e-mail address - 'target@acme.com'
	at 00006C00: EXE MZ followed by PE - "MZ\x90\x00\x03\x00\x00\...\x00\x00\x00PE\x00\x00"
	at 00006C4E: EXE PE DOS message - 'This program cannot be run in DOS mode'
	[...]
	at 00006EEE: EXE: interesting Win32 function names - 'IsDebuggerPresent'


Sample 3 - bbharvest
--------------------

Now, let's check the third sample:

	:::text
	balbuzard.py samples/sample3.exe

	at 00000000: EXE MZ followed by PE - 'MZ\x90\x00\x03\x00\x00\...\x00\x00\x00PE\x00\x00'
	at 0000004E: EXE PE DOS message - 'This program cannot be run in DOS mode'

This is an executable file, but there is no interesting string in clear text. If we run bbcrack, there is no useful result either. However, we know this small file is suspicious, and there seem to be obfuscated strings in it. Let's try **[[bbharvest]]** to look for obfuscated patterns of interest:

	:::text
	bbharvest.py samples/sample3.exe

	*** WARNING: harvest mode may return a lot of false positives!
	identity: at 00000000 EXE MZ followed by PE, string='MZ\x90\x00\x03\x00\x00\...\x00\x00\x00PE\x00\x00'
	identity: at 0000004E EXE PE DOS message, string='This program cannot be run in DOS mode'
	[...]
	xor11: at 000002F0 e-mail address, string='target@acme.nl'
	xor88_rol5: at 000002D0 IPv4 address, string='173.194.67.99'
	rol3_addD6: at 000002E0 IPv4 address, string='74.125.136.94'

This time, [[bbharvest]] found three strings obfuscated with different transforms and keys:

- an e-mail address obfuscated with XOR 11
- two IP addresses obfuscated with XOR 88 + ROL 5, and ROL 3 + ADD D6

This kind of strings would not be found by bbcrack due to its design, but bbharvest runs a slower algorithm that can expose even single strings obfuscated with an algorithm/key that is used only once.

This is the end of this short demo. The next sections explain how to use the tools with more details and other examples: [[balbuzard]], [[bbcrack]], [[bbharvest]], [[bbtrans]].


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
