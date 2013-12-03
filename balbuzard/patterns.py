"""
balbuzard patterns - v0.01 2013-12-03 Philippe Lagadec

This file contains pattern definitions for the Balbuzard tools.

Balbuzard is a package of open-source python tools for malware analysis:
balbuzard is a tool to extract patterns of interest from malicious files, such
as IP addresses, URLs and common file headers. It is easily extensible with
patterns, regular expressions and Yara rules.
bbcrack uses a new algorithm based on patterns of interest to bruteforce typical
malware obfuscation such as XOR, ROL, ADD and various combinations.

For more info and updates: http://www.decalage.info/balbuzard


balbuzard is copyright (c) 2007-2013, Philippe Lagadec (http://www.decalage.info)
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
"""

__version__ = '0.01'

#------------------------------------------------------------------------------
# CHANGELOG:
# 2013-12-03 v0.01 PL: - 1st version, moved patterns from balbuzard

#------------------------------------------------------------------------------
# TODO:
# + declare each pattern as a variable, used to create lists of patterns
# + move patterns for bbcrack and bbharvest here
# + improve regex list with http://regexlib.com
# - extract list of common strings found in EXE files
# + add headers from other filetypes (Office, JPEG, archives, RTF, ZIP, ...)
# + add regex for IPv6 address
# - OLE header: add beta signature
# - IP address: black list of uninteresting IPs (false positives), such as
#   0.0.0.0, 1.1.1.1, etc
# - patterns to find known crypto algorithm constants: convert FindCrypt to
#   python strings - http://www.hexblog.com/?p=28
# - check also signsrch and clamsrch, especially this script to parse signsrch
#   signature file: http://code.google.com/p/clamsrch/source/browse/clamifier.py


#=== PATTERNS =================================================================

# Patterns for balbuzard:
patterns = [
    # NOTE: '(?i)' makes a regex case-insensitive
##    Pattern_re("IP addresses", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", weight=10),
    Pattern_re("IPv4 address", r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])", weight=100),
    Pattern_re('URL (http/https/ftp)', r'(http|https|ftp)\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~])*[^\.\,\)\(\s]', weight=10),
##    Pattern_re('e-mail address', r'([a-zA-Z0-9]+([\.+_-][a-zA-Z0-9]+)*)@(([a-zA-Z0-9]+((\.|[-]{1,2})[a-zA-Z0-9]+)*)\.[a-zA-Z]{2,6})', weight=10), # source: http://regexlib.com/REDetails.aspx?regexp_id=2119
    Pattern_re('e-mail address', r'(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2}|com|org|net|edu|gov|mil|int|biz|info|mobi|name|aero|asia|jobs|museum)\b', weight=10), # adapted from http://www.regular-expressions.info/email.html
    Pattern_re('domain name', r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)', weight=10), # source: http://regexlib.com/REDetails.aspx?regexp_id=1319

    Pattern("EXE MZ headers", "MZ|ZM".split('|')),
    Pattern("EXE PE headers", "PE"),
    Pattern_re("EXE MZ followed by PE", r"(?s)MZ.{32,1024}PE\000\000", weight=100), # (?s) sets the DOTALL flag, so that dot matches any character
    Pattern("EXE PE DOS message", "This program cannot be run in DOS mode", nocase=True, weight=10000),
    Pattern_re("Executable filename", r"\w+\.(EXE|COM|VBS|JS|VBE|JSE|BAT|CMD|DLL|SCR)", nocase=True, weight=10),
    Pattern("EXE: UPX header", "UPX"),
    Pattern("EXE: section name", ".text|.data|.rdata|.rsrc".split('|'), nocase=True, weight=10), #nocase?
    Pattern("EXE: packed with Petite", ".petite", nocase=True, weight=10), #nocase?
    Pattern("EXE: interesting Win32 function names", "WriteFile|IsDebuggerPresent|RegSetValue|CreateRemoteThread".split('|'), weight=10000),  #nocase?
    Pattern("EXE: interesting WinSock function names", "WS2_32.dll|WSASocket|WSASend|WSARecv".split('|'), nocase=True, weight=10000), #nocase?
    Pattern("EXE: possibly compiled with Microsoft Visual C++", "Microsoft Visual C++", weight=10000),

    Pattern("Interesting registry keys", "CurrentVersion\\Run|UserInit".split('|'), weight=10000), #nocase?
    Pattern("Interesting file names", "\\drivers\\etc\\hosts|cmd\.exe|\\Start Menu\\Programs\\Startup".split('|'), nocase=True, weight=10000),
    Pattern("Interesting keywords", "password|login|pwd|administrator|admin|root|smtp|pop|ftp|ssh|icq|backdoor|vmware".split('|'), nocase=True, weight=100), # removed http
    #Pattern_re("NOP instructions (possible shellcode)", r"\x90{4,}"), # this regex matches 4 NOPs or more

    Pattern("Possible OLE2 header (D0CF)", "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", weight=10),
    #ref: http://msdn.microsoft.com/en-us/library/dd941946.aspx
    Pattern("Possible VBA macros", "VBA"), #nocase?

    Pattern('Possible Flash header', 'SWF|FWS'.split('|')),
    Pattern('Flash OLE object 1', 'ShockwaveFlash.ShockwaveFlash', weight=10),
    Pattern('Flash OLE object 2', 'S\x00h\x00o\x00c\x00k\x00w\x00a\x00v\x00e\x00F\x00l\x00a\x00s\x00h', weight=10), # warning: this is unicode

    Pattern('Possible PDF header', '%PDF-', weight=10),
    Pattern('Possible PDF end of file marker', '%EOF', weight=10),

    Pattern_re('Hex blob', r'([A-F0-9][A-F0-9]|[a-f0-9][a-f0-9]){16,}', weight=1),
    Pattern_re('Base64 blob', r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', weight=1),
    ]

