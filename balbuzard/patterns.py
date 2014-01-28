"""
balbuzard patterns - v0.06 2014-01-28 Philippe Lagadec

This file contains pattern definitions for the Balbuzard tools.

Balbuzard is a package of open-source python tools for malware analysis:
balbuzard is a tool to extract patterns of interest from malicious files, such
as IP addresses, URLs and common file headers. It is easily extensible with
patterns, regular expressions and Yara rules.
bbcrack uses a new algorithm based on patterns of interest to bruteforce typical
malware obfuscation such as XOR, ROL, ADD and various combinations.

For more info and updates: http://www.decalage.info/balbuzard


balbuzard is copyright (c) 2007-2014, Philippe Lagadec (http://www.decalage.info)
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

__version__ = '0.06'

#------------------------------------------------------------------------------
# CHANGELOG:
# 2013-12-03 v0.01 PL: - 1st version, moved patterns from balbuzard
# 2013-12-04 v0.02 PL: - declare each pattern as a variable, used to create
#                        lists of patterns
# 2013-12-09 v0.03 PL: - added filter function for IPv4 addresses
#                      - moved bbharvest patterns here
# 2014-01-04 v0.04 PL: - added Java filenames to pat_exe_fnames
# 2014-01-23 v0.05 PL: - grouped patterns by topic
#                      - moved and merged patterns from bbcrack
# 2014-01-28 v0.06 PL: - improved word pattern for bbcrack

#------------------------------------------------------------------------------
# TODO:
# + move patterns for bbcrack here
# + improve regex list with http://regexlib.com
# - extract list of common strings found in EXE files
# + add headers from other filetypes (Office, JPEG, archives, RTF, ZIP, ...)
# + add regex for IPv6 address
# - OLE header: add beta signature
# - patterns to find known crypto algorithm constants: convert FindCrypt to
#   python strings - http://www.hexblog.com/?p=28
# - check also signsrch and clamsrch, especially this script to parse signsrch
#   signature file: http://code.google.com/p/clamsrch/source/browse/clamifier.py
# + filter out e-mail addresses if too short
# + add more patterns with typical strings found in executables
# - for some patterns such as e-mail, would be good to have a validation function
#   on top of regex to filter out false positives. for example using tldextract
#   or list of TLDs: http://data.iana.org/TLD/tlds-alpha-by-domain.txt.
# - ipv4_filter: check that all bytes are <=255 (only useful with simple regex)


#=== FILTERS ==================================================================

def ipv4_filter (value, index=0, pattern=None):
    """
    IPv4 address filter:
    - check if string length is >7 (e.g. not just 4 digits and 3 dots)
    - check if not in list of bogon IP addresses
    return True if OK, False otherwise.
    """
    ip = value
    # check if string length is >7 (e.g. not just 4 digits and 3 dots)
    if len(ip) < 8:
        return False

    # BOGON IP ADDRESS RANGES:
    # source: http://www.team-cymru.org/Services/Bogons/bogon-dd.html

    # extract 1st and 2nd decimal number from IP as int:
    ip_bytes = ip.split('.')
    byte1 = int(ip_bytes[0])
    byte2 = int(ip_bytes[1])
    #print 'ip=%s byte1=%d byte2=%d' % (ip, byte1, byte2)

    # 0.0.0.0 255.0.0.0
    if ip.startswith('0.'): return False

    # actually we might want to see the following bogon IPs if malware uses them
    # => this should be an option
    # 10.0.0.0 255.0.0.0
    if ip.startswith('10.'): return False
    # 100.64.0.0 255.192.0.0
    if ip.startswith('100.') and (byte2&192 == 64): return False
    # 127.0.0.0 255.0.0.0
    if ip.startswith('127.'): return False
    # 169.254.0.0 255.255.0.0
    if ip.startswith('169.254.'): return False
    # 172.16.0.0 255.240.0.0
    if ip.startswith('172.') and (byte2&240 == 16): return False
    # 192.0.0.0 255.255.255.0
    if ip.startswith('192.0.0.'): return False
    # 192.0.2.0 255.255.255.0
    if ip.startswith('192.0.2.'): return False
    # 192.168.0.0 255.255.0.0
    if ip.startswith('192.168.'): return False
    # 198.18.0.0 255.254.0.0
    if ip.startswith('198.') and (byte2&254 == 18): return False
    # 198.51.100.0 255.255.255.0
    if ip.startswith('198.51.100.'): return False
    # 203.0.113.0 255.255.255.0
    if ip.startswith('203.0.113.'): return False
    # 224.0.0.0 240.0.0.0
    if byte1&240 == 224: return False
    # 240.0.0.0 240.0.0.0
    if byte1&240 == 240: return False

    # also reject IPs ending with .0 or .255
    if ip.endswith('.0') or ip.endswith('.255'): return False
    # otherwise it's a valid IP adress
    return True

# TLDs registered at IANA:
# from http://data.iana.org/TLD/tlds-alpha-by-domain.txt retrieved on 2013-12-09
# (max len = 22 chars)
tlds = set((
     'ac',  'ad',  'ae',  'aero',  'af',  'ag',  'ai',  'al',
     'am',  'an',  'ao',  'aq',  'ar',  'arpa',  'as',  'asia',
     'at',  'au',  'aw',  'ax',  'az',  'ba',  'bb',  'bd',
     'be',  'bf',  'bg',  'bh',  'bi',  'bike',  'biz',  'bj',
     'bm',  'bn',  'bo',  'br',  'bs',  'bt',  'bv',  'bw',
     'by',  'bz',  'ca',  'camera',  'cat',  'cc',  'cd',  'cf',
     'cg',  'ch',  'ci',  'ck',  'cl',  'clothing',  'cm',  'cn',
     'co',  'com',  'construction',  'contractors',  'coop',  'cr',  'cu',  'cv',
     'cw',  'cx',  'cy',  'cz',  'de',  'diamonds',  'directory',  'dj',
     'dk',  'dm',  'do',  'dz',  'ec',  'edu',  'ee',  'eg',
     'enterprises',  'equipment',  'er',  'es',  'estate',  'et',  'eu',  'fi',
     'fj',  'fk',  'fm',  'fo',  'fr',  'ga',  'gallery',  'gb',
     'gd',  'ge',  'gf',  'gg',  'gh',  'gi',  'gl',  'gm',
     'gn',  'gov',  'gp',  'gq',  'gr',  'graphics',  'gs',  'gt',
     'gu',  'guru',  'gw',  'gy',  'hk',  'hm',  'hn',  'holdings',
     'hr',  'ht',  'hu',  'id',  'ie',  'il',  'im',  'in',
     'info',  'int',  'io',  'iq',  'ir',  'is',  'it',  'je',
     'jm',  'jo',  'jobs',  'jp',  'ke',  'kg',  'kh',  'ki',
     'kitchen',  'km',  'kn',  'kp',  'kr',  'kw',  'ky',  'kz',
     'la',  'land',  'lb',  'lc',  'li',  'lighting',  'lk',  'lr',
     'ls',  'lt',  'lu',  'lv',  'ly',  'ma',  'mc',  'md',
     'me',  'menu',  'mg',  'mh',  'mil',  'mk',  'ml',  'mm',
     'mn',  'mo',  'mobi',  'mp',  'mq',  'mr',  'ms',  'mt',
     'mu',  'museum',  'mv',  'mw',  'mx',  'my',  'mz',  'na',
     'name',  'nc',  'ne',  'net',  'nf',  'ng',  'ni',  'nl',
     'no',  'np',  'nr',  'nu',  'nz',  'om',  'org',  'pa',
     'pe',  'pf',  'pg',  'ph',  'photography',  'pk',  'pl',  'plumbing',
     'pm',  'pn',  'post',  'pr',  'pro',  'ps',  'pt',  'pw',
     'py',  'qa',  're',  'ro',  'rs',  'ru',  'rw',  'sa',
     'sb',  'sc',  'sd',  'se',  'sexy',  'sg',  'sh',  'si',
     'singles',  'sj',  'sk',  'sl',  'sm',  'sn',  'so',  'sr',
     'st',  'su',  'sv',  'sx',  'sy',  'sz',  'tattoo',  'tc',
     'td',  'technology',  'tel',  'tf',  'tg',  'th',  'tips',  'tj',
     'tk',  'tl',  'tm',  'tn',  'to',  'today',  'tp',  'tr',
     'travel',  'tt',  'tv',  'tw',  'tz',  'ua',  'ug',  'uk',
     'uno',  'us',  'uy',  'uz',  'va',  'vc',  've',  'ventures',
     'vg',  'vi',  'vn',  'voyage',  'vu',  'wf',  'ws',  'xn--3e0b707e',
     'xn--45brj9c',  'xn--80ao21a',  'xn--80asehdb',  'xn--80aswg',  'xn--90a3ac',
     'xn--clchc0ea0b2g2a9gcd',  'xn--fiqs8s',  'xn--fiqz9s',
     'xn--fpcrj9c3d',  'xn--fzc2c9e2c',  'xn--gecrj9c',  'xn--h2brj9c',
     'xn--j1amh',  'xn--j6w193g',  'xn--kprw13d',  'xn--kpry57d',
     'xn--l1acc',  'xn--lgbbat1ad8j',  'xn--mgb9awbf',  'xn--mgba3a4f16a',
     'xn--mgbaam7a8h',  'xn--mgbayh7gpa',  'xn--mgbbh1a71e',  'xn--mgbc0a9azcg',
     'xn--mgberp4a5d4ar',  'xn--mgbx4cd0ab',  'xn--ngbc5azd',  'xn--o3cw4h',
     'xn--ogbpf8fl',  'xn--p1ai',  'xn--pgbs0dh',  'xn--q9jyb4c',
     'xn--s9brj9c',  'xn--unup4y',  'xn--wgbh1c',  'xn--wgbl6a',
     'xn--xkc2al3hye2a',  'xn--xkc2dl3a5ee0h',  'xn--yfro4i67o',  'xn--ygbi2ammx',
     'xxx',  'ye',  'yt',  'za',  'zm',  'zw',
))


def email_filter (value, index=0, pattern=None):
    # check length, e.g. longer than xy@hp.fr
    # check case? e.g. either lower, upper, or capital (but CamelCase covers
    # almost everything... the only rejected case would be starting with lower
    # and containing upper?)
    # or reject mixed case in last part of domain name? (might filter 50% of
    # false positives)
    # optionally, DNS MX query with caching?

    user, domain = value.split('@', 1)
    if len(user)<2: return False
    if len(domain)<5: return False
    tld = domain.rsplit('.', 1)[1].lower()
    if tld not in tlds: return False

    return True


def str_filter (value, index=0, pattern=None):
    """
    String filter: avoid false positives with random case. A typical string
    should be either:
    - all UPPERCASE
    - all lowercase
    - or Capitalized
    return True if OK, False otherwise.
    Usage: This filter is meant to be used with string patterns that catch words
    with the option nocase=True, but where random case is not likely.
    Note 1: It is assumed the string only contains alphabetical characters (a-z)
    Note 2: this filter does not cover CamelCase strings.
    """
    # case 1: all UPPERCASE
    # case 2: all lowercase except 1st character which can be uppercase (Capitalized)
    if value.isupper() or value[1:].islower(): return True
    #Note: we could also use istitle() if strings are not only alphabetical.


#=== PATTERNS =================================================================

# NOTES:
# '(?i)' makes a regex case-insensitive
# \b matches a word boundary, it can help speeding up regex search and avoiding
# some false positives. See http://www.regular-expressions.info/wordboundaries.html

#------------------------------------------------------------------------------
# IP ADDRESSES
##    Pattern_re("IP addresses", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", weight=10),
# Here I use \b to make sure there is no other digit around and to speedup search
pat_ipv4 = Pattern_re("IPv4 address",
    r"\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b",
    weight=100, filt=ipv4_filter)

#------------------------------------------------------------------------------
# URLs
pat_url = Pattern_re('URL (http/https/ftp)', r'(http|https|ftp)\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~])*[^\.\,\)\(\s]', weight=10000)
# simpler version for bbcrack:
pat_url2 = Pattern_re('URL (http/https/ftp)', r'(http|https|ftp)\://[a-zA-Z0-9\-\.&%\$#\=~]+', weight=10000)
#NOTE: here the score can be high because false positives are less likely, since
#      it starts with a fixed string.

#------------------------------------------------------------------------------
# E-MAIL ADDRESSES
pat_email = Pattern_re('e-mail address',
    ##r'(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2}|com|org|net|edu|gov|mil|int|biz|info|mobi|name|aero|asia|jobs|museum)\b',
    # changed to catch all current TLDs registered at IANA (in combination with filter function):
    # TLD = either only chars from 2 to 12, or 'XN--' followed by up to 18 chars and digits
    r'(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2,12}|XN--[A-Z0-9]{4,18})\b',
    weight=10, filt=email_filter)
    # adapted from http://www.regular-expressions.info/email.html
##    Pattern_re('e-mail address', r'([a-zA-Z0-9]+([\.+_-][a-zA-Z0-9]+)*)@(([a-zA-Z0-9]+((\.|[-]{1,2})[a-zA-Z0-9]+)*)\.[a-zA-Z]{2,6})', weight=10), # source: http://regexlib.com/REDetails.aspx?regexp_id=2119

#------------------------------------------------------------------------------
# DOMAIN NAMES
pat_domain = Pattern_re('domain name', r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)', weight=10) # source: http://regexlib.com/REDetails.aspx?regexp_id=1319
#TODO: make it similar to e-mail address, with filter?

#------------------------------------------------------------------------------
# EXECUTABLE FILES
pat_mz = Pattern("EXE MZ headers", "MZ|ZM".split('|'))
pat_pe = Pattern("EXE PE headers", "PE")
pat_mzpe = Pattern_re("EXE MZ followed by PE", r"(?s)MZ.{32,1024}PE\000\000", weight=100) # (?s) sets the DOTALL flag, so that dot matches any character
pat_exemsg = Pattern("EXE PE DOS message", "This program cannot be run in DOS mode", nocase=True, weight=10000)
pat_section = Pattern("EXE: section name", ".text|.data|.rdata|.rsrc|.reloc".split('|'), nocase=True, weight=100) #nocase?

#------------------------------------------------------------------------------
# PACKERS
pat_upx = Pattern("EXE: UPX header", "UPX")
pat_petite = Pattern("EXE: packed with Petite", ".petite", nocase=True, weight=10) #nocase?

#------------------------------------------------------------------------------
# INDICATORS
pat_exe_fname = Pattern_re("Executable filename", r"\b\w+\.(EXE|COM|VBS|JS|VBE|JSE|BAT|CMD|DLL|SCR|CLASS|JAR)\b", nocase=True, weight=10)
pat_win32 = Pattern("EXE: interesting Win32 function names", "WriteFile|IsDebuggerPresent|RegSetValue|CreateRemoteThread".split('|'), weight=10000)  #nocase?
pat_winsock = Pattern("EXE: interesting WinSock function names", "WS2_32.dll|WSASocket|WSASend|WSARecv".split('|'), nocase=True, weight=10000) #nocase?
pat_msvcpp = Pattern("EXE: possibly compiled with Microsoft Visual C++", "Microsoft Visual C++", weight=10000)

pat_regkeys = Pattern("Interesting registry keys", "CurrentVersion\\Run|UserInit".split('|'), weight=10000) #nocase?
pat_filenames = Pattern("Interesting file names", "\\drivers\\etc\\hosts|cmd\.exe|\\Start Menu\\Programs\\Startup".split('|'), nocase=True, weight=10000)
pat_keywords = Pattern("Interesting keywords", "password|login|pwd|administrator|admin|root|smtp|pop|ftp|ssh|icq|backdoor|vmware".split('|'), nocase=True, weight=100) # removed http
    #Pattern_re("NOP instructions (possible shellcode)", r"\x90{4,}"), # this regex matches 4 NOPs or more

#------------------------------------------------------------------------------
# FILE PARTS
pat_ole2 = Pattern("Possible OLE2 header (e.g. MS Office documents)", "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", weight=10)
    #ref: http://msdn.microsoft.com/en-us/library/dd941946.aspx
pat_vba = Pattern("Possible VBA macros", "VBA") #nocase?

pat_flash = Pattern('Possible Flash header', 'SWF|FWS'.split('|'))
pat_flashobj1 = Pattern('Flash OLE object 1', 'ShockwaveFlash.ShockwaveFlash', weight=10)
pat_flashobj2 = Pattern('Flash OLE object 2', 'S\x00h\x00o\x00c\x00k\x00w\x00a\x00v\x00e\x00F\x00l\x00a\x00s\x00h', weight=10) # warning: this is unicode

pat_pdf_hdr = Pattern('Possible PDF header', '%PDF-', weight=10)
pat_pdf_eof = Pattern('Possible PDF end of file marker', '%EOF', weight=10)


#------------------------------------------------------------------------------
# ENCODED DATA
pat_hex = Pattern_re('Hex blob', r'([A-F0-9][A-F0-9]|[a-f0-9][a-f0-9]){16,}', weight=1)
pat_b64 = Pattern_re('Base64 blob', r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', weight=1)


#------------------------------------------------------------------------------
#Specific to bbcrack stage 1:
# see below

#------------------------------------------------------------------------------
#Specific to bbcrack stage 2:

# A word may either be UPPERCASE/lowercase/Capitalized, but not random case.
# So either all uppercase [A-Z]
# Or one any case [A-Za-z] followed by lowercase only [a-z]
# This is to avoid false positives.
pat_word6 = Pattern_re('Any word longer than 6 chars', r'\b(?:[A-Z]{6,}|[A-Za-z][a-z]{5,})\b')
# old simpler version:
#pat_word6 = Pattern_re('Any word longer than 6 chars', r'\b[A-Za-z]{6,}\b')

pat_sentence = Pattern_re('Sentence of 3 words or more', r'([A-Za-z]{2,}\s){2,}[A-Za-z]{2,}', weight=1) #TODO: this one seems incomplete
pat_camelcase_word = Pattern_re('CamelCase word', r'\b([A-Z][a-z0-9]{2,}){2,}\b', weight=1)


#=== PATTERN GROUPS ===========================================================

#------------------------------------------------------------------------------
# Patterns for balbuzard:

patterns = [
    pat_ipv4,
    pat_url,
    pat_email,
    pat_domain,
    pat_mz,
    pat_pe,
    pat_mzpe,
    pat_exemsg,
    pat_exe_fname,
    pat_upx,
    pat_section,
    pat_petite,
    pat_win32,
    pat_winsock,
    pat_msvcpp,
    pat_regkeys,
    pat_filenames,
    pat_keywords,
    pat_ole2,
    pat_vba,
    pat_flash,
    pat_flashobj1,
    pat_flashobj2,
    pat_pdf_hdr,
    pat_pdf_eof,
    pat_hex,
    pat_b64,
    ]


#------------------------------------------------------------------------------
# Patterns for bbcrack:

# Stage 1: simple patterns for initial, fast filtering of best candidates
# (only used for counting - avoid regex)
bbcrack_patterns_stage1 = [
    Pattern('spaces', ' '),
    Pattern('nulls', '\x00'),
    Pattern('newlines', '\x0D\x0A', weight=100),
    Pattern('spaces blob', ' '*8, weight=100),
    Pattern('nulls blob', '\x00'*8, weight=100),
    Pattern('http URL start', 'http://', weight=10000),
    Pattern('https URL start', 'https://', weight=10000),
    Pattern('ftp URL start', 'ftp://', weight=10000),
    Pattern('EXE PE section', ['.text', '.data', '.rdata', '.rsrc', '.reloc'], weight=10000),
    Pattern('Frequent strings in EXE', ['program', 'cannot', 'mode',
        'microsoft', 'kernel32', 'version', 'assembly', 'xmlns', 'schemas',
        'manifestVersion', 'security', 'win32'], nocase=True, filt=str_filter,
        weight=10000),
    Pattern('Common English words likely to be found in malware', ['this',
        'file', 'open', 'enter', 'password', 'service', 'process', 'type',
        'system', 'error'], nocase=True, filt=str_filter, weight=10000),
    Pattern('Common file extensions in malware', ['.exe', '.dll', '.pdf'],
        nocase=True, filt=str_filter, weight=10000),
    Pattern('Common TLDs in domain names', ['.com', '.org', '.net', '.edu',
        '.ru', '.cn', '.co.uk'], nocase=True, filt=str_filter, weight=10000),
    Pattern('Common hostnames in URLs', ['www.', 'smtp.', 'pop.'],
        nocase=True, filt=str_filter, weight=10000),
    Pattern('Frequent Win32 function names', ['GetCurrent', 'Thread'], weight=10000),
    #Pattern("EXE PE DOS message", "This program cannot be run in DOS mode", nocase=True, weight=100000),
    ]

#TODO:
# - other frequent Win32 function names
# - frequent unicode strings

# specific patterns for cracking (simpler than Balbuzard, for speed):
# Here it's better to be simple and fast than accurate
bbcrack_patterns = [
##    Pattern('Whitespaces and newline characters', regex=r'\s+'),
##    Pattern('Null characters', regex=r'\000+'),
    pat_word6,
    pat_sentence,
    pat_ipv4,
    pat_url2,
    pat_email,
    #pat_domain,
    pat_camelcase_word,
    pat_mzpe,
    pat_exemsg,
    pat_hex,
    pat_b64,
    pat_section,
    pat_ole2,
]


#------------------------------------------------------------------------------
# patterns for bbharvest:

# Similar to balbuzard, with a few differences
harvest_patterns = [
    pat_ipv4,
    pat_url,
    pat_email,
    pat_domain,
    # for harvest we don't catch MZ or PE alone, too many false positives
    pat_mzpe,
    pat_exemsg,
    pat_exe_fname,
    pat_upx,
    pat_section,
    pat_petite,
    pat_win32,
    pat_winsock,
    pat_msvcpp,
    pat_regkeys,
    pat_filenames,
    pat_keywords,
    pat_ole2,
    pat_vba,
    pat_flash,
    pat_flashobj1,
    pat_flashobj2,
    pat_pdf_hdr,
    pat_pdf_eof,
    # no detection of hex or Base64 blobs, too many false positives or too slow
]

