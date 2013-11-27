"""
balbuzard - v0.12 2013-08-28 Philippe Lagadec

Balbuzard is a tool to quickly extract patterns from suspicious files for
malware analysis (IP addresses, domain names, known file headers and strings,
etc).

For more info and updates: http://www.decalage.info/balbuzard

usage: balbuzard <file>


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

__version__ = '0.12'

#------------------------------------------------------------------------------
# CHANGELOG:
# 2007-07-11 v0.01 PL: - 1st version
# 2007-07-30 v0.02 PL: - added list of patterns
# 2007-07-31 v0.03 PL: - added patterns
#                        - added hexadecimal dump
# 2007-08-09 v0.04 PL: - improved some regexs, added Petite detection
# 2008-06-06 v0.05 PL: - escape non-printable characters with '\xNN' when
#                          displaying matches
#                      - optional custom pattern list in reScan_custom.py
#                      - optional call to magic.py to guess filetype
# 2011-05-06 v0.06 PL: - added bruteforce functions
# 2013-02-24 v0.07 PL: - renamed rescan to balbuzard
#                      - changed license from CeCILL v2 to BSD
#                      - added patterns for URL, e-mail, Flash
#                      - new Pattern class to add patterns
#                      - pattern can now be a regex or a string, with weigth
#                      - moved bruteforce functions to balbucrack
# 2013-03-18 v0.08 PL: - a few more/improved patterns
#                      - optionparser with option -s for short display
# 2013-03-21 v0.09 PL: - open file from password-protected zip (inspired from
#                        Didier Steven's pdfid, thanks Didier! :-)
#                      - improved plugin system
# 2013-03-26 v0.10 PL: - improved Pattern and Pattern_re classes
# 2013-07-31 v0.11 PL: - added support for Yara plugins
# 2013-08-28 v0.12 PL: - plugins can now be in subfolders
#                      - improved OLE2 pattern


#------------------------------------------------------------------------------
# TODO:
# + option to use the Yara-python engine for searching (translating balbuzard
#   patterns to yara at runtime)
# - option to support Unicode strings? (need to check 2 alignments and 2 byte
#   orders, or simply insert \x00 between all chars)
# + improve patterns to avoid some false positives: maybe use pefile or magic.py ?
# - pattern: validation function to be called to verify matches (may be a regex
#   or any python function returning a bool)
# + improve regex list with http://regexlib.com
# - extract list of common strings found in EXE files
# + add headers from other filetypes (Office, JPEG, archives, RTF, ZIP, ...)
# - HTML report with color highlighting
# - GUI ?
# - optional use of other magic libs (TrIDscan, pymagic, python-magic, etc: see PyPI)
# - provide samples
# - RTF hex object decoder?
# - option to decode stream before searching: unicode, hex, base64, etc
# - option for short display: one line per pattern found, with index, pattern
#   name and matched value
# - options for CSV and XML outputs
# - export to OpenIOC?
# - IP address: black list of uninteresting IPs (false positives), such as
#   0.0.0.0, 1.1.1.1, etc
# - patterns to find known crypto algorithm constants: convert FindCrypt to
#   python strings - http://www.hexblog.com/?p=28
# - check also signsrch and clamsrch, especially this script to parse signsrch
#   signature file: http://code.google.com/p/clamsrch/source/browse/clamifier.py


# ISSUES:
# - BUG: it seems that re ignores null bytes in patterns, despite what the doc says?
# - BUG: the URL pattern is not fully correct, need to find a better one
# - BUG: the e-mail pattern catches a lot of false positives.


#--- IMPORTS ------------------------------------------------------------------

import sys, re, os, os.path, optparse, glob, zipfile, time, string, fnmatch

# try to import magic.py - see http://www.jsnp.net/code/magic.py or PyPI/magic
try:
    from thirdparty.magic import magic
    MAGIC = True
except:
    MAGIC = False

# try to import yara-python:
try:
    import yara
    YARA = True
except:
    YARA = False


#--- CLASSES ------------------------------------------------------------------

class Pattern (object):
    """
    a Pattern object is a string or a list of strings to be searched in data.
    Attributes:
        - name: str, description of the pattern for display
        - pat: str or list/tuple of strings to be searched
        - nocase: bool, if True, search is case-insensitive
        - single: bool, if True search will stop at the first occurence
        - weight: int, weight used by balbucrack
    """

    def __init__(self, name, pat=None, nocase=False, single=False, weight=1):
        self.name = name
        # self.pat should always be a list of strings:
        if isinstance(pat, str):
            self.pat = [pat]
        else:
            # else we assume it's a sequence:
            self.pat = pat
        self.nocase = nocase
        if nocase:
            # transform pat to lowercase
            self.pat_lower = map(string.lower, self.pat)
        self.single = single
        self.weight = weight
        # for profiling:
        self.total_time = 0


    def find_all (self, data, data_lower=None):
        """
        find all occurences of pattern in data.
        data_lower should be set to data.lower(), if there are case-insensitive
        patterns (it's better to do it only once)
        return a list of tuples (index, string)
        """
        found = []
        if self.nocase:
            d = data_lower
            pat = self.pat_lower
        else:
            d = data
            pat = self.pat
        for s in pat:
            l = len(s)
            for i in str_find_all(d, s):
                found.append((i, data[i:i+len(s)]))
        return found


    def count (self, data, data_lower=None):
        """
        count all occurences of pattern in data.
        Except for those with single=True, only the first occurence of any
        string is counted.
        data_lower should be set to data.lower(), if there are case-insensitive
        patterns (it's better to do it only once)
        return an integer
        """
        count = 0
        if self.nocase:
            d = data_lower
            pat = self.pat_lower
        else:
            d = data
            pat = self.pat
        if not self.single:
            for s in pat:
                count += d.count(s)
            return count
        else:
            for s in pat:
                if s in d:
                    return 1
            return 0



class Pattern_re (Pattern):
    """
    a Pattern_re object is a regular expression to be searched in data.
    Attributes:
        - name: str, description of the pattern for display
        - pat: str, regular expression to be searched
        - trigger: str or list/tuple of strings to be searched before pat
        - nocase: bool, if True, search is case-insensitive
        - single: bool, if True search will stop at the first occurence
        - weight: int, weight used by balbucrack
    """

    def __init__(self, name, pat=None, trigger=None, nocase=False, single=False,
        weight=1):
        # first call the Pattern constructor:
        Pattern.__init__(self, name, pat, nocase, single, weight)
        # compile regex
        flags = 0
        if nocase:
            flags = re.IGNORECASE
        self.pat = re.compile(pat, flags)
        self.trigger = trigger
        if trigger is not None:
            # create second pattern for trigger, for single search:
            self.trigger_pat = Pattern(name, pat=trigger, nocase=nocase, single=True)


    def find_all (self, data, data_lower=None):
        """
        find all occurences of pattern in data.
        data_lower should be set to data.lower(), if there are case-insensitive
        patterns (it's better to do it only once)
        return a list of tuples (index, string)
        """
        found = []
        if self.trigger is not None:
            # when trigger is specified, search trigger first and stop if not
            # found:
            if self.trigger_pat.count(data, data_lower) == 0:
                return found
        for m in self.pat.finditer(data):
            found.append((m.start(), m.group()))
        return found


    def count (self, data, data_lower=None):
        """
        count all occurences of pattern in data.
        data_lower should be set to data.lower(), if there are case-insensitive
        patterns (it's better to do it only once)
        return an integer
        """
        if self.trigger is not None:
            # when trigger is specified, search trigger first and stop if not
            # found:
            if self.trigger_pat.count(data, data_lower) == 0:
                return 0
        return len(self.pat.findall(data))


#------------------------------------------------------------------------------
class Balbuzard (object):
    """
    class to scan a string of data, searching for a set of patterns (strings
    and regular expressions)
    """

    def __init__(self, patterns=None, yara_rules=None):
        self.patterns = patterns
        if patterns == None:
            self.patterns = []
        self.yara_rules = yara_rules

##    def add_pattern(self, name, regex=None, string=None, weight=1):
##        self.patterns.append(Pattern(name, regex, string, weight))

    def scan (self, data):
        """
        Scans data for all patterns. This is an iterator: for each pattern
        found, yields the Pattern object and a list of matches as tuples
        (index in data, matched string).
        """
        # prep lowercase version of data for case-insensitive patterns
        data_lower = data.lower()
        for pattern in self.patterns:
            matches = pattern.find_all(data, data_lower)
            if len(matches)>0:
                yield pattern, matches
        if YARA and self.yara_rules is not None:
            for rules in self.yara_rules:
                yara_matches = rules.match(data=data)
                for match in yara_matches:
                    # create a fake pattern object, with a single match:
                    pattern = Pattern(match.rule)
                    matches = []
                    for s in match.strings:
                        offset, id, d = s
                        matches.append((offset, d))
                    yield pattern, matches

    def scan_profiling (self, data):
        """
        Scans data for all patterns. This is an iterator: for each pattern
        found, yields the Pattern object and a list of matches as tuples
        (index in data, matched string).
        Version with profiling, to check which patterns take time.
        """
        start = time.clock()
        # prep lowercase version of data for case-insensitive patterns
        data_lower = data.lower()
        for pattern in self.patterns:
            start_pattern = time.clock()
            matches = pattern.find_all(data, data_lower)
            pattern.time = time.clock()-start_pattern
            pattern.total_time += pattern.time
            if len(matches)>0:
                yield pattern, matches
        self.time = time.clock()-start

    def count (self, data):
        """
        Scans data for all patterns. This is an iterator: for each pattern
        found, yields the Pattern object and the count as int.
        """
        # prep lowercase version of data for case-insensitive patterns
        data_lower = data.lower()
        for pattern in self.patterns:
            count = pattern.count(data, data_lower)
            if count:
                yield pattern, count

    def scan_hexdump (self, data):
        """
        Scans data for all patterns, displaying an hexadecimal dump for each
        match on the console.
        """
        for pattern, matches in self.scan(data):
            print "-"*79
            print "%s:" % pattern.name
            for index, match in matches:
                print "at %08X: %s" % (index, repr(match))
                # 5 lines of hexadecimal dump around the pattern: 2 lines = 32 bytes
                start = max(index-32, 0) & 0xFFFFFFF0
                index_end = index + len(match)
                end = min(index_end+32+15, len(data)) & 0xFFFFFFF0
                length = end-start
                #print start, end, length
                print hexdump3(data[start:end], length=16, startindex=start)
                print ""
    ##            if item == "EXE MZ headers" and MAGIC:
    ##                # Check if it's really a EXE header
    ##                print "Magic: %s\n" % magic.whatis(data[m.start():])

    def scan_short (self, data):
        """
        Scans data for all patterns, displaying one line for each
        match on the console.
        """
        for pattern, matches in self.scan(data):
            for index, match in matches:
                # limit matched string display to 50 chars:
                m = repr(match)
                if len(m)> 50:
                    m = m[:24]+'...'+m[-23:]
                print "at %08X: %s - %s" % (index, pattern.name, m)



#--- GLOBALS ------------------------------------------------------------------

patterns = []


#--- FUNCTIONS ----------------------------------------------------------------

##def add_pattern(name, regex=None, string=None, weight=1):
##    patterns.append(Pattern(name, regex, string, weight))


# HEXDUMP from http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

##def hexdump(src, length=8):
##    N=0; result=''
##    while src:
##       s,src = src[:length],src[length:]
##       hexa = ' '.join(["%02X"%ord(x) for x in s])
##       s = s.translate(FILTER)
##       result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
##       N+=length
##    return result
##
##def hexdump2(src, length=8):
##    result=[]
##    for i in xrange(0, len(src), length):
##       s = src[i:i+length]
##       hexa = ' '.join(["%02X"%ord(x) for x in s])
##       printable = s.translate(FILTER)
##       result.append("%04X   %-*s   %s\n" % (i, length*3, hexa, printable))
##    return ''.join(result)

# my improved hexdump, to add a start index:
def hexdump3(src, length=8, startindex=0):
    """
    Returns a hexadecimal dump of a binary string.
    length: number of bytes per row.
    startindex: index of 1st byte.
    """
    result=[]
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
       printable = s.translate(FILTER)
       result.append("%04X   %-*s   %s\n" % (i+startindex, length*3, hexa, printable))
    return ''.join(result)


def str_find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub)


# recursive glob function to find plugin files in any subfolder:
# inspired by http://stackoverflow.com/questions/14798220/how-can-i-search-sub-folders-using-glob-glob-module-in-python
def rglob (path, pattern='*.*'):
    """
    similar to glob.glob, but finds files recursively in all subfolders of path.
    path: root directory where to search files
    pattern: pattern for filenames, using wildcards, e.g. *.txt
    """
    # more compatible API with glob: use single param, split path from pattern
    return [os.path.join(dirpath, f)
        for dirpath, dirnames, files in os.walk(path)
        for f in fnmatch.filter(files, pattern)]


#=== MAIN =====================================================================

# list of regular expressions for patterns
patterns = [
    # NOTE: '(?i)' makes a regex case-insensitive
##    Pattern_re("IP addresses", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", weight=10),
    Pattern_re("IP address", r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])", weight=100),
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


#=== MAIN =====================================================================

if __name__ == '__main__':

    usage = 'usage: %prog [options] <filename>'
    parser = optparse.OptionParser(usage=usage)
##    parser.add_option('-o', '--outfile', dest='outfile',
##        help='output file')
##    parser.add_option('-c', '--csv', dest='csv',
##        help='export results to CSV file')
    parser.add_option("-s", action="store_true", dest="short",
        help='short display, without hex view.')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
        help='if the file is a zip archive, open first file from it, using the provided password (requires Python 2.6+)')

    (options, args) = parser.parse_args()

    # Print help if no argurments are passed
    if len(args) == 0:
        print __doc__
        parser.print_help()
        sys.exit()

    # load plugins
    for f in rglob('plugins', 'bbz*.py'): # glob.iglob('plugins/bbz*.py'):
        print 'Loading plugin from', f
        execfile(f)

    # load yara plugins
    if YARA:
        yara_rules = []
        for f in rglob('plugins', '*.yara'):  #glob.iglob('plugins/*.yara'):  # or bbz*.yara?
            print 'Loading yara plugin from', f
            yara_rules.append(yara.compile(f))


    fname = args[0]
    if options.zip_password is not None:
        # extract 1st file from zip archive, using password
        pwd = options.zip_password
        print 'Opening zip archive %s with password "%s"' % (fname, pwd)
        z = zipfile.ZipFile(fname, 'r')
        print 'Opening first file:', z.infolist()[0].filename
        data = z.read(z.infolist()[0], pwd)
    else:
        # normal file
        print 'Opening file', fname
        data = open(fname, 'rb').read()

    if MAGIC:
        print "Filetype according to magic: %s\n" % magic.whatis(data)

    bbz = Balbuzard(patterns, yara_rules=yara_rules)
    if options.short:
        bbz.scan_short(data)
    else:
        bbz.scan_hexdump(data)

# This was coded while listening to The National "Boxer".