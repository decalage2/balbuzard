"""
balbuzard - v0.15 2013-12-09 Philippe Lagadec

Balbuzard is a tool to quickly extract patterns from suspicious files for
malware analysis (IP addresses, domain names, known file headers and strings,
etc).

For more info and updates: http://www.decalage.info/balbuzard

usage: balbuzard [options] <file> [file2 ... fileN]


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

__version__ = '0.15'

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
# 2013-12-03 v0.13 PL: - moved patterns to separate file patterns.py
#                      - fixed issue when balbuzard launched from another dir
#                      - added CSV output
# 2013-12-04 v0.14 PL: - can now scan several files from command line args
#                      - now short display is default, -v for hex view
# 2013-12-09 v0.15 PL: - Pattern_re: added filter function to ignore false
#                        positives


#------------------------------------------------------------------------------
# TODO:
# + add yara plugins support to Balbuzard.count and scan_profiling
# + merge Balbuzard.scan_hexdump and short
# + batch mode to scan several files when using wildcards
# + option to choose which plugins to load: all (default), none, python or yara
#   only
# + option to use the Yara-python engine for searching (translating balbuzard
#   patterns to yara at runtime)
# - Yara plugins: keep track of the filename containing each set of Yara rules
# - option to support Unicode strings? (need to check 2 alignments and 2 byte
#   orders, or simply insert \x00 between all chars, e.g. 'T\x00E\x00S\x00T')
# + improve patterns to avoid some false positives: maybe use pefile or magic.py ?
# - HTML report with color highlighting
# - GUI ?
# - optional use of other magic libs (TrIDscan, pymagic, python-magic, etc: see PyPI)
# - provide samples
# - RTF hex object decoder?
# - option to decode stream before searching: unicode, hex, base64, etc
# - options for XML outputs
# - export to OpenIOC?
# ? zip file: open all files instead of only the 1st one, or add an option to
#   specify the filename(s) to open within the zip, with wildcards?


# ISSUES:
# - BUG: it seems that re ignores null bytes in patterns, despite what the doc says?
# - BUG: the URL pattern is not fully correct, need to find a better one
# - BUG: the e-mail pattern catches a lot of false positives.


#--- IMPORTS ------------------------------------------------------------------

import sys, re, os, os.path, optparse, glob, zipfile, time, string, fnmatch, imp
import csv

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
        - filt: function to filter out false positives, should be a function
          with arguments (value, index, pattern), returning True when acceptable
          or False when it is a false positive.
    """

    def __init__(self, name, pat=None, trigger=None, nocase=False, single=False,
        weight=1, filt=None):
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
        self.filter = filt
        print 'pattern %s: filter=%s' % (self.name, self.filter)


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
            valid = True
            if self.filter is not None:
                valid = self.filter(value=m.group(), index=m.start(), pattern=self)
            if valid: found.append((m.start(), m.group()))
            # debug message:
            else: print 'Filtered out %s: %s' % (self.name, repr(m.group()))
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
        # when no filter is defined, quickest way to count:
        if self.filter is None:
            return len(self.pat.findall(data))
        # otherwise, need to call filter for each match:
        c = 0
        for m in self.pat.finditer(data):
            valid = self.filter(value=m.group(), index=m.start(), pattern=self)
            if valid: c += 1
        return c


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

    def scan_display (self, data, filename, hexdump=False, csv_writer=None):
        """
        Scans data for all patterns, displaying an hexadecimal dump for each
        match on the console (if hexdump=True), or one line for each
        match (if hexdump=False).
        """
        for pattern, matches in self.scan(data):
            if hexdump:
                print "-"*79
                print "%s:" % pattern.name
            for index, match in matches:
                # limit matched string display to 50 chars:
                m = repr(match)
                if len(m)> 50:
                    m = m[:24]+'...'+m[-23:]
                if hexdump:
                    print "at %08X: %s" % (index, m)
                    # 5 lines of hexadecimal dump around the pattern: 2 lines = 32 bytes
                    start = max(index-32, 0) & 0xFFFFFFF0
                    index_end = index + len(match)
                    end = min(index_end+32+15, len(data)) & 0xFFFFFFF0
                    length = end-start
                    #print start, end, length
                    print hexdump3(data[start:end], length=16, startindex=start)
                    print ""
                else:
                    print "at %08X: %s - %s" % (index, pattern.name, m)
                if csv_writer is not None:
                    #['Filename', 'Index', 'Pattern name', 'Found string', 'Length']
                    csv_writer.writerow([filename, '0x%08X' % index, pattern.name,
                        m, len(match)])
        # blank line between each file:
        print ''

    ##            if item == "EXE MZ headers" and MAGIC:
    ##                # Check if it's really a EXE header
    ##                print "Magic: %s\n" % magic.whatis(data[m.start():])



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


def main_is_frozen():
    """
    To determine whether the script is launched from the interpreter or if it
    is an executable compiled with py2exe.
    See http://www.py2exe.org/index.cgi/HowToDetermineIfRunningFromExe
    """
    return (hasattr(sys, "frozen") # new py2exe
        or hasattr(sys, "importers") # old py2exe
        or imp.is_frozen("__main__")) # tools/freeze


def get_main_dir():
    """
    To determine the directory where the main script is located.
    Works if it is launched from the interpreter or if it is an executable
    compiled with py2exe.
    See http://www.py2exe.org/index.cgi/HowToDetermineIfRunningFromExe
    """
    if main_is_frozen():
        # script compiled with py2exe:
        return os.path.dirname(os.path.abspath(sys.executable))
    else:
        # else the script is sys.argv[0]
        return os.path.dirname(os.path.abspath(sys.argv[0]))




#=== MAIN =====================================================================

# get main directory where this script is located:
main_dir = get_main_dir()
# with python 2.6+, make it a relative path:
try:
    main_dir = os.path.relpath(main_dir)
except:
    pass

# load patterns
patfile = os.path.join(main_dir, 'patterns.py')
execfile(patfile)



#=== MAIN =====================================================================

if __name__ == '__main__':

    usage = 'usage: %prog [options] <filename> [filename2 ...]'
    parser = optparse.OptionParser(usage=usage)
##    parser.add_option('-o', '--outfile', dest='outfile',
##        help='output file')
    parser.add_option('-c', '--csv', dest='csv',
        help='export results to a CSV file')
    parser.add_option("-v", action="store_true", dest="verbose",
        help='verbose display, with hex view.')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
        help='if the file is a zip archive, open first file from it, using the provided password (requires Python 2.6+)')

    (options, args) = parser.parse_args()

    # Print help if no argurments are passed
    if len(args) == 0:
        print __doc__
        parser.print_help()
        sys.exit()

    # load plugins
    plugins_dir = os.path.join(main_dir, 'plugins')
    for f in rglob(plugins_dir, 'bbz*.py'): # glob.iglob('plugins/bbz*.py'):
        print 'Loading plugin from', f
        execfile(f)

    # load yara plugins
    if YARA:
        yara_rules = []
        for f in rglob(plugins_dir, '*.yara'):  #glob.iglob('plugins/*.yara'):  # or bbz*.yara?
            print 'Loading yara plugin from', f
            yara_rules.append(yara.compile(f))

    # open CSV file
    if options.csv:
        print 'Writing output to CSV file: %s' % options.csv
        csvfile = open(options.csv, 'wb')
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Filename', 'Index', 'Pattern name',
            'Found string', 'Length'])
    else:
        csv_writer = None


    # scan each file provided as argument:
    for arg in args:
        for fname in glob.iglob(arg):
            print "="*79
            print "File: %s\n" % fname
            if options.zip_password is not None:
                # extract 1st file from zip archive, using password
                pwd = options.zip_password
                print 'Opening zip archive %s with password "%s"' % (fname, pwd)
                z = zipfile.ZipFile(fname, 'r')
                fname = z.infolist()[0].filename
                print 'Opening first file in zip archive:', fname
                data = z.read(z.infolist()[0], pwd)
            else:
                # normal file
                print 'Opening file', fname
                data = open(fname, 'rb').read()

            if MAGIC:
                print "Filetype according to magic: %s\n" % magic.whatis(data)

            bbz = Balbuzard(patterns, yara_rules=yara_rules)
            bbz.scan_display(data, fname, hexdump=options.verbose, csv_writer=csv_writer)

    # close CSV file
    if options.csv:
        csvfile.close()


# This was coded while listening to The National "Boxer".