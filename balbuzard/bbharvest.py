"""
bbharvest - v0.01 2013-12-06 Philippe Lagadec

bbharvest is a tool to analyse malware that uses obfuscation such as XOR, ROL,
ADD (and many combinations) to hide information such as IP addresses, domain
names, URLs, strings, embedded files, etc. It is targeted at malware
using several obfuscation transforms and/or several keys in a single file.
It tries all possible keys of selected transforms and extracts all patterns of
interest using the balbuzard engines.
It is part of the Balbuzard package.

For more info and updates: http://www.decalage.info/balbuzard
"""

# LICENSE:
#
# balbucrack is copyright (c) 2013, Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


__version__ = '0.01'

#------------------------------------------------------------------------------
# CHANGELOG:
# 2013-12-06 v0.01 PL: - 1st version, moved code from bbcrack


#------------------------------------------------------------------------------
# TODO:
# + avoid duplicate code in main, using functions in bbcrack
# + plugin dir to load user transforms and patterns (using exec or import?)
# + harvest mode: option to save copy of every matching file
# - csv output for stage1+2 or harvest mode
# - for some patterns such as e-mail, would be good to have a validation function
#   on top of regex to filter out false positives. for example using tldextract
#   or list of TLDs: http://data.iana.org/TLD/tlds-alpha-by-domain.txt.


#--- IMPORTS ------------------------------------------------------------------

import sys, os, time, optparse, zipfile

from bbcrack import *


#--- PATTERNS -----------------------------------------------------------------

harvest_patterns = [
    Pattern_re("IP address", r"\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b", weight=100),
    Pattern_re('URL (http/https/ftp)', r'(http|https|ftp)\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~])*[^\.\,\)\(\s]', weight=10),
##    Pattern('e-mail address', regex=r'([a-zA-Z0-9]+([\.+_-][a-zA-Z0-9]+)*)@(([a-zA-Z0-9]+((\.|[-]{1,2})[a-zA-Z0-9]+)*)\.[a-zA-Z]{2,6})', weight=10), # source: http://regexlib.com/REDetails.aspx?regexp_id=2119
    Pattern_re('e-mail address', r'(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2}|com|org|net|edu|gov|mil|int|biz|info|mobi|name|aero|asia|jobs|museum)\b', weight=10), # adapted from http://www.regular-expressions.info/email.html
    Pattern_re('domain name', r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)', weight=10), # source: http://regexlib.com/REDetails.aspx?regexp_id=1319
    Pattern_re("EXE MZ followed by PE", r"(?s)MZ.{32,1024}PE\000\000", weight=100), # (?s) sets the DOTALL flag, so that dot matches any character
    Pattern_re("Executable filename", r"\b\w+\.(EXE|COM|VBS|JS|VBE|JSE|BAT|CMD|DLL|SCR)\b", nocase=True, weight=10),
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
    Pattern("Possible VBA macros", "VBA"), #nocase?

    Pattern('Possible Flash header', 'SWF|FWS'.split('|')),
    Pattern('Flash OLE object 1', 'ShockwaveFlash.ShockwaveFlash', weight=10),
    Pattern('Flash OLE object 2', 'S\x00h\x00o\x00c\x00k\x00w\x00a\x00v\x00e\x00F\x00l\x00a\x00s\x00h', weight=10), # warning: this is unicode

    Pattern('Possible PDF header', '%PDF-', weight=10),
    Pattern('Possible PDF end of file marker', '%EOF', weight=10),

##    Pattern_re('Hex blob', r'([A-F0-9][A-F0-9]|[a-f0-9][a-f0-9]){16,}', weight=1),
##    Pattern_re('Base64 blob', r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', weight=1),
]


#--- FUNCTIONS ----------------------------------------------------------------

def multi_trans (raw_data, transform_classes, profiling=False):
    """
    apply all transforms to raw_data, and extract all patterns of interest
    (Slow, but useful when a file uses multiple transforms.)
    """
    print '*** WARNING: harvest mode may return a lot of false positives!'
    # here we only want to extract patterns of interest
    bbz = balbuzard.Balbuzard(harvest_patterns)
    if not profiling:
        for Transform_class in transform_classes:
            # iterate over all possible params for that transform class:
            for params in Transform_class.iter_params():
                # instantiate a Transform object with these params
                transform = Transform_class(params)
                msg = 'transform %s          \r' % transform.shortname
                print msg,
                # transform data:
                data = transform.transform_string(raw_data)
                # search each pattern in transformed data:
                for pattern, matches in bbz.scan(data):
                    for index, match in matches:
                        if len(match)>3:
                            print '%s: %s at index %X, string=%s' % (
                                transform.shortname, pattern.name, index, repr(match))
        print '                                      '
    else:
        # same code, with profiling:
        count_trans = 0
        count_patterns = 0
        start_time = time.clock()
        for Transform_class in transform_classes:
            # iterate over all possible params for that transform class:
            for params in Transform_class.iter_params():
                count_trans += 1
                # instantiate a Transform object with these params
                transform = Transform_class(params)
                msg = 'transform %s          \r' % transform.shortname
                print msg,
                # transform data:
                start_trans = time.clock()
                data = transform.transform_string(raw_data)
                transform.time = time.clock()-start_trans
                # search each pattern in transformed data:
                for pattern, matches in bbz.scan_profiling(data):
                    count_patterns += 1
                    for index, match in matches:
                        if len(match)>3:
                            print '%s: %s at index %X, string=%s' % (
                                transform.shortname, pattern.name, index, repr(match))
                if count_trans % 10 == 0:
                    t = time.clock()-start_time
                    print 'PROFILING: %d transforms in %.1fs, %.2f ms/trans' % (
                        count_trans, t, t*1000/count_trans)
                    for pattern in sorted(bbz.patterns, key=attrgetter('total_time'),
                        reverse=True):
                        print '- %s: %.1f%%, total time = %.1fs' % (
                            pattern.name, 100*pattern.total_time/t,
                            pattern.total_time)
        print '                                      '


#=== MAIN =====================================================================

if __name__ == '__main__':

    usage = 'usage: %prog [options] <filename>'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-l', '--level', dest='level', type='int', default=1,
        help='select transforms level 1, 2 or 3')
##    parser.add_option('-s', '--save', dest='save', type='int', default=10,
##        help='number of transforms to save to files after stage 2')
    parser.add_option("-t", "--transform", dest='transform', type='str', default=None,
        help='only check specific transforms (comma separated list, or "-t list" to display all available transforms)')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
        help='if the file is a zip archive, open first file from it, using the provided password (requires Python 2.6+)')
    parser.add_option("-p", action="store_true", dest="profiling",
        help='profiling: measure time spent on each pattern.')

    (options, args) = parser.parse_args()

    # if option "-t list", display list of transforms and quit:
    if options.transform == 'list':
        print 'Available transforms:'
        for Transform in transform_classes3:
            print '- %s: %s' % (Transform.gen_id, Transform.gen_name)
        sys.exit()

    # Print help if no argurments are passed
    if len(args) == 0:
        print __doc__
        parser.print_help()
        sys.exit()


    #TODO replace the following code by functions in bbcrack, to avoid duplication:

    fname = args[0]
    if options.zip_password is not None:
        # extract 1st file from zip archive, using password
        pwd = options.zip_password
        print 'Opening zip archive %s with password "%s"' % (fname, pwd)
        z = zipfile.ZipFile(fname, 'r')
        print 'Opening first file:', z.infolist()[0].filename
        raw_data = z.read(z.infolist()[0], pwd)
    else:
        # normal file
        print 'Opening file', fname
        f = file(fname, 'rb')
        raw_data = f.read()
        f.close()

    if   options.level == 1:
        transform_classes = transform_classes1
    elif options.level == 2:
        transform_classes = transform_classes2
    else:
        transform_classes = transform_classes3

    if options.transform:
        # options.transform is either a transform name, or a comma-separated list
        transform_classes = []
        trans_names = options.transform.split(',')
        for tname in trans_names:
            for trans in transform_classes3:
                if trans.gen_id == tname:
                    transform_classes.append(trans)
        # check if any transform was found:
        if len(transform_classes) == 0:
            sys.exit('Transform "%s" does not exist. Use "-t list" to see all available transforms.' % options.transform)

    # harvest mode, for multiple transformations
    multi_trans(raw_data, transform_classes, profiling=options.profiling)



# This was coded while listening to Mogwai "The Hawk Is Howling".