#! /usr/bin/env python2
"""
bbharvest

bbharvest is a tool to analyse malware that uses obfuscation such as XOR, ROL,
ADD (and many combinations) to hide information such as IP addresses, domain
names, URLs, strings, embedded files, etc. It is targeted at malware
using several obfuscation transforms and/or several keys in a single file.
It tries all possible keys of selected transforms and extracts all patterns of
interest using the balbuzard engines.
It is part of the Balbuzard package.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository: https://github.com/decalage2/balbuzard
For more info and updates: http://www.decalage.info/balbuzard
"""

# LICENSE:
#
# bbharvest is copyright (c) 2013-2019, Philippe Lagadec (http://www.decalage.info)
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



#------------------------------------------------------------------------------
# CHANGELOG:
# 2013-03-15       PL: - harvest mode in bbcrack: run all transforms, extract all
#                        significant patterns
# 2013-12-06 v0.01 PL: - moved harvest code from bbcrack to bbharvest
# 2013-12-08 v0.02 PL: - added CSV output, renamed multi_trans to harvest
# 2013-12-09 v0.03 PL: - merged patterns list with balbuzard in patterns.py
# 2014-01-04 v0.04 PL: - use functions from bbcrack to simplify main
#                      - added -i option for incremental level
# 2014-01-06 v0.05 PL: - added the possibility to write transform plugins
# 2019-06-16 v0.20 PL: - added main function for pip entry points (issue #8)

__version__ = '0.20'

#------------------------------------------------------------------------------
# TODO:
# + avoid duplicate code in main, using functions in bbcrack
# + option to save copy of every matching file
# + csv output for profiling mode
# + main: same fix as balbuzard for fname in zip


#--- IMPORTS ------------------------------------------------------------------

import sys, os, time, optparse, zipfile, csv

from bbcrack import *


#--- PATTERNS -----------------------------------------------------------------

from balbuzard import harvest_patterns


#--- FUNCTIONS ----------------------------------------------------------------

def harvest (raw_data, transform_classes, filename, profiling=False,
    csv_writer=None):
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
                            # limit matched string display to 50 chars:
                            m = repr(match)
                            if len(m)> 50:
                                m = m[:24]+'...'+m[-23:]
                            print '%s: at %08X %s, string=%s' % (
                                transform.shortname, index, pattern.name, m)
                            if csv_writer is not None:
                                #['Filename', 'Transform', 'Index', 'Pattern name', 'Found string', 'Length']
                                csv_writer.writerow([filename,
                                    transform.shortname, '0x%08X' % index,
                                    pattern.name, m, len(match)])
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

def main():
    usage = 'usage: %prog [options] <filename>'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-l', '--level', dest='level', type='int', default=1,
        help='select transforms level 1, 2 or 3')
    parser.add_option('-i', '--inclevel', dest='inclevel', type='int', default=None,
        help='select transforms only with level 1, 2 or 3 (incremental)')
##    parser.add_option('-s', '--save', dest='save', type='int', default=10,
##        help='number of transforms to save to files after stage 2')
    parser.add_option('-c', '--csv', dest='csv',
        help='export results to a CSV file')
    parser.add_option("-t", "--transform", dest='transform', type='str', default=None,
        help='only check specific transforms (comma separated list, or "-t list" to display all available transforms)')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
        help='if the file is a zip archive, open first file from it, using the provided password (requires Python 2.6+)')
    parser.add_option("-p", action="store_true", dest="profiling",
        help='profiling: measure time spent on each pattern.')

    (options, args) = parser.parse_args()

    # load transform plugins
    load_plugins()

    # if option "-t list", display list of transforms and quit:
    if options.transform == 'list':
        list_transforms()

    # Print help if no argurments are passed
    if len(args) == 0:
        print __doc__
        parser.print_help()
        sys.exit()


    fname = args[0]
    raw_data = read_file(fname, options.zip_password)

    transform_classes = select_transforms(level=options.level,
        incremental_level=options.inclevel, transform_names=options.transform)

    # open CSV file
    if options.csv:
        print 'Writing output to CSV file: %s' % options.csv
        csvfile = open(options.csv, 'wb')
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Filename', 'Transform', 'Index', 'Pattern name',
            'Found string', 'Length'])
    else:
        csv_writer = None


    harvest(raw_data, transform_classes, fname, profiling=options.profiling,
        csv_writer=csv_writer)


if __name__ == '__main__':
    main()

# This was coded while listening to Mogwai "The Hawk Is Howling".
