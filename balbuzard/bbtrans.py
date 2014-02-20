#! /usr/bin/env python2
"""
bbtrans - v0.03 2014-01-20 Philippe Lagadec

bbtrans is a tool to apply a transform such as XOR, ROL, ADD (and many
combinations) to a file. This is useful to deobfuscate malware when the
obfuscation scheme is known, or to test bbcrack.
It is part of the Balbuzard package.

For more info and updates: http://www.decalage.info/balbuzard

usage: bbtrans [options] <file>
"""
# LICENSE:
#
# bbtrans is copyright (c) 2013-2014, Philippe Lagadec (http://www.decalage.info)
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
# 2013-03-28 v0.01 PL: - first version
# 2013-12-09 v0.02 PL: - use hex for params instead of decimal
# 2014-01-20 v0.03 PL: - use function from bbcrack to list transforms

#------------------------------------------------------------------------------
# TODO:
# + support wildcards and several files like balbuzard
# - option to choose output filename



from bbcrack import *

import sys, optparse

if __name__ == '__main__':

    usage = 'usage: %prog [options] <filename>'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-t", "--transform", dest='transform', type='str', default=None,
        help='transform to be applied (or "-t list" to display all available transforms)')
    parser.add_option("-p", "--params", dest='params', type='str', default=None,
        help='parameters for transform (comma separated list)')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
        help='if the file is a zip archive, open first file from it, using the provided password (requires Python 2.6+)')

    (options, args) = parser.parse_args()

    # if option "-t list", display list of transforms and quit:
    if options.transform == 'list':
        list_transforms()

    # Print help if no argurments are passed
    if len(args) == 0 or options.transform is None:
        print __doc__
        parser.print_help()
        sys.exit()

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

##    fname = sys.argv[1]
##    print 'Filename:', fname
##    trans_id = sys.argv[2]

    params = options.params.split(',')
    #params = map(int, params) # for decimal params
    # convert hex params to int:
    for i in xrange(len(params)):
        params[i] = int(params[i], 16)
    if len(params)==1:
        params = params[0]
    else:
        params = tuple(params)

    for Transform_class in transform_classes_all:
        if Transform_class.gen_id == options.transform:
            print 'Transform class:', Transform_class.gen_name
            print 'Params:', params
            transform = Transform_class(params)
            print 'Transform:', transform.name
            base, ext = os.path.splitext(fname)
            trans_fname = base+'_'+transform.shortname+ext
            print 'Saving to file', trans_fname
##            data = open(fname, 'rb').read()
            trans_data = transform.transform_string(raw_data)
            open(trans_fname, 'wb').write(trans_data)

