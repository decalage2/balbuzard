#!/usr/bin/env python 
'''
magic.py
 determines a file type by its magic number

 (C)opyright 2000 Jason Petrone <jp_py@jsnp.net>
 All Rights Reserved

 Command Line Usage: running as `python magic.py file` will print
                     a description of what 'file' is.

 Module Usage:
     magic.whatis(data): when passed a string 'data' containing 
                         binary or text data, a description of
                         what the data is will be returned.

     magic.file(filename): returns a description of what the file
                           'filename' contains.
'''

import re, struct, string

__version__ = '0.1'

magic = [
  [0L, 'leshort', '=', 1538L, 'application/x-alan-adventure-game'],
  [0L, 'string', '=', 'TADS', 'application/x-tads-game'],
  [0L, 'short', '=', 420L, 'application/x-executable-file'],
  [0L, 'short', '=', 421L, 'application/x-executable-file'],
  [0L, 'leshort', '=', 603L, 'application/x-executable-file'],
  [0L, 'string', '=', 'Core\001', 'application/x-executable-file'],
  [0L, 'string', '=', 'AMANDA: TAPESTART DATE', 'application/x-amanda-header'],
  [0L, 'belong', '=', 1011L, 'application/x-executable-file'],
  [0L, 'belong', '=', 999L, 'application/x-library-file'],
  [0L, 'belong', '=', 435L, 'video/mpeg'],
  [0L, 'belong', '=', 442L, 'video/mpeg'],
  [0L, 'beshort&0xfff0', '=', 65520L, 'audio/mpeg'],
  [4L, 'leshort', '=', 44817L, 'video/fli'],
  [4L, 'leshort', '=', 44818L, 'video/flc'],
  [0L, 'string', '=', 'MOVI', 'video/x-sgi-movie'],
  [4L, 'string', '=', 'moov', 'video/quicktime'],
  [4L, 'string', '=', 'mdat', 'video/quicktime'],
  [0L, 'long', '=', 100554L, 'application/x-apl-workspace'],
  [0L, 'string', '=', 'FiLeStArTfIlEsTaRt', 'text/x-apple-binscii'],
  [0L, 'string', '=', '\012GL', 'application/data'],
  [0L, 'string', '=', 'v\377', 'application/data'],
  [0L, 'string', '=', 'NuFile', 'application/data'],
  [0L, 'string', '=', 'N\365F\351l\345', 'application/data'],
  [0L, 'belong', '=', 333312L, 'application/data'],
  [0L, 'belong', '=', 333319L, 'application/data'],
  [257L, 'string', '=', 'ustar\000', 'application/x-tar'],
  [257L, 'string', '=', 'ustar  \000', 'application/x-gtar'],
  [0L, 'short', '=', 70707L, 'application/x-cpio'],
  [0L, 'short', '=', 143561L, 'application/x-bcpio'],
  [0L, 'string', '=', '070707', 'application/x-cpio'],
  [0L, 'string', '=', '070701', 'application/x-cpio'],
  [0L, 'string', '=', '070702', 'application/x-cpio'],
  [0L, 'string', '=', '!<arch>\012debian', 'application/x-dpkg'],
  [0L, 'long', '=', 177555L, 'application/x-ar'],
  [0L, 'short', '=', 177555L, 'application/data'],
  [0L, 'long', '=', 177545L, 'application/data'],
  [0L, 'short', '=', 177545L, 'application/data'],
  [0L, 'long', '=', 100554L, 'application/x-apl-workspace'],
  [0L, 'string', '=', '<ar>', 'application/x-ar'],
  [0L, 'string', '=', '!<arch>\012__________E', 'application/x-ar'],
  [0L, 'string', '=', '-h-', 'application/data'],
  [0L, 'string', '=', '!<arch>', 'application/x-ar'],
  [0L, 'string', '=', '<ar>', 'application/x-ar'],
  [0L, 'string', '=', '<ar>', 'application/x-ar'],
  [0L, 'belong', '=', 1711210496L, 'application/x-ar'],
  [0L, 'belong', '=', 1013019198L, 'application/x-ar'],
  [0L, 'long', '=', 557605234L, 'application/x-ar'],
  [0L, 'lelong', '=', 177555L, 'application/data'],
  [0L, 'leshort', '=', 177555L, 'application/data'],
  [0L, 'lelong', '=', 177545L, 'application/data'],
  [0L, 'leshort', '=', 177545L, 'application/data'],
  [0L, 'lelong', '=', 236525L, 'application/data'],
  [0L, 'lelong', '=', 236526L, 'application/data'],
  [0L, 'lelong&0x8080ffff', '=', 2074L, 'application/x-arc'],
  [0L, 'lelong&0x8080ffff', '=', 2330L, 'application/x-arc'],
  [0L, 'lelong&0x8080ffff', '=', 538L, 'application/x-arc'],
  [0L, 'lelong&0x8080ffff', '=', 794L, 'application/x-arc'],
  [0L, 'lelong&0x8080ffff', '=', 1050L, 'application/x-arc'],
  [0L, 'lelong&0x8080ffff', '=', 1562L, 'application/x-arc'],
  [0L, 'string', '=', '\032archive', 'application/data'],
  [0L, 'leshort', '=', 60000L, 'application/x-arj'],
  [0L, 'string', '=', 'HPAK', 'application/data'],
  [0L, 'string', '=', '\351,\001JAM application/data', ''],
  [2L, 'string', '=', '-lh0-', 'application/x-lha'],
  [2L, 'string', '=', '-lh1-', 'application/x-lha'],
  [2L, 'string', '=', '-lz4-', 'application/x-lha'],
  [2L, 'string', '=', '-lz5-', 'application/x-lha'],
  [2L, 'string', '=', '-lzs-', 'application/x-lha'],
  [2L, 'string', '=', '-lh -', 'application/x-lha'],
  [2L, 'string', '=', '-lhd-', 'application/x-lha'],
  [2L, 'string', '=', '-lh2-', 'application/x-lha'],
  [2L, 'string', '=', '-lh3-', 'application/x-lha'],
  [2L, 'string', '=', '-lh4-', 'application/x-lha'],
  [2L, 'string', '=', '-lh5-', 'application/x-lha'],
  [0L, 'string', '=', 'Rar!', 'application/x-rar'],
  [0L, 'string', '=', 'SQSH', 'application/data'],
  [0L, 'string', '=', 'UC2\032', 'application/data'],
  [0L, 'string', '=', 'PK\003\004', 'application/zip'],
  [20L, 'lelong', '=', 4257523676L, 'application/x-zoo'],
  [10L, 'string', '=', '# This is a shell archive', 'application/x-shar'],
  [0L, 'string', '=', '*STA', 'application/data'],
  [0L, 'string', '=', '2278', 'application/data'],
  [0L, 'beshort', '=', 560L, 'application/x-executable-file'],
  [0L, 'beshort', '=', 561L, 'application/x-executable-file'],
  [0L, 'string', '=', '\000\004\036\212\200', 'application/core'],
  [0L, 'string', '=', '.snd', 'audio/basic'],
  [0L, 'lelong', '=', 6583086L, 'audio/basic'],
  [0L, 'string', '=', 'MThd', 'audio/midi'],
  [0L, 'string', '=', 'CTMF', 'audio/x-cmf'],
  [0L, 'string', '=', 'SBI', 'audio/x-sbi'],
  [0L, 'string', '=', 'Creative Voice File', 'audio/x-voc'],
  [0L, 'belong', '=', 1314148939L, 'audio/x-multitrack'],
  [0L, 'string', '=', 'RIFF', 'audio/x-wav'],
  [0L, 'string', '=', 'EMOD', 'audio/x-emod'],
  [0L, 'belong', '=', 779248125L, 'audio/x-pn-realaudio'],
  [0L, 'string', '=', 'MTM', 'audio/x-multitrack'],
  [0L, 'string', '=', 'if', 'audio/x-669-mod'],
  [0L, 'string', '=', 'FAR', 'audio/mod'],
  [0L, 'string', '=', 'MAS_U', 'audio/x-multimate-mod'],
  [44L, 'string', '=', 'SCRM', 'audio/x-st3-mod'],
  [0L, 'string', '=', 'GF1PATCH110\000ID#000002\000', 'audio/x-gus-patch'],
  [0L, 'string', '=', 'GF1PATCH100\000ID#000002\000', 'audio/x-gus-patch'],
  [0L, 'string', '=', 'JN', 'audio/x-669-mod'],
  [0L, 'string', '=', 'UN05', 'audio/x-mikmod-uni'],
  [0L, 'string', '=', 'Extended Module:', 'audio/x-ft2-mod'],
  [21L, 'string', '=', '!SCREAM!', 'audio/x-st2-mod'],
  [1080L, 'string', '=', 'M.K.', 'audio/x-protracker-mod'],
  [1080L, 'string', '=', 'M!K!', 'audio/x-protracker-mod'],
  [1080L, 'string', '=', 'FLT4', 'audio/x-startracker-mod'],
  [1080L, 'string', '=', '4CHN', 'audio/x-fasttracker-mod'],
  [1080L, 'string', '=', '6CHN', 'audio/x-fasttracker-mod'],
  [1080L, 'string', '=', '8CHN', 'audio/x-fasttracker-mod'],
  [1080L, 'string', '=', 'CD81', 'audio/x-oktalyzer-mod'],
  [1080L, 'string', '=', 'OKTA', 'audio/x-oktalyzer-mod'],
  [1080L, 'string', '=', '16CN', 'audio/x-taketracker-mod'],
  [1080L, 'string', '=', '32CN', 'audio/x-taketracker-mod'],
  [0L, 'string', '=', 'TOC', 'audio/x-toc'],
  [0L, 'short', '=', 3401L, 'application/x-executable-file'],
  [0L, 'long', '=', 406L, 'application/x-executable-file'],
  [0L, 'short', '=', 406L, 'application/x-executable-file'],
  [0L, 'short', '=', 3001L, 'application/x-executable-file'],
  [0L, 'lelong', '=', 314L, 'application/x-executable-file'],
  [0L, 'string', '=', '//', 'text/cpp'],
  [0L, 'string', '=', '\\\\1cw\\', 'application/data'],
  [0L, 'string', '=', '\\\\1cw', 'application/data'],
  [0L, 'belong&0xffffff00', '=', 2231440384L, 'application/data'],
  [0L, 'belong&0xffffff00', '=', 2231487232L, 'application/data'],
  [0L, 'short', '=', 575L, 'application/x-executable-file'],
  [0L, 'short', '=', 577L, 'application/x-executable-file'],
  [4L, 'string', '=', 'pipe', 'application/data'],
  [4L, 'string', '=', 'prof', 'application/data'],
  [0L, 'string', '=', ': shell', 'application/data'],
  [0L, 'string', '=', '#!/bin/sh', 'application/x-sh'],
  [0L, 'string', '=', '#! /bin/sh', 'application/x-sh'],
  [0L, 'string', '=', '#! /bin/sh', 'application/x-sh'],
  [0L, 'string', '=', '#!/bin/csh', 'application/x-csh'],
  [0L, 'string', '=', '#! /bin/csh', 'application/x-csh'],
  [0L, 'string', '=', '#! /bin/csh', 'application/x-csh'],
  [0L, 'string', '=', '#!/bin/ksh', 'application/x-ksh'],
  [0L, 'string', '=', '#! /bin/ksh', 'application/x-ksh'],
  [0L, 'string', '=', '#! /bin/ksh', 'application/x-ksh'],
  [0L, 'string', '=', '#!/bin/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#! /bin/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#! /bin/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#!/usr/local/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#! /usr/local/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#!/usr/local/bin/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#! /usr/local/bin/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#! /usr/local/bin/tcsh', 'application/x-csh'],
  [0L, 'string', '=', '#!/usr/local/bin/zsh', 'application/x-zsh'],
  [0L, 'string', '=', '#! /usr/local/bin/zsh', 'application/x-zsh'],
  [0L, 'string', '=', '#! /usr/local/bin/zsh', 'application/x-zsh'],
  [0L, 'string', '=', '#!/usr/local/bin/ash', 'application/x-sh'],
  [0L, 'string', '=', '#! /usr/local/bin/ash', 'application/x-zsh'],
  [0L, 'string', '=', '#! /usr/local/bin/ash', 'application/x-zsh'],
  [0L, 'string', '=', '#!/usr/local/bin/ae', 'text/script'],
  [0L, 'string', '=', '#! /usr/local/bin/ae', 'text/script'],
  [0L, 'string', '=', '#! /usr/local/bin/ae', 'text/script'],
  [0L, 'string', '=', '#!/bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#!/usr/bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#!/usr/local/bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/local/bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/local/bin/nawk', 'application/x-awk'],
  [0L, 'string', '=', '#!/bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#!/usr/bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#!/usr/local/bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/local/bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/local/bin/gawk', 'application/x-awk'],
  [0L, 'string', '=', '#!/bin/awk', 'application/x-awk'],
  [0L, 'string', '=', '#! /bin/awk', 'application/x-awk'],
  [0L, 'string', '=', '#! /bin/awk', 'application/x-awk'],
  [0L, 'string', '=', '#!/usr/bin/awk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/bin/awk', 'application/x-awk'],
  [0L, 'string', '=', '#! /usr/bin/awk', 'application/x-awk'],
  [0L, 'string', '=', 'BEGIN', 'application/x-awk'],
  [0L, 'string', '=', '#!/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#! /bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#! /bin/perl', 'application/x-perl'],
  [0L, 'string', '=', 'eval "exec /bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#!/usr/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#! /usr/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#! /usr/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', 'eval "exec /usr/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#!/usr/local/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#! /usr/local/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#! /usr/local/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', 'eval "exec /usr/local/bin/perl', 'application/x-perl'],
  [0L, 'string', '=', '#!/bin/python', 'application/x-python'],
  [0L, 'string', '=', '#! /bin/python', 'application/x-python'],
  [0L, 'string', '=', '#! /bin/python', 'application/x-python'],
  [0L, 'string', '=', 'eval "exec /bin/python', 'application/x-python'],
  [0L, 'string', '=', '#!/usr/bin/python', 'application/x-python'],
  [0L, 'string', '=', '#! /usr/bin/python', 'application/x-python'],
  [0L, 'string', '=', '#! /usr/bin/python', 'application/x-python'],
  [0L, 'string', '=', 'eval "exec /usr/bin/python', 'application/x-python'],
  [0L, 'string', '=', '#!/usr/local/bin/python', 'application/x-python'],
  [0L, 'string', '=', '#! /usr/local/bin/python', 'application/x-python'],
  [0L, 'string', '=', '#! /usr/local/bin/python', 'application/x-python'],
  [0L, 'string', '=', 'eval "exec /usr/local/bin/python', 'application/x-python'],
  [0L, 'string', '=', '#!/usr/bin/env python', 'application/x-python'],
  [0L, 'string', '=', '#! /usr/bin/env python', 'application/x-python'],
  [0L, 'string', '=', '#!/bin/rc', 'text/script'],
  [0L, 'string', '=', '#! /bin/rc', 'text/script'],
  [0L, 'string', '=', '#! /bin/rc', 'text/script'],
  [0L, 'string', '=', '#!/bin/bash', 'application/x-sh'],
  [0L, 'string', '=', '#! /bin/bash', 'application/x-sh'],
  [0L, 'string', '=', '#! /bin/bash', 'application/x-sh'],
  [0L, 'string', '=', '#!/usr/local/bin/bash', 'application/x-sh'],
  [0L, 'string', '=', '#! /usr/local/bin/bash', 'application/x-sh'],
  [0L, 'string', '=', '#! /usr/local/bin/bash', 'application/x-sh'],
  [0L, 'string', '=', '#! /', 'text/script'],
  [0L, 'string', '=', '#! /', 'text/script'],
  [0L, 'string', '=', '#!/', 'text/script'],
  [0L, 'string', '=', '#! text/script', ''],
  [0L, 'string', '=', '\037\235', 'application/compress'],
  [0L, 'string', '=', '\037\213', 'application/x-gzip'],
  [0L, 'string', '=', '\037\036', 'application/data'],
  [0L, 'short', '=', 17437L, 'application/data'],
  [0L, 'short', '=', 8191L, 'application/data'],
  [0L, 'string', '=', '\377\037', 'application/data'],
  [0L, 'short', '=', 145405L, 'application/data'],
  [0L, 'string', '=', 'BZh', 'application/x-bzip2'],
  [0L, 'leshort', '=', 65398L, 'application/data'],
  [0L, 'leshort', '=', 65142L, 'application/data'],
  [0L, 'leshort', '=', 64886L, 'application/x-lzh'],
  [0L, 'string', '=', '\037\237', 'application/data'],
  [0L, 'string', '=', '\037\236', 'application/data'],
  [0L, 'string', '=', '\037\240', 'application/data'],
  [0L, 'string', '=', 'BZ', 'application/x-bzip'],
  [0L, 'string', '=', '\211LZO\000\015\012\032\012', 'application/data'],
  [0L, 'belong', '=', 507L, 'application/x-object-file'],
  [0L, 'belong', '=', 513L, 'application/x-executable-file'],
  [0L, 'belong', '=', 515L, 'application/x-executable-file'],
  [0L, 'belong', '=', 517L, 'application/x-executable-file'],
  [0L, 'belong', '=', 70231L, 'application/core'],
  [24L, 'belong', '=', 60011L, 'application/data'],
  [24L, 'belong', '=', 60012L, 'application/data'],
  [24L, 'belong', '=', 60013L, 'application/data'],
  [24L, 'belong', '=', 60014L, 'application/data'],
  [0L, 'belong', '=', 601L, 'application/x-object-file'],
  [0L, 'belong', '=', 607L, 'application/data'],
  [0L, 'belong', '=', 324508366L, 'application/x-gdbm'],
  [0L, 'lelong', '=', 324508366L, 'application/x-gdbm'],
  [0L, 'string', '=', 'GDBM', 'application/x-gdbm'],
  [0L, 'belong', '=', 398689L, 'application/x-db'],
  [0L, 'belong', '=', 340322L, 'application/x-db'],
  [0L, 'string', '=', '<list>\012<protocol bbn-m', 'application/data'],
  [0L, 'string', '=', 'diff text/x-patch', ''],
  [0L, 'string', '=', '*** text/x-patch', ''],
  [0L, 'string', '=', 'Only in text/x-patch', ''],
  [0L, 'string', '=', 'Common subdirectories: text/x-patch', ''],
  [0L, 'string', '=', '!<arch>\012________64E', 'application/data'],
  [0L, 'leshort', '=', 387L, 'application/x-executable-file'],
  [0L, 'leshort', '=', 392L, 'application/x-executable-file'],
  [0L, 'leshort', '=', 399L, 'application/x-object-file'],
  [0L, 'string', '=', '\377\377\177', 'application/data'],
  [0L, 'string', '=', '\377\377|', 'application/data'],
  [0L, 'string', '=', '\377\377~', 'application/data'],
  [0L, 'string', '=', '\033c\033', 'application/data'],
  [0L, 'long', '=', 4553207L, 'image/x11'],
  [0L, 'string', '=', '!<PDF>!\012', 'application/x-prof'],
  [0L, 'short', '=', 1281L, 'application/x-locale'],
  [24L, 'belong', '=', 60012L, 'application/x-dump'],
  [24L, 'belong', '=', 60011L, 'application/x-dump'],
  [24L, 'lelong', '=', 60012L, 'application/x-dump'],
  [24L, 'lelong', '=', 60011L, 'application/x-dump'],
  [0L, 'string', '=', '\177ELF', 'application/x-executable-file'],
  [0L, 'short', '=', 340L, 'application/data'],
  [0L, 'short', '=', 341L, 'application/x-executable-file'],
  [1080L, 'leshort', '=', 61267L, 'application/x-linux-ext2fs'],
  [0L, 'string', '=', '\366\366\366\366', 'application/x-pc-floppy'],
  [774L, 'beshort', '=', 55998L, 'application/data'],
  [510L, 'leshort', '=', 43605L, 'application/data'],
  [1040L, 'leshort', '=', 4991L, 'application/x-filesystem'],
  [1040L, 'leshort', '=', 5007L, 'application/x-filesystem'],
  [1040L, 'leshort', '=', 9320L, 'application/x-filesystem'],
  [1040L, 'leshort', '=', 9336L, 'application/x-filesystem'],
  [0L, 'string', '=', '-rom1fs-\000', 'application/x-filesystem'],
  [395L, 'string', '=', 'OS/2', 'application/x-bootable'],
  [0L, 'string', '=', 'FONT', 'font/x-vfont'],
  [0L, 'short', '=', 436L, 'font/x-vfont'],
  [0L, 'short', '=', 17001L, 'font/x-vfont'],
  [0L, 'string', '=', '%!PS-AdobeFont-1.0', 'font/type1'],
  [6L, 'string', '=', '%!PS-AdobeFont-1.0', 'font/type1'],
  [0L, 'belong', '=', 4L, 'font/x-snf'],
  [0L, 'lelong', '=', 4L, 'font/x-snf'],
  [0L, 'string', '=', 'STARTFONT font/x-bdf', ''],
  [0L, 'string', '=', '\001fcp', 'font/x-pcf'],
  [0L, 'string', '=', 'D1.0\015', 'font/x-speedo'],
  [0L, 'string', '=', 'flf', 'font/x-figlet'],
  [0L, 'string', '=', 'flc', 'application/x-font'],
  [0L, 'belong', '=', 335698201L, 'font/x-libgrx'],
  [0L, 'belong', '=', 4282797902L, 'font/x-dos'],
  [7L, 'belong', '=', 4540225L, 'font/x-dos'],
  [7L, 'belong', '=', 5654852L, 'font/x-dos'],
  [4098L, 'string', '=', 'DOSFONT', 'font/x-dos'],
  [0L, 'string', '=', '<MakerFile', 'application/x-framemaker'],
  [0L, 'string', '=', '<MIFFile', 'application/x-framemaker'],
  [0L, 'string', '=', '<MakerDictionary', 'application/x-framemaker'],
  [0L, 'string', '=', '<MakerScreenFont', 'font/x-framemaker'],
  [0L, 'string', '=', '<MML', 'application/x-framemaker'],
  [0L, 'string', '=', '<BookFile', 'application/x-framemaker'],
  [0L, 'string', '=', '<Maker', 'application/x-framemaker'],
  [0L, 'lelong&0377777777', '=', 41400407L, 'application/x-executable-file'],
  [0L, 'lelong&0377777777', '=', 41400410L, 'application/x-executable-file'],
  [0L, 'lelong&0377777777', '=', 41400413L, 'application/x-executable-file'],
  [0L, 'lelong&0377777777', '=', 41400314L, 'application/x-executable-file'],
  [7L, 'string', '=', '\357\020\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000', 'application/core'],
  [0L, 'lelong', '=', 11421044151L, 'application/data'],
  [0L, 'string', '=', 'GIMP Gradient', 'application/x-gimp-gradient'],
  [0L, 'string', '=', 'gimp xcf', 'application/x-gimp-image'],
  [20L, 'string', '=', 'GPAT', 'application/x-gimp-pattern'],
  [20L, 'string', '=', 'GIMP', 'application/x-gimp-brush'],
  [0L, 'string', '=', '\336\022\004\225', 'application/x-locale'],
  [0L, 'string', '=', '\225\004\022\336', 'application/x-locale'],
  [0L, 'beshort', '=', 627L, 'application/x-executable-file'],
  [0L, 'beshort', '=', 624L, 'application/x-executable-file'],
  [0L, 'string', '=', '\000\001\000\000\000', 'font/ttf'],
  [0L, 'long', '=', 1203604016L, 'application/data'],
  [0L, 'long', '=', 1702407010L, 'application/data'],
  [0L, 'long', '=', 1003405017L, 'application/data'],
  [0L, 'long', '=', 1602007412L, 'application/data'],
  [0L, 'belong', '=', 34603270L, 'application/x-object-file'],
  [0L, 'belong', '=', 34603271L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34603272L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34603275L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34603278L, 'application/x-library-file'],
  [0L, 'belong', '=', 34603277L, 'application/x-library-file'],
  [0L, 'belong', '=', 34865414L, 'application/x-object-file'],
  [0L, 'belong', '=', 34865415L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34865416L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34865419L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34865422L, 'application/x-library-file'],
  [0L, 'belong', '=', 34865421L, 'application/x-object-file'],
  [0L, 'belong', '=', 34275590L, 'application/x-object-file'],
  [0L, 'belong', '=', 34275591L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34275592L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34275595L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34275598L, 'application/x-library-file'],
  [0L, 'belong', '=', 34275597L, 'application/x-library-file'],
  [0L, 'belong', '=', 557605234L, 'application/x-ar'],
  [0L, 'long', '=', 34078982L, 'application/x-executable-file'],
  [0L, 'long', '=', 34078983L, 'application/x-executable-file'],
  [0L, 'long', '=', 34078984L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34341128L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34341127L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34341131L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34341126L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34210056L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34210055L, 'application/x-executable-file'],
  [0L, 'belong', '=', 34341134L, 'application/x-library-file'],
  [0L, 'belong', '=', 34341133L, 'application/x-library-file'],
  [0L, 'long', '=', 65381L, 'application/x-library-file'],
  [0L, 'long', '=', 34275173L, 'application/x-library-file'],
  [0L, 'long', '=', 34406245L, 'application/x-library-file'],
  [0L, 'long', '=', 34144101L, 'application/x-library-file'],
  [0L, 'long', '=', 22552998L, 'application/core'],
  [0L, 'long', '=', 1302851304L, 'font/x-hp-windows'],
  [0L, 'string', '=', 'Bitmapfile', 'image/unknown'],
  [0L, 'string', '=', 'IMGfile', 'CIS image/unknown'],
  [0L, 'long', '=', 34341132L, 'application/x-lisp'],
  [0L, 'string', '=', 'msgcat01', 'application/x-locale'],
  [0L, 'string', '=', 'HPHP48-', 'HP48 binary'],
  [0L, 'string', '=', '%%HP:', 'HP48 text'],
  [0L, 'beshort', '=', 200L, 'hp200 (68010) BSD'],
  [0L, 'beshort', '=', 300L, 'hp300 (68020+68881) BSD'],
  [0L, 'beshort', '=', 537L, '370 XA sysV executable'],
  [0L, 'beshort', '=', 532L, '370 XA sysV pure executable'],
  [0L, 'beshort', '=', 54001L, '370 sysV pure executable'],
  [0L, 'beshort', '=', 55001L, '370 XA sysV pure executable'],
  [0L, 'beshort', '=', 56401L, '370 sysV executable'],
  [0L, 'beshort', '=', 57401L, '370 XA sysV executable'],
  [0L, 'beshort', '=', 531L, 'SVR2 executable (Amdahl-UTS)'],
  [0L, 'beshort', '=', 534L, 'SVR2 pure executable (Amdahl-UTS)'],
  [0L, 'beshort', '=', 530L, 'SVR2 pure executable (USS/370)'],
  [0L, 'beshort', '=', 535L, 'SVR2 executable (USS/370)'],
  [0L, 'beshort', '=', 479L, 'executable (RISC System/6000 V3.1) or obj module'],
  [0L, 'beshort', '=', 260L, 'shared library'],
  [0L, 'beshort', '=', 261L, 'ctab data'],
  [0L, 'beshort', '=', 65028L, 'structured file'],
  [0L, 'string', '=', '0xabcdef', 'AIX message catalog'],
  [0L, 'belong', '=', 505L, 'AIX compiled message catalog'],
  [0L, 'string', '=', '<aiaff>', 'archive'],
  [0L, 'string', '=', 'FORM', 'IFF data'],
  [0L, 'string', '=', 'P1', 'image/x-portable-bitmap'],
  [0L, 'string', '=', 'P2', 'image/x-portable-graymap'],
  [0L, 'string', '=', 'P3', 'image/x-portable-pixmap'],
  [0L, 'string', '=', 'P4', 'image/x-portable-bitmap'],
  [0L, 'string', '=', 'P5', 'image/x-portable-graymap'],
  [0L, 'string', '=', 'P6', 'image/x-portable-pixmap'],
  [0L, 'string', '=', 'IIN1', 'image/tiff'],
  [0L, 'string', '=', 'MM\000*', 'image/tiff'],
  [0L, 'string', '=', 'II*\000', 'image/tiff'],
  [0L, 'string', '=', '\211PNG', 'image/x-png'],
  [1L, 'string', '=', 'PNG', 'image/x-png'],
  [0L, 'string', '=', 'GIF8', 'image/gif'],
  [0L, 'string', '=', '\361\000@\273', 'image/x-cmu-raster'],
  [0L, 'string', '=', 'id=ImageMagick', 'MIFF image data'],
  [0L, 'long', '=', 1123028772L, 'Artisan image data'],
  [0L, 'string', '=', '#FIG', 'FIG image text'],
  [0L, 'string', '=', 'ARF_BEGARF', 'PHIGS clear text archive'],
  [0L, 'string', '=', '@(#)SunPHIGS', 'SunPHIGS'],
  [0L, 'string', '=', 'GKSM', 'GKS Metafile'],
  [0L, 'string', '=', 'BEGMF', 'clear text Computer Graphics Metafile'],
  [0L, 'beshort&0xffe0', '=', 32L, 'binary Computer Graphics Metafile'],
  [0L, 'beshort', '=', 12320L, 'character Computer Graphics Metafile'],
  [0L, 'string', '=', 'yz', 'MGR bitmap, modern format, 8-bit aligned'],
  [0L, 'string', '=', 'zz', 'MGR bitmap, old format, 1-bit deep, 16-bit aligned'],
  [0L, 'string', '=', 'xz', 'MGR bitmap, old format, 1-bit deep, 32-bit aligned'],
  [0L, 'string', '=', 'yx', 'MGR bitmap, modern format, squeezed'],
  [0L, 'string', '=', '%bitmap\000', 'FBM image data'],
  [1L, 'string', '=', 'PC Research, Inc', 'group 3 fax data'],
  [0L, 'beshort', '=', 65496L, 'image/jpeg'],
  [0L, 'string', '=', 'hsi1', 'image/x-jpeg-proprietary'],
  [0L, 'string', '=', 'BM', 'image/x-bmp'],
  [0L, 'string', '=', 'IC', 'image/x-ico'],
  [0L, 'string', '=', 'PI', 'PC pointer image data'],
  [0L, 'string', '=', 'CI', 'PC color icon data'],
  [0L, 'string', '=', 'CP', 'PC color pointer image data'],
  [0L, 'string', '=', '/* XPM */', 'X pixmap image text'],
  [0L, 'leshort', '=', 52306L, 'RLE image data,'],
  [0L, 'string', '=', 'Imagefile version-', 'iff image data'],
  [0L, 'belong', '=', 1504078485L, 'x/x-image-sun-raster'],
  [0L, 'beshort', '=', 474L, 'x/x-image-sgi'],
  [0L, 'string', '=', 'IT01', 'FIT image data'],
  [0L, 'string', '=', 'IT02', 'FIT image data'],
  [2048L, 'string', '=', 'PCD_IPI', 'x/x-photo-cd-pack-file'],
  [0L, 'string', '=', 'PCD_OPA', 'x/x-photo-cd-overfiew-file'],
  [0L, 'string', '=', 'SIMPLE  =', 'FITS image data'],
  [0L, 'string', '=', 'This is a BitMap file', 'Lisp Machine bit-array-file'],
  [0L, 'string', '=', '!!', 'Bennet Yee\'s "face" format'],
  [0L, 'beshort', '=', 4112L, 'PEX Binary Archive'],
  [3000L, 'string', '=', 'Visio (TM) Drawing', '%s'],
  [0L, 'leshort', '=', 502L, 'basic-16 executable'],
  [0L, 'leshort', '=', 503L, 'basic-16 executable (TV)'],
  [0L, 'leshort', '=', 510L, 'application/x-executable-file'],
  [0L, 'leshort', '=', 511L, 'application/x-executable-file'],
  [0L, 'leshort', '=', 512L, 'application/x-executable-file'],
  [0L, 'leshort', '=', 522L, 'application/x-executable-file'],
  [0L, 'leshort', '=', 514L, 'application/x-executable-file'],
  [0L, 'string', '=', '\210OPS', 'Interleaf saved data'],
  [0L, 'string', '=', '<!OPS', 'Interleaf document text'],
  [4L, 'string', '=', 'pgscriptver', 'IslandWrite document'],
  [13L, 'string', '=', 'DrawFile', 'IslandDraw document'],
  [0L, 'leshort&0xFFFC', '=', 38400L, 'little endian ispell'],
  [0L, 'beshort&0xFFFC', '=', 38400L, 'big endian ispell'],
  [0L, 'belong', '=', 3405691582L, 'compiled Java class data,'],
  [0L, 'beshort', '=', 44269L, 'Java serialization data'],
  [0L, 'string', '=', 'KarmaRHD', 'Version Karma Data Structure Version'],
  [0L, 'string', '=', 'lect', 'DEC SRC Virtual Paper Lectern file'],
  [53L, 'string', '=', 'yyprevious', 'C program text (from lex)'],
  [21L, 'string', '=', 'generated by flex', 'C program text (from flex)'],
  [0L, 'string', '=', '%{', 'lex description text'],
  [0L, 'short', '=', 32768L, 'lif file'],
  [0L, 'lelong', '=', 6553863L, 'Linux/i386 impure executable (OMAGIC)'],
  [0L, 'lelong', '=', 6553864L, 'Linux/i386 pure executable (NMAGIC)'],
  [0L, 'lelong', '=', 6553867L, 'Linux/i386 demand-paged executable (ZMAGIC)'],
  [0L, 'lelong', '=', 6553804L, 'Linux/i386 demand-paged executable (QMAGIC)'],
  [0L, 'string', '=', '\007\001\000', 'Linux/i386 object file'],
  [0L, 'string', '=', '\001\003\020\004', 'Linux-8086 impure executable'],
  [0L, 'string', '=', '\001\003 \004', 'Linux-8086 executable'],
  [0L, 'string', '=', '\243\206\001\000', 'Linux-8086 object file'],
  [0L, 'string', '=', '\001\003\020\020', 'Minix-386 impure executable'],
  [0L, 'string', '=', '\001\003 \020', 'Minix-386 executable'],
  [0L, 'string', '=', '*nazgul*', 'Linux compiled message catalog'],
  [216L, 'lelong', '=', 421L, 'Linux/i386 core file'],
  [2L, 'string', '=', 'LILO', 'Linux/i386 LILO boot/chain loader'],
  [0L, 'string', '=', '0.9', ''],
  [0L, 'leshort', '=', 1078L, 'font/linux-psf'],
  [4086L, 'string', '=', 'SWAP-SPACE', 'Linux/i386 swap file'],
  [0L, 'leshort', '=', 387L, 'ECOFF alpha'],
  [514L, 'string', '=', 'HdrS', 'Linux kernel'],
  [0L, 'belong', '=', 3099592590L, 'Linux kernel'],
  [0L, 'string', '=', 'Begin3', 'Linux Software Map entry text'],
  [0L, 'string', '=', ';;', 'Lisp/Scheme program text'],
  [0L, 'string', '=', '\012(', 'byte-compiled Emacs-Lisp program data'],
  [0L, 'string', '=', ';ELC\023\000\000\000', 'byte-compiled Emacs-Lisp program data'],
  [0L, 'string', '=', "(SYSTEM::VERSION '", 'CLISP byte-compiled Lisp program text'],
  [0L, 'long', '=', 1886817234L, 'CLISP memory image data'],
  [0L, 'long', '=', 3532355184L, 'CLISP memory image data, other endian'],
  [0L, 'long', '=', 3725722773L, 'GNU-format message catalog data'],
  [0L, 'long', '=', 2500072158L, 'GNU-format message catalog data'],
  [0L, 'belong', '=', 3405691582L, 'mach-o fat file'],
  [0L, 'belong', '=', 4277009102L, 'mach-o'],
  [11L, 'string', '=', 'must be converted with BinHex', 'BinHex binary text'],
  [0L, 'string', '=', 'SIT!', 'StuffIt Archive (data)'],
  [65L, 'string', '=', 'SIT!', 'StuffIt Archive (rsrc + data)'],
  [0L, 'string', '=', 'SITD', 'StuffIt Deluxe (data)'],
  [65L, 'string', '=', 'SITD', 'StuffIt Deluxe (rsrc + data)'],
  [0L, 'string', '=', 'Seg', 'StuffIt Deluxe Segment (data)'],
  [65L, 'string', '=', 'Seg', 'StuffIt Deluxe Segment (rsrc + data)'],
  [0L, 'string', '=', 'APPL', 'Macintosh Application (data)'],
  [65L, 'string', '=', 'APPL', 'Macintosh Application (rsrc + data)'],
  [0L, 'string', '=', 'zsys', 'Macintosh System File (data)'],
  [65L, 'string', '=', 'zsys', 'Macintosh System File(rsrc + data)'],
  [0L, 'string', '=', 'FNDR', 'Macintosh Finder (data)'],
  [65L, 'string', '=', 'FNDR', 'Macintosh Finder(rsrc + data)'],
  [0L, 'string', '=', 'libr', 'Macintosh Library (data)'],
  [65L, 'string', '=', 'libr', 'Macintosh Library(rsrc + data)'],
  [0L, 'string', '=', 'shlb', 'Macintosh Shared Library (data)'],
  [65L, 'string', '=', 'shlb', 'Macintosh Shared Library(rsrc + data)'],
  [0L, 'string', '=', 'cdev', 'Macintosh Control Panel (data)'],
  [65L, 'string', '=', 'cdev', 'Macintosh Control Panel(rsrc + data)'],
  [0L, 'string', '=', 'INIT', 'Macintosh Extension (data)'],
  [65L, 'string', '=', 'INIT', 'Macintosh Extension(rsrc + data)'],
  [0L, 'string', '=', 'FFIL', 'font/ttf'],
  [65L, 'string', '=', 'FFIL', 'font/ttf'],
  [0L, 'string', '=', 'LWFN', 'font/type1'],
  [65L, 'string', '=', 'LWFN', 'font/type1'],
  [0L, 'string', '=', 'PACT', 'Macintosh Compact Pro Archive (data)'],
  [65L, 'string', '=', 'PACT', 'Macintosh Compact Pro Archive(rsrc + data)'],
  [0L, 'string', '=', 'ttro', 'Macintosh TeachText File (data)'],
  [65L, 'string', '=', 'ttro', 'Macintosh TeachText File(rsrc + data)'],
  [0L, 'string', '=', 'TEXT', 'Macintosh TeachText File (data)'],
  [65L, 'string', '=', 'TEXT', 'Macintosh TeachText File(rsrc + data)'],
  [0L, 'string', '=', 'PDF', 'Macintosh PDF File (data)'],
  [65L, 'string', '=', 'PDF', 'Macintosh PDF File(rsrc + data)'],
  [0L, 'string', '=', '# Magic', 'magic text file for file(1) cmd'],
  [0L, 'string', '=', 'Relay-Version:', 'old news text'],
  [0L, 'string', '=', '#! rnews', 'batched news text'],
  [0L, 'string', '=', 'N#! rnews', 'mailed, batched news text'],
  [0L, 'string', '=', 'Forward to', 'mail forwarding text'],
  [0L, 'string', '=', 'Pipe to', 'mail piping text'],
  [0L, 'string', '=', 'Return-Path:', 'message/rfc822'],
  [0L, 'string', '=', 'Path:', 'message/news'],
  [0L, 'string', '=', 'Xref:', 'message/news'],
  [0L, 'string', '=', 'From:', 'message/rfc822'],
  [0L, 'string', '=', 'Article', 'message/news'],
  [0L, 'string', '=', 'BABYL', 'message/x-gnu-rmail'],
  [0L, 'string', '=', 'Received:', 'message/rfc822'],
  [0L, 'string', '=', 'MIME-Version:', 'MIME entity text'],
  [0L, 'string', '=', 'Content-Type: ', ''],
  [0L, 'string', '=', 'Content-Type:', ''],
  [0L, 'long', '=', 31415L, 'Mirage Assembler m.out executable'],
  [0L, 'string', '=', '\311\304', 'ID tags data'],
  [0L, 'string', '=', '\001\001\001\001', 'MMDF mailbox'],
  [4L, 'string', '=', 'Research,', 'Digifax-G3-File'],
  [0L, 'short', '=', 256L, 'raw G3 data, byte-padded'],
  [0L, 'short', '=', 5120L, 'raw G3 data'],
  [0L, 'string', '=', 'RMD1', 'raw modem data'],
  [0L, 'string', '=', 'PVF1\012', 'portable voice format'],
  [0L, 'string', '=', 'PVF2\012', 'portable voice format'],
  [0L, 'beshort', '=', 520L, 'mc68k COFF'],
  [0L, 'beshort', '=', 521L, 'mc68k executable (shared)'],
  [0L, 'beshort', '=', 522L, 'mc68k executable (shared demand paged)'],
  [0L, 'beshort', '=', 554L, '68K BCS executable'],
  [0L, 'beshort', '=', 555L, '88K BCS executable'],
  [0L, 'string', '=', 'S0', 'Motorola S-Record; binary data in text format'],
  [0L, 'string', '=', '@echo off', 'MS-DOS batch file text'],
  [128L, 'string', '=', 'PE\000\000', 'MS Windows PE'],
  [0L, 'leshort', '=', 332L, 'MS Windows COFF Intel 80386 object file'],
  [0L, 'leshort', '=', 358L, 'MS Windows COFF MIPS R4000 object file'],
  [0L, 'leshort', '=', 388L, 'MS Windows COFF Alpha object file'],
  [0L, 'leshort', '=', 616L, 'MS Windows COFF Motorola 68000 object file'],
  [0L, 'leshort', '=', 496L, 'MS Windows COFF PowerPC object file'],
  [0L, 'leshort', '=', 656L, 'MS Windows COFF PA-RISC object file'],
  [0L, 'string', '=', 'MZ', 'application/x-ms-dos-executable'],
  [0L, 'string', '=', 'LZ', 'MS-DOS executable (built-in)'],
  [0L, 'string', '=', 'regf', 'Windows NT Registry file'],
  [2080L, 'string', '=', 'Microsoft Word 6.0 Document', 'text/vnd.ms-word'],
  [2080L, 'string', '=', 'Documento Microsoft Word 6', 'text/vnd.ms-word'],
  [2112L, 'string', '=', 'MSWordDoc', 'text/vnd.ms-word'],
  [0L, 'belong', '=', 834535424L, 'text/vnd.ms-word'],
  [0L, 'string', '=', 'PO^Q`', 'text/vnd.ms-word'],
  [2080L, 'string', '=', 'Microsoft Excel 5.0 Worksheet', 'application/vnd.ms-excel'],
  [2114L, 'string', '=', 'Biff5', 'application/vnd.ms-excel'],
  [0L, 'belong', '=', 6656L, 'Lotus 1-2-3'],
  [0L, 'belong', '=', 512L, 'Lotus 1-2-3'],
  [1L, 'string', '=', 'WPC', 'text/vnd.wordperfect'],
  [0L, 'beshort', '=', 610L, 'Tower/XP rel 2 object'],
  [0L, 'beshort', '=', 615L, 'Tower/XP rel 2 object'],
  [0L, 'beshort', '=', 620L, 'Tower/XP rel 3 object'],
  [0L, 'beshort', '=', 625L, 'Tower/XP rel 3 object'],
  [0L, 'beshort', '=', 630L, 'Tower32/600/400 68020 object'],
  [0L, 'beshort', '=', 640L, 'Tower32/800 68020'],
  [0L, 'beshort', '=', 645L, 'Tower32/800 68010'],
  [0L, 'lelong', '=', 407L, 'NetBSD little-endian object file'],
  [0L, 'belong', '=', 407L, 'NetBSD big-endian object file'],
  [0L, 'belong&0377777777', '=', 41400413L, 'NetBSD/i386 demand paged'],
  [0L, 'belong&0377777777', '=', 41400410L, 'NetBSD/i386 pure'],
  [0L, 'belong&0377777777', '=', 41400407L, 'NetBSD/i386'],
  [0L, 'belong&0377777777', '=', 41400507L, 'NetBSD/i386 core'],
  [0L, 'belong&0377777777', '=', 41600413L, 'NetBSD/m68k demand paged'],
  [0L, 'belong&0377777777', '=', 41600410L, 'NetBSD/m68k pure'],
  [0L, 'belong&0377777777', '=', 41600407L, 'NetBSD/m68k'],
  [0L, 'belong&0377777777', '=', 41600507L, 'NetBSD/m68k core'],
  [0L, 'belong&0377777777', '=', 42000413L, 'NetBSD/m68k4k demand paged'],
  [0L, 'belong&0377777777', '=', 42000410L, 'NetBSD/m68k4k pure'],
  [0L, 'belong&0377777777', '=', 42000407L, 'NetBSD/m68k4k'],
  [0L, 'belong&0377777777', '=', 42000507L, 'NetBSD/m68k4k core'],
  [0L, 'belong&0377777777', '=', 42200413L, 'NetBSD/ns32532 demand paged'],
  [0L, 'belong&0377777777', '=', 42200410L, 'NetBSD/ns32532 pure'],
  [0L, 'belong&0377777777', '=', 42200407L, 'NetBSD/ns32532'],
  [0L, 'belong&0377777777', '=', 42200507L, 'NetBSD/ns32532 core'],
  [0L, 'belong&0377777777', '=', 42400413L, 'NetBSD/sparc demand paged'],
  [0L, 'belong&0377777777', '=', 42400410L, 'NetBSD/sparc pure'],
  [0L, 'belong&0377777777', '=', 42400407L, 'NetBSD/sparc'],
  [0L, 'belong&0377777777', '=', 42400507L, 'NetBSD/sparc core'],
  [0L, 'belong&0377777777', '=', 42600413L, 'NetBSD/pmax demand paged'],
  [0L, 'belong&0377777777', '=', 42600410L, 'NetBSD/pmax pure'],
  [0L, 'belong&0377777777', '=', 42600407L, 'NetBSD/pmax'],
  [0L, 'belong&0377777777', '=', 42600507L, 'NetBSD/pmax core'],
  [0L, 'belong&0377777777', '=', 43000413L, 'NetBSD/vax demand paged'],
  [0L, 'belong&0377777777', '=', 43000410L, 'NetBSD/vax pure'],
  [0L, 'belong&0377777777', '=', 43000407L, 'NetBSD/vax'],
  [0L, 'belong&0377777777', '=', 43000507L, 'NetBSD/vax core'],
  [0L, 'lelong', '=', 459141L, 'ECOFF NetBSD/alpha binary'],
  [0L, 'belong&0377777777', '=', 43200507L, 'NetBSD/alpha core'],
  [0L, 'belong&0377777777', '=', 43400413L, 'NetBSD/mips demand paged'],
  [0L, 'belong&0377777777', '=', 43400410L, 'NetBSD/mips pure'],
  [0L, 'belong&0377777777', '=', 43400407L, 'NetBSD/mips'],
  [0L, 'belong&0377777777', '=', 43400507L, 'NetBSD/mips core'],
  [0L, 'belong&0377777777', '=', 43600413L, 'NetBSD/arm32 demand paged'],
  [0L, 'belong&0377777777', '=', 43600410L, 'NetBSD/arm32 pure'],
  [0L, 'belong&0377777777', '=', 43600407L, 'NetBSD/arm32'],
  [0L, 'belong&0377777777', '=', 43600507L, 'NetBSD/arm32 core'],
  [0L, 'string', '=', 'StartFontMetrics', 'font/x-sunos-news'],
  [0L, 'string', '=', 'StartFont', 'font/x-sunos-news'],
  [0L, 'belong', '=', 326773060L, 'font/x-sunos-news'],
  [0L, 'belong', '=', 326773063L, 'font/x-sunos-news'],
  [0L, 'belong', '=', 326773072L, 'font/x-sunos-news'],
  [0L, 'belong', '=', 326773073L, 'font/x-sunos-news'],
  [8L, 'belong', '=', 326773573L, 'font/x-sunos-news'],
  [8L, 'belong', '=', 326773576L, 'font/x-sunos-news'],
  [0L, 'string', '=', 'Octave-1-L', 'Octave binary data (little endian)'],
  [0L, 'string', '=', 'Octave-1-B', 'Octave binary data (big endian)'],
  [0L, 'string', '=', '\177OLF', 'OLF'],
  [0L, 'beshort', '=', 34765L, 'OS9/6809 module:'],
  [0L, 'beshort', '=', 19196L, 'OS9/68K module:'],
  [0L, 'long', '=', 61374L, 'OSF/Rose object'],
  [0L, 'short', '=', 565L, 'i386 COFF object'],
  [0L, 'short', '=', 10775L, '"compact bitmap" format (Poskanzer)'],
  [0L, 'string', '=', '%PDF-', 'PDF document'],
  [0L, 'lelong', '=', 101555L, 'PDP-11 single precision APL workspace'],
  [0L, 'lelong', '=', 101554L, 'PDP-11 double precision APL workspace'],
  [0L, 'leshort', '=', 407L, 'PDP-11 executable'],
  [0L, 'leshort', '=', 401L, 'PDP-11 UNIX/RT ldp'],
  [0L, 'leshort', '=', 405L, 'PDP-11 old overlay'],
  [0L, 'leshort', '=', 410L, 'PDP-11 pure executable'],
  [0L, 'leshort', '=', 411L, 'PDP-11 separate I&D executable'],
  [0L, 'leshort', '=', 437L, 'PDP-11 kernel overlay'],
  [0L, 'beshort', '=', 39168L, 'PGP key public ring'],
  [0L, 'beshort', '=', 38145L, 'PGP key security ring'],
  [0L, 'beshort', '=', 38144L, 'PGP key security ring'],
  [0L, 'beshort', '=', 42496L, 'PGP encrypted data'],
  [0L, 'string', '=', '-----BEGIN PGP', 'PGP armored data'],
  [0L, 'string', '=', '# PaCkAgE DaTaStReAm', 'pkg Datastream (SVR4)'],
  [0L, 'short', '=', 601L, 'mumps avl global'],
  [0L, 'short', '=', 602L, 'mumps blt global'],
  [0L, 'string', '=', '%!', 'application/postscript'],
  [0L, 'string', '=', '\004%!', 'application/postscript'],
  [0L, 'belong', '=', 3318797254L, 'DOS EPS Binary File'],
  [0L, 'string', '=', '*PPD-Adobe:', 'PPD file'],
  [0L, 'string', '=', '\033%-12345X@PJL', 'HP Printer Job Language data'],
  [0L, 'string', '=', '\033%-12345X@PJL', 'HP Printer Job Language data'],
  [0L, 'string', '=', '\033E\033', 'image/x-pcl-hp'],
  [0L, 'string', '=', '@document(', 'Imagen printer'],
  [0L, 'string', '=', 'Rast', 'RST-format raster font data'],
  [0L, 'belong&0xff00ffff', '=', 1442840576L, 'ps database'],
  [0L, 'long', '=', 1351614727L, 'Pyramid 90x family executable'],
  [0L, 'long', '=', 1351614728L, 'Pyramid 90x family pure executable'],
  [0L, 'long', '=', 1351614731L, 'Pyramid 90x family demand paged pure executable'],
  [0L, 'beshort', '=', 60843L, ''],
  [0L, 'string', '=', '{\\\\rtf', 'Rich Text Format data,'],
  [38L, 'string', '=', 'Spreadsheet', 'sc spreadsheet file'],
  [8L, 'string', '=', '\001s SCCS', 'archive data'],
  [0L, 'byte', '=', 46L, 'Sendmail frozen configuration'],
  [0L, 'short', '=', 10012L, 'Sendmail frozen configuration'],
  [0L, 'lelong', '=', 234L, 'BALANCE NS32000 .o'],
  [0L, 'lelong', '=', 4330L, 'BALANCE NS32000 executable (0 @ 0)'],
  [0L, 'lelong', '=', 8426L, 'BALANCE NS32000 executable (invalid @ 0)'],
  [0L, 'lelong', '=', 12522L, 'BALANCE NS32000 standalone executable'],
  [0L, 'leshort', '=', 4843L, 'SYMMETRY i386 .o'],
  [0L, 'leshort', '=', 8939L, 'SYMMETRY i386 executable (0 @ 0)'],
  [0L, 'leshort', '=', 13035L, 'SYMMETRY i386 executable (invalid @ 0)'],
  [0L, 'leshort', '=', 17131L, 'SYMMETRY i386 standalone executable'],
  [0L, 'string', '=', 'kbd!map', 'kbd map file'],
  [0L, 'belong', '=', 407L, 'old SGI 68020 executable'],
  [0L, 'belong', '=', 410L, 'old SGI 68020 pure executable'],
  [0L, 'beshort', '=', 34661L, 'disk quotas file'],
  [0L, 'beshort', '=', 1286L, 'IRIS Showcase file'],
  [0L, 'beshort', '=', 550L, 'IRIS Showcase template'],
  [0L, 'belong', '=', 1396917837L, 'IRIS Showcase file'],
  [0L, 'belong', '=', 1413695053L, 'IRIS Showcase template'],
  [0L, 'belong', '=', 3735927486L, 'IRIX Parallel Arena'],
  [0L, 'beshort', '=', 352L, 'MIPSEB COFF executable'],
  [0L, 'beshort', '=', 354L, 'MIPSEL COFF executable'],
  [0L, 'beshort', '=', 24577L, 'MIPSEB-LE COFF executable'],
  [0L, 'beshort', '=', 25089L, 'MIPSEL-LE COFF executable'],
  [0L, 'beshort', '=', 355L, 'MIPSEB MIPS-II COFF executable'],
  [0L, 'beshort', '=', 358L, 'MIPSEL MIPS-II COFF executable'],
  [0L, 'beshort', '=', 25345L, 'MIPSEB-LE MIPS-II COFF executable'],
  [0L, 'beshort', '=', 26113L, 'MIPSEL-LE MIPS-II COFF executable'],
  [0L, 'beshort', '=', 320L, 'MIPSEB MIPS-III COFF executable'],
  [0L, 'beshort', '=', 322L, 'MIPSEL MIPS-III COFF executable'],
  [0L, 'beshort', '=', 16385L, 'MIPSEB-LE MIPS-III COFF executable'],
  [0L, 'beshort', '=', 16897L, 'MIPSEL-LE MIPS-III COFF executable'],
  [0L, 'beshort', '=', 384L, 'MIPSEB Ucode'],
  [0L, 'beshort', '=', 386L, 'MIPSEL Ucode'],
  [0L, 'belong', '=', 3735924144L, 'IRIX core dump'],
  [0L, 'belong', '=', 3735924032L, 'IRIX 64-bit core dump'],
  [0L, 'belong', '=', 3133063355L, 'IRIX N32 core dump'],
  [0L, 'string', '=', 'CrshDump', 'IRIX vmcore dump of'],
  [0L, 'string', '=', 'SGIAUDIT', 'SGI Audit file'],
  [0L, 'string', '=', 'WNGZWZSC', 'Wingz compiled script'],
  [0L, 'string', '=', 'WNGZWZSS', 'Wingz spreadsheet'],
  [0L, 'string', '=', 'WNGZWZHP', 'Wingz help file'],
  [0L, 'string', '=', '\\#Inventor', 'V IRIS Inventor 1.0 file'],
  [0L, 'string', '=', '\\#Inventor', 'V2 Open Inventor 2.0 file'],
  [0L, 'string', '=', 'glfHeadMagic();', 'GLF_TEXT'],
  [4L, 'belong', '=', 1090584576L, 'GLF_BINARY_LSB_FIRST'],
  [4L, 'belong', '=', 321L, 'GLF_BINARY_MSB_FIRST'],
  [0L, 'string', '=', '<!DOCTYPE HTML', 'text/html'],
  [0L, 'string', '=', '<!doctype html', 'text/html'],
  [0L, 'string', '=', '<HEAD', 'text/html'],
  [0L, 'string', '=', '<head', 'text/html'],
  [0L, 'string', '=', '<TITLE', 'text/html'],
  [0L, 'string', '=', '<title', 'text/html'],
  [0L, 'string', '=', '<html', 'text/html'],
  [0L, 'string', '=', '<HTML', 'text/html'],
  [0L, 'string', '=', '<!DOCTYPE', 'exported SGML document text'],
  [0L, 'string', '=', '<!doctype', 'exported SGML document text'],
  [0L, 'string', '=', '<!SUBDOC', 'exported SGML subdocument text'],
  [0L, 'string', '=', '<!subdoc', 'exported SGML subdocument text'],
  [0L, 'string', '=', '<!--', 'exported SGML document text'],
  [0L, 'string', '=', 'RTSS', 'NetMon capture file'],
  [0L, 'string', '=', 'TRSNIFF data    \032', 'Sniffer capture file'],
  [0L, 'string', '=', 'XCP\000', 'NetXRay capture file'],
  [0L, 'ubelong', '=', 2712847316L, 'tcpdump capture file (big-endian)'],
  [0L, 'ulelong', '=', 2712847316L, 'tcpdump capture file (little-endian)'],
  [0L, 'string', '=', '<!SQ DTD>', 'Compiled SGML rules file'],
  [0L, 'string', '=', '<!SQ A/E>', 'A/E SGML Document binary'],
  [0L, 'string', '=', '<!SQ STS>', 'A/E SGML binary styles file'],
  [0L, 'short', '=', 49374L, 'Compiled PSI (v1) data'],
  [0L, 'short', '=', 49370L, 'Compiled PSI (v2) data'],
  [0L, 'short', '=', 125252L, 'SoftQuad DESC or font file binary'],
  [0L, 'string', '=', 'SQ BITMAP1', 'SoftQuad Raster Format text'],
  [0L, 'string', '=', 'X SoftQuad', 'troff Context intermediate'],
  [0L, 'belong&077777777', '=', 600413L, 'sparc demand paged'],
  [0L, 'belong&077777777', '=', 600410L, 'sparc pure'],
  [0L, 'belong&077777777', '=', 600407L, 'sparc'],
  [0L, 'belong&077777777', '=', 400413L, 'mc68020 demand paged'],
  [0L, 'belong&077777777', '=', 400410L, 'mc68020 pure'],
  [0L, 'belong&077777777', '=', 400407L, 'mc68020'],
  [0L, 'belong&077777777', '=', 200413L, 'mc68010 demand paged'],
  [0L, 'belong&077777777', '=', 200410L, 'mc68010 pure'],
  [0L, 'belong&077777777', '=', 200407L, 'mc68010'],
  [0L, 'belong', '=', 407L, 'old sun-2 executable'],
  [0L, 'belong', '=', 410L, 'old sun-2 pure executable'],
  [0L, 'belong', '=', 413L, 'old sun-2 demand paged executable'],
  [0L, 'belong', '=', 525398L, 'SunOS core file'],
  [0L, 'long', '=', 4197695630L, 'SunPC 4.0 Hard Disk'],
  [0L, 'string', '=', '#SUNPC_CONFIG', 'SunPC 4.0 Properties Values'],
  [0L, 'string', '=', 'snoop', 'Snoop capture file'],
  [36L, 'string', '=', 'acsp', 'Kodak Color Management System, ICC Profile'],
  [0L, 'string', '=', '#!teapot\012xdr', 'teapot work sheet (XDR format)'],
  [0L, 'string', '=', '\032\001', 'Compiled terminfo entry'],
  [0L, 'short', '=', 433L, 'Curses screen image'],
  [0L, 'short', '=', 434L, 'Curses screen image'],
  [0L, 'string', '=', '\367\002', 'TeX DVI file'],
  [0L, 'string', '=', '\367\203', 'font/x-tex'],
  [0L, 'string', '=', '\367Y', 'font/x-tex'],
  [0L, 'string', '=', '\367\312', 'font/x-tex'],
  [0L, 'string', '=', 'This is TeX,', 'TeX transcript text'],
  [0L, 'string', '=', 'This is METAFONT,', 'METAFONT transcript text'],
  [2L, 'string', '=', '\000\021', 'font/x-tex-tfm'],
  [2L, 'string', '=', '\000\022', 'font/x-tex-tfm'],
  [0L, 'string', '=', '\\\\input\\', 'texinfo Texinfo source text'],
  [0L, 'string', '=', 'This is Info file', 'GNU Info text'],
  [0L, 'string', '=', '\\\\input', 'TeX document text'],
  [0L, 'string', '=', '\\\\section', 'LaTeX document text'],
  [0L, 'string', '=', '\\\\setlength', 'LaTeX document text'],
  [0L, 'string', '=', '\\\\documentstyle', 'LaTeX document text'],
  [0L, 'string', '=', '\\\\chapter', 'LaTeX document text'],
  [0L, 'string', '=', '\\\\documentclass', 'LaTeX 2e document text'],
  [0L, 'string', '=', '\\\\relax', 'LaTeX auxiliary file'],
  [0L, 'string', '=', '\\\\contentsline', 'LaTeX table of contents'],
  [0L, 'string', '=', '\\\\indexentry', 'LaTeX raw index file'],
  [0L, 'string', '=', '\\\\begin{theindex}', 'LaTeX sorted index'],
  [0L, 'string', '=', '\\\\glossaryentry', 'LaTeX raw glossary'],
  [0L, 'string', '=', '\\\\begin{theglossary}', 'LaTeX sorted glossary'],
  [0L, 'string', '=', 'This is makeindex', 'Makeindex log file'],
  [0L, 'string', '=', '**TI82**', 'TI-82 Graphing Calculator'],
  [0L, 'string', '=', '**TI83**', 'TI-83 Graphing Calculator'],
  [0L, 'string', '=', '**TI85**', 'TI-85 Graphing Calculator'],
  [0L, 'string', '=', '**TI92**', 'TI-92 Graphing Calculator'],
  [0L, 'string', '=', '**TI80**', 'TI-80 Graphing Calculator File.'],
  [0L, 'string', '=', '**TI81**', 'TI-81 Graphing Calculator File.'],
  [0L, 'string', '=', 'TZif', 'timezone data'],
  [0L, 'string', '=', '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001\000', 'old timezone data'],
  [0L, 'string', '=', '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\002\000', 'old timezone data'],
  [0L, 'string', '=', '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\003\000', 'old timezone data'],
  [0L, 'string', '=', '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\004\000', 'old timezone data'],
  [0L, 'string', '=', '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\005\000', 'old timezone data'],
  [0L, 'string', '=', '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\006\000', 'old timezone data'],
  [0L, 'string', '=', '.\\\\"', 'troff or preprocessor input text'],
  [0L, 'string', '=', '\'\\\\"', 'troff or preprocessor input text'],
  [0L, 'string', '=', '\'.\\\\"', 'troff or preprocessor input text'],
  [0L, 'string', '=', '\\\\"', 'troff or preprocessor input text'],
  [0L, 'string', '=', 'x T', 'ditroff text'],
  [0L, 'string', '=', '@\357', 'very old (C/A/T) troff output data'],
  [0L, 'string', '=', 'Interpress/Xerox', 'Xerox InterPress data'],
  [0L, 'short', '=', 263L, 'unknown machine executable'],
  [0L, 'short', '=', 264L, 'unknown pure executable'],
  [0L, 'short', '=', 265L, 'PDP-11 separate I&D'],
  [0L, 'short', '=', 267L, 'unknown pure executable'],
  [0L, 'long', '=', 268L, 'unknown demand paged pure executable'],
  [0L, 'long', '=', 269L, 'unknown demand paged pure executable'],
  [0L, 'long', '=', 270L, 'unknown readable demand paged pure executable'],
  [0L, 'string', '=', 'begin uuencoded', 'or xxencoded text'],
  [0L, 'string', '=', 'xbtoa Begin', "btoa'd text"],
  [0L, 'string', '=', '$\012ship', "ship'd binary text"],
  [0L, 'string', '=', 'Decode the following with bdeco', 'bencoded News text'],
  [11L, 'string', '=', 'must be converted with BinHex', 'BinHex binary text'],
  [0L, 'short', '=', 610L, 'Perkin-Elmer executable'],
  [0L, 'beshort', '=', 572L, 'amd 29k coff noprebar executable'],
  [0L, 'beshort', '=', 1572L, 'amd 29k coff prebar executable'],
  [0L, 'beshort', '=', 160007L, 'amd 29k coff archive'],
  [6L, 'beshort', '=', 407L, 'unicos (cray) executable'],
  [596L, 'string', '=', 'X\337\377\377', 'Ultrix core file'],
  [0L, 'string', '=', 'Joy!peffpwpc', 'header for PowerPC PEF executable'],
  [0L, 'lelong', '=', 101557L, 'VAX single precision APL workspace'],
  [0L, 'lelong', '=', 101556L, 'VAX double precision APL workspace'],
  [0L, 'lelong', '=', 407L, 'VAX executable'],
  [0L, 'lelong', '=', 410L, 'VAX pure executable'],
  [0L, 'lelong', '=', 413L, 'VAX demand paged pure executable'],
  [0L, 'leshort', '=', 570L, 'VAX COFF executable'],
  [0L, 'leshort', '=', 575L, 'VAX COFF pure executable'],
  [0L, 'string', '=', 'LBLSIZE=', 'VICAR image data'],
  [43L, 'string', '=', 'SFDU_LABEL', 'VICAR label file'],
  [0L, 'short', '=', 21845L, 'VISX image file'],
  [0L, 'string', '=', '\260\0000\000', 'VMS VAX executable'],
  [0L, 'belong', '=', 50331648L, 'VMS Alpha executable'],
  [1L, 'string', '=', 'WPC', '(Corel/WP)'],
  [0L, 'string', '=', 'core', 'core file (Xenix)'],
  [0L, 'byte', '=', 128L, '8086 relocatable (Microsoft)'],
  [0L, 'leshort', '=', 65381L, 'x.out'],
  [0L, 'leshort', '=', 518L, 'Microsoft a.out'],
  [0L, 'leshort', '=', 320L, 'old Microsoft 8086 x.out'],
  [0L, 'lelong', '=', 518L, 'b.out'],
  [0L, 'leshort', '=', 1408L, 'XENIX 8086 relocatable or 80286 small model'],
  [0L, 'long', '=', 59399L, 'object file (z8000 a.out)'],
  [0L, 'long', '=', 59400L, 'pure object file (z8000 a.out)'],
  [0L, 'long', '=', 59401L, 'separate object file (z8000 a.out)'],
  [0L, 'long', '=', 59397L, 'overlay object file (z8000 a.out)'],
  [0L, 'string', '=', 'ZyXEL\002', 'ZyXEL voice data'],
]

magicNumbers = []

def strToNum(n):
  val = 0
  col = long(1)
  if n[:1] == 'x': n = '0' + n
  if n[:2] == '0x':
    # hex
    n = string.lower(n[2:])
    while len(n) > 0:
      l = n[len(n) - 1]
      val = val + string.hexdigits.index(l) * col
      col = col * 16
      n = n[:len(n)-1]
  elif n[0] == '\\':
    # octal
    n = n[1:]
    while len(n) > 0:
      l = n[len(n) - 1]
      if ord(l) < 48 or ord(l) > 57: break
      val = val + int(l) * col
      col = col * 8
      n = n[:len(n)-1]
  else:
    val = string.atol(n)
  return val
       
def unescape(s):
  # replace string escape sequences
  while 1:
    m = re.search(r'\\', s)
    if not m: break
    x = m.start()+1
    if m.end() == len(s): 
      # escaped space at end
      s = s[:len(s)-1] + ' '
    elif s[x:x+2] == '0x':
      # hex ascii value
      c = chr(strToNum(s[x:x+4]))
      s = s[:x-1] + c + s[x+4:]
    elif s[m.start()+1] == 'x':
      # hex ascii value
      c = chr(strToNum(s[x:x+3]))
      s = s[:x-1] + c + s[x+3:]
    elif ord(s[x]) > 47 and ord(s[x]) < 58:
      # octal ascii value
      end = x
      while (ord(s[end]) > 47 and ord(s[end]) < 58):
        end = end + 1
        if end > len(s) - 1: break
      c = chr(strToNum(s[x-1:end]))
      s = s[:x-1] + c + s[end:]
    elif s[x] == 'n':
      # newline
      s = s[:x-1] + '\n' + s[x+1:]
    else:
      break
  return s

class magicTest:
  def __init__(self, offset, t, op, value, msg, mask = None):
    if t.count('&') > 0:
      mask = strToNum(t[t.index('&')+1:])  
      t = t[:t.index('&')]
    if type(offset) == type('a'):
      self.offset = strToNum(offset)
    else:
      self.offset = offset
    self.type = t
    self.msg = msg
    self.subTests = []
    self.op = op
    self.mask = mask
    self.value = value
      

  def test(self, data):
    if self.mask:
      data = data & self.mask
    if self.op == '=': 
      if self.value == data: return self.msg
    elif self.op ==  '<':
      pass
    elif self.op ==  '>':
      pass
    elif self.op ==  '&':
      pass
    elif self.op ==  '^':
      pass
    return None

  def compare(self, data):
    #print str([self.type, self.value, self.msg])
    try: 
      if self.type == 'string':
        c = ''; s = ''
        for i in range(0, len(self.value)+1):
          if i + self.offset > len(data) - 1: break
          s = s + c
          [c] = struct.unpack('c', data[self.offset + i])
        data = s
      elif self.type == 'short':
        [data] = struct.unpack('h', data[self.offset : self.offset + 2])
      elif self.type == 'leshort':
        [data] = struct.unpack('<h', data[self.offset : self.offset + 2])
      elif self.type == 'beshort':
        [data] = struct.unpack('>H', data[self.offset : self.offset + 2])
      elif self.type == 'long':
        [data] = struct.unpack('l', data[self.offset : self.offset + 4])
      elif self.type == 'lelong':
        [data] = struct.unpack('<l', data[self.offset : self.offset + 4])
      elif self.type == 'belong':
        [data] = struct.unpack('>l', data[self.offset : self.offset + 4])
      else:
        #print 'UNKNOWN TYPE: ' + self.type
        pass
    except:
      return None
  
#    print str([self.msg, self.value, data])
    return self.test(data)
    

def load(file):
  global magicNumbers
  lines = open(file).readlines()
  last = { 0: None }
  for line in lines:
    if re.match(r'\s*#', line):
      # comment
      continue
    else:
      # split up by space delimiters, and remove trailing space
      line = string.rstrip(line)
      line = re.split(r'\s*', line)
      if len(line) < 3:
        # bad line
        continue
      offset = line[0]
      type = line[1]
      value = line[2]
      level = 0
      while offset[0] == '>':
        # count the level of the type
        level = level + 1
        offset = offset[1:]
      l = magicNumbers
      if level > 0:
        l = last[level - 1].subTests
      if offset[0] == '(':
        # don't handle indirect offsets just yet
        print 'SKIPPING ' + string.join(list(line[3:]))
        pass
      elif offset[0] == '&':
        # don't handle relative offsets just yet
        print 'SKIPPING ' + string.join(list(line[3:]))
        pass
      else:
        operands = ['=', '<', '>', '&']
        if operands.count(value[0]) > 0:
          # a comparison operator is specified
          op = value[0] 
          value = value[1:]
        else:
          print str([value, operands])
          if len(value) >1 and value[0] == '\\' and operands.count(value[1]) >0:
            # literal value that collides with operands is escaped
            value = value[1:]
          op = '='

        mask = None
        if type == 'string':
          while 1:
            value = unescape(value)
            if value[len(value)-1] == ' ' and len(line) > 3:
              # last value was an escaped space, join
              value = value + line[3]
              del line[3]
            else:
              break
        else:
          if value.count('&') != 0:
            mask = value[(value.index('&') + 1):]
            print 'MASK: ' + mask
            value = value[:(value.index('&')+1)]
          try: value = strToNum(value)
          except: continue
          msg = string.join(list(line[3:]))
        new = magicTest(offset, type, op, value, msg, mask)
        last[level] = new
        l.append(new)

def whatis(data):
  for test in magicNumbers:
     m = test.compare(data)
     if m: return m
  # no matching, magic number. is it binary or text?
  for c in data:
    if ord(c) > 128:
      return 'data'
  # its ASCII, now do text tests
  if string.find('The', data, 0, 8192) > -1:
    return 'English text'
  if string.find('def', data, 0, 8192) > -1:
    return 'Python Source'
  return 'ASCII text'
      
    
def file(file):
  try:
    return whatis(open(file, 'r').read(8192))
  except Exception, e:
    if str(e) == '[Errno 21] Is a directory':
      return 'directory'
    else:
      raise e
  

#### BUILD DATA ####
#load('mime-magic')
#f = open('out', 'w')
#for m in magicNumbers:
#  f.write(str([m.offset, m.type, m.op, m.value, m.msg]) + ',\n')
#f.close

import sys
for m in magic:
  magicNumbers.append(magicTest(m[0], m[1], m[2], m[3], m[4]))

if __name__ == '__main__':
  import sys
  for arg in sys.argv[1:]:
    msg = file(arg)
    if msg:
      print arg + ': ' + msg
    else:
      print arg + ': unknown'
