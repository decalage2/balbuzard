# This is a sample plugin script for Balbuzard

# All plugin scripts need to be named bbz*.py, in the plugins folder
# Each plugin script should add a list of Pattern objects to the patterns list:

patterns += [

    # example: a pattern with a simple case-sensitive string
    #Pattern("EXE PE DOS message", "This program cannot be run in DOS mode"),

    # example: a pattern with a simple case-INsensitive string
    #Pattern("EXE PE DOS message", "This program cannot be run in DOS mode", nocase=True),

    # example: a pattern with a list of strings
    #Pattern("EXE: section name", [".text", ".data", ".rdata", ".rsrc"])

    # example: a pattern with a regular expression
    #Pattern_re("IP address", r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"),

    # example: a pattern with a regular expression, case-insensitive
    #Pattern_re("Executable filename", r"\w+\.(EXE|COM|VBS|JS|VBE|JSE|BAT|CMD|DLL|SCR)", nocase=True),

    ]

# see balbuzard.py and the Pattern classes for more options.