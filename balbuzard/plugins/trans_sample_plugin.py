# This is a sample transform plugin script for bbcrack

# All transform plugin scripts need to be named trans*.py, in the plugins folder
# Each plugin script should add Transform objects.

# First define a new Transform class, inheriting either from Transform_char or
# Transform_string:

# - Transform_char: for transforms that apply to each character/byte
#   independently, not depending on the location of the character.
#   (example: simple XOR)
# - Transform_string: for all other transforms, that may apply to several
#   characters at once, or taking into account the location of the character.
#   (example: XOR with increasing key)

# Transform_char is usually much faster because it uses a translation table.

# A class represents a generic transform (obfuscation algorithm), such as XOR
# or XOR+ROL.
# When the class is instantiated as an object, it includes the keys of the
# obfuscation algorithm, specified as parameters. (e.g. "XOR 4F" or "XOR 4F +
# ROL 3")

# For each transform class, you need to implement the following methods/variables:
# - a description and an short name for the transform
# - __init__() to store parameters
# - iter_params() to generate all the possible parameters for bruteforcing
# - transform_char() or transform_string() to apply the transform to a single
#   character or to the whole string at once.

# Then do not forget to add to the proper level 1, 2 or 3. (see below after
# class samples)

# If you develop useful plugin scripts and you would like me to reference them,
# or if you think about additional transforms that bbcrack should include,
# please contact me using this form: http://www.decalage.info/contact


# See below for three different examples:
# 1) Transform_char with single parameter
# 2) Transform_char with multiple parameters
# 3) Transform_string

#------------------------------------------------------------------------------
##class Transform_SAMPLE_XOR (Transform_char):
##    """
##    sample XOR Transform, single parameter
##    """
##    # Provide a description for the transform, and an id (short name for
##    # command line options):
##    gen_name = 'SAMPLE XOR with 8 bits static key A. Parameters: A (1-FF).'
##    gen_id   = 'samplexor'
##
##    # the __init__ method must store provided parameters and build the specific
##    # name and shortname of the transform with parameters
##    def __init__(self, params):
##        """
##        constructor for the Transform object.
##        This method needs to be overloaded for every specific Transform.
##        It should set name and shortname according to the provided parameters.
##        (for example shortname="xor_17" for a XOR transform with params=17)
##        params: single value or tuple of values, parameters for the transformation
##        """
##        self.params = params
##        self.name = "Sample XOR %02X" % params
##        # this shortname will be used to save bbcrack and bbtrans results to files
##        self.shortname = "samplexor%02X" % params
##
##    def transform_char (self, char):
##        """
##        Method to be overloaded, only for a transform that acts on a character.
##        This method should apply the transform to the provided char, using params
##        as parameters, and return the transformed data as a character.
##        (here character = string of length 1)
##
##        NOTE: here the algorithm can be slow, because it will only be used 256
##        times to build a translation table.
##        """
##        # here params is an integer
##        return chr(ord(char) ^ self.params)
##
##    @staticmethod
##    def iter_params ():
##        """
##        Method to be overloaded.
##        This static method should iterate over all possible parameters for the
##        transform function, yielding each set of parameters as a single value
##        or a tuple of values.
##        (for example for a XOR transform, it should yield 1 to 255)
##        This method should be used on the Transform class in order to
##        instantiate a Transform object with each set of parameters.
##        """
##        # the XOR key can be 1 to 255 (0 would be identity)
##        for key in xrange(1,256):
##            yield key

#------------------------------------------------------------------------------
##class Transform_SAMPLE_XOR_ROL (Transform_char):
##    """
##    Sample XOR+ROL Transform - multiple parameters
##    """
##    # generic name for the class:
##    gen_name = 'XOR with static 8 bits key A, then rotate B bits left. Parameters: A (1-FF), B (1-7).'
##    gen_id   = 'xor_rol'
##
##    def __init__(self, params):
##        # Here we assume that params is a tuple with two integers:
##        self.params = params
##        self.name = "XOR %02X then ROL %d" % params
##        self.shortname = "xor%02X_rol%d" % params
##
##    def transform_char (self, char):
##        # here params is a tuple
##        xor_key, rol_bits = self.params
##        return chr(rol(ord(char) ^ xor_key, rol_bits))
##
##    @staticmethod
##    def iter_params ():
##        "return (XOR key, ROL bits)"
##        # the XOR key can be 1 to 255 (0 would be like ROL)
##        for xor_key in xrange(1,256):
##            # the ROL bits can be 1 to 7:
##            for rol_bits in xrange(1,8):
##                # yield a tuple with XOR key and ROL bits:
##                yield (xor_key, rol_bits)

#------------------------------------------------------------------------------
##class Transform_SAMPLE_XOR_INC (Transform_string):
##    """
##    Sample XOR Transform, with incrementing key
##    (this kind of transform must be implemented as a Transform_string, because
##    it gives different results depending on the location of the character)
##    """
##    # generic name for the class:
##    gen_name = 'XOR with 8 bits key A incrementing after each character. Parameters: A (0-FF).'
##    gen_id   = 'xor_inc'
##
##    def __init__(self, params):
##        self.params = params
##        self.name = "XOR %02X INC" % params
##        self.shortname = "xor%02X_inc" % params
##
##    def transform_string (self, data):
##        """
##        Method to be overloaded, only for a transform that acts on a string
##        globally.
##        This method should apply the transform to the data string, using params
##        as parameters, and return the transformed data as a string.
##        (the resulting string does not need to have the same length as data)
##        """
##        # here params is an integer
##        out = ''
##        for i in xrange(len(data)):
##            xor_key = (self.params + i) & 0xFF
##            out += chr(ord(data[i]) ^ xor_key)
##        return out
##
##    @staticmethod
##    def iter_params ():
##        # the XOR key can be 0 to 255 (0 is not identity here)
##        for xor_key in xrange(0,256):
##            yield xor_key


#------------------------------------------------------------------------------

# Second, add it to the proper level:
# - level 1 for fast transform with up to 2000 iterations (e.g. xor, xor+rol)
# - level 2 for slower transforms or more iterations (e.g. xor+add)
# - level 3 for slow or infrequent transforms

##add_transform(Transform_SAMPLE_XOR, level=1)
##add_transform(Transform_SAMPLE_XOR_ROL, level=1)
##add_transform(Transform_SAMPLE_XOR_INC, level=2)


# see bbcrack.py and the Transform classes for more options.
