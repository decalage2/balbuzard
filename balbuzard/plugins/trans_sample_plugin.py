# This is a sample transform plugin script for bbcrack

# All transform plugin scripts need to be named trans*.py, in the plugins folder
# Each plugin script should add Transform objects.

# First define a new Transform class, inheriting either from Transform_char or
# Transform_str:

##class Transform_SAMPLEXOR (Transform_char):
##    """
##    sample XOR Transform
##    """
##    # generic name for the class:
##    gen_name = 'SAMPLE XOR with 8 bits static key A. Parameters: A (1-FF).'
##    gen_id   = 'samplexor'
##
##    def __init__(self, params):
##        assert isinstance(params, int)
##        assert params>0 and params<256
##        self.params = params
##        self.name = "Sample XOR %02X" % params
##        self.shortname = "samplexor%02X" % params
##
##    def transform_char (self, char):
##        # here params is an integer
##        return chr(ord(char) ^ self.params)
##
##    @staticmethod
##    def iter_params ():
##        # the XOR key can be 1 to 255 (0 would be identity)
##        for key in xrange(1,256):
##            yield key

# Second, add it to the proper level:
# - level 1 for fast transform with up to 2000 iterations (e.g. xor, xor+rol)
# - level 2 for slower transforms or more iteration (e.g. xor+add)
# - level 3 for slow or infrequent transforms

##add_transform(Transform_SAMPLEXOR, level=1)

# see bbcrack.py and the Transform classes for more options.
