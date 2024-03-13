
class XmlParseError(Exception):
    """An exception that occurs due to an improperly formatted XML of an OpenIOC file"""


class OpenIOCSemanticError(Exception):
    """An unknown or unsupported OpenIoC tag or term was provided"""

class UnsupportedDataType(Exception):
    """Provided data type is unsupported as of now"""

class UnsupportedOpenIocTerm(Exception):
    """Provided term is not supported as of now"""
