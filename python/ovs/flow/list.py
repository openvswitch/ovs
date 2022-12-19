import re

from ovs.flow.kv import KeyValue, KeyMetadata, ParseError
from ovs.flow.decoders import decode_default


class ListDecoders(object):
    """ListDecoders is used by ListParser to decode the elements in the list.

    A decoder is a function that accepts a value and returns its decoded
    object.

    ListDecoders is initialized with a list of tuples that contains the
    keyword and the decoding function associated with each position in the
    list. The order is, therefore, important.

    Args:
        decoders (list of tuples): Optional; a list of tuples.
            The first element in the tuple is the keyword associated with the
            value. The second element in the tuple is the decoder function.
    """

    def __init__(self, decoders=None):
        self._decoders = decoders or list()

    def decode(self, index, value_str):
        """Decode the index'th element of the list.

        Args:
            index (int): The position in the list of the element to decode.
            value_str (str): The value string to decode.
        """
        if index < 0 or index >= len(self._decoders):
            if self._default_decoder:
                return self._default_decoder(index, value_str)
            else:
                raise ParseError(
                    f"Cannot decode element {index} in list: {value_str}"
                )

        try:
            key = self._decoders[index][0]
            value = self._decoders[index][1](value_str)
            return key, value
        except Exception as e:
            raise ParseError(
                "Failed to decode value_str {}: {}".format(value_str, str(e))
            )

    @staticmethod
    def _default_decoder(index, value):
        key = "elem_{}".format(index)
        return key, decode_default(value)


class ListParser(object):
    """ListParser parses a list of values and stores them as key-value pairs.

    It uses a ListDecoders instance to decode each element in the list.

    Args:
        string (str): The string to parse.
        decoders (ListDecoders): Optional, the decoders to use.
        delims (list): Optional, list of delimiters of the list. Defaults to
            [','].
    """
    def __init__(self, string, decoders=None, delims=[","]):
        self._string = string
        self._decoders = decoders or ListDecoders()
        self._keyval = list()
        self._regexp = r"({})".format("|".join(delims))

    def kv(self):
        return self._keyval

    def __iter__(self):
        return iter(self._keyval)

    def parse(self):
        """Parse the list in string.

        Raises:
            ParseError if any parsing error occurs.
        """
        kpos = 0
        index = 0
        while kpos < len(self._string) and self._string[kpos] != "\n":
            split_parts = re.split(self._regexp, self._string[kpos:], 1)
            value_str = split_parts[0]

            key, value = self._decoders.decode(index, value_str)

            meta = KeyMetadata(
                kpos=kpos,
                vpos=kpos,
                kstring=value_str,
                vstring=value_str,
            )
            self._keyval.append(KeyValue(key, value, meta))

            kpos += len(value_str) + 1
            index += 1


def decode_nested_list(decoders, value, delims=[","]):
    """Decodes a string value that contains a list of elements and returns
    them in a dictionary.

    Args:
        decoders (ListDecoders): The ListDecoders to use.
        value (str): The value string to decode.
        delims (list(str)): Optional, the list of delimiters to use.
    """
    parser = ListParser(value, decoders, delims)
    parser.parse()
    return {kv.key: kv.value for kv in parser.kv()}


def nested_list_decoder(decoders=None, delims=[","]):
    """Helper function that creates a nested list decoder with given
    ListDecoders and delimiters.
    """
    def decoder(value):
        return decode_nested_list(decoders, value, delims)

    return decoder
