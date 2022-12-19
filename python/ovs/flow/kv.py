"""Common helper classes for flow Key-Value parsing."""

import functools
import re

from ovs.flow.decoders import decode_default


class ParseError(RuntimeError):
    """Exception raised when an error occurs during parsing."""

    pass


class KeyMetadata(object):
    """Class for keeping key metadata.

    Attributes:
        kpos (int): The position of the keyword in the parent string.
        vpos (int): The position of the value in the parent string.
        kstring (string): The keyword string as found in the flow string.
        vstring (string): The value as found in the flow string.
        delim (string): Optional, the string used as delimiter between the key
            and the value.
        end_delim (string): Optional, the string used as end delimiter
    """

    def __init__(self, kpos, vpos, kstring, vstring, delim="", end_delim=""):
        """Constructor."""
        self.kpos = kpos
        self.vpos = vpos
        self.kstring = kstring
        self.vstring = vstring
        self.delim = delim
        self.end_delim = end_delim

    def __str__(self):
        return "key: [{},{}), val:[{}, {})".format(
            self.kpos,
            self.kpos + len(self.kstring),
            self.vpos,
            self.vpos + len(self.vstring),
        )

    def __repr__(self):
        return "{}('{}')".format(self.__class__.__name__, self)


class KeyValue(object):
    """Class for keeping key-value data.

    Attributes:
        key (str): The key string.
        value (any): The value data.
        meta (KeyMetadata): The key metadata.
    """

    def __init__(self, key, value, meta=None):
        """Constructor."""
        self.key = key
        self.value = value
        self.meta = meta

    def __str__(self):
        return "{}: {} ({})".format(self.key, str(self.value), str(self.meta))

    def __repr__(self):
        return "{}('{}')".format(self.__class__.__name__, self)


class KVDecoders(object):
    """KVDecoders class is used by KVParser to select how to decode the value
    of a specific keyword.

    A decoder is simply a function that accepts a value string and returns
    the value objects to be stored.
    The returned value may be of any type.

    Decoders may return a KeyValue instance to indicate that the keyword should
    also be modified to match the one provided in the returned KeyValue.

    The decoder to be used will be selected using the key as an index. If not
    found, the default decoder will be used. If free keys are found (i.e:
    keys without a value), the default_free decoder will be used. For that
    reason, the default_free decoder, must return both the key and value to be
    stored.

    Args:
        decoders (dict): Optional; A dictionary of decoders indexed by keyword.
        default (callable): Optional; A function to use if a match is not
            found in configured decoders. If not provided, the default behavior
            is to try to decode the value into an integer and, if that fails,
            just return the string as-is. The function must accept a the key
            and the value and return the decoded (key, value) tuple back.
        default_free (callable): Optional; The decoder used if a match is not
            found in configured decoders and it's a free value (e.g:
            a value without a key) Defaults to returning the free value as
            keyword and "True" as value.
            The callable must accept a string and return a key-value pair.
    """

    def __init__(self, decoders=None, default=None, default_free=None):
        self._decoders = decoders or dict()
        self._default = default or (lambda k, v: (k, decode_default(v)))
        self._default_free = default_free or self._default_free_decoder

    def decode(self, keyword, value_str):
        """Decode a keyword and value.

        Args:
            keyword (str): The keyword whose value is to be decoded.
            value_str (str): The value string.

        Returns:
            The key (str) and value(any) to be stored.
        """

        decoder = self._decoders.get(keyword)
        if decoder:
            result = decoder(value_str)
            if isinstance(result, KeyValue):
                keyword = result.key
                value = result.value
            else:
                value = result

            return keyword, value
        else:
            if value_str:
                return self._default(keyword, value_str)
            else:
                return self._default_free(keyword)

    @staticmethod
    def _default_free_decoder(key):
        """Default decoder for free keywords."""
        return key, True


delim_pattern = re.compile(r"(\(|=|:|,|\n|\r|\t)")
parenthesis = re.compile(r"(\(|\))")
end_pattern = re.compile(r"( |,|\n|\r|\t)")
separators = (" ", ",")
end_of_string = (",", "\n", "\t", "\r", "")


class KVParser(object):
    """KVParser parses a string looking for key-value pairs.

    Args:
        string (str): The string to parse.
        decoders (KVDecoders): Optional; the KVDecoders instance to use.
    """

    def __init__(self, string, decoders=None):
        """Constructor."""
        self._decoders = decoders or KVDecoders()
        self._keyval = list()
        self._string = string

    def keys(self):
        return list(kv.key for kv in self._keyval)

    def kv(self):
        return self._keyval

    def __iter__(self):
        return iter(self._keyval)

    def parse(self):
        """Parse the key-value pairs in string.

        The input string is assumed to contain a list of comma (or space)
        separated key-value pairs.

        Key-values pairs can have multiple different delimiters, eg:
            "key1:value1,key2=value2,key3(value3)".

        Also, we can stumble upon a "free" keywords, e.g:
            "key1=value1,key2=value2,free_keyword".
        We consider this as keys without a value.

        So, to parse the string we do the following until the end of the
        string is found:

            1 - Skip any leading comma's or spaces.
            2 - Find the next delimiter (or end_of_string character).
            3 - Depending on the delimiter, obtain the key and the value.
                For instance, if the delimiter is "(", find the next matching
                ")".
            4 - Use the KVDecoders to decode the key-value.
            5 - Store the KeyValue object with the corresponding metadata.

        Raises:
            ParseError if any parsing error occurs.
        """
        kpos = 0
        while kpos < len(self._string) and self._string[kpos] != "\n":
            keyword = ""
            delimiter = ""
            rest = ""

            # 1. Skip separator characters.
            if self._string[kpos] in separators:
                kpos += 1
                continue

            # 2. Find the next delimiter or end of string character.
            try:
                keyword, delimiter, rest = delim_pattern.split(
                    self._string[kpos:], 1
                )
            except ValueError:
                keyword = self._string[kpos:]  # Free keyword

            # 3. Extract the value from the rest of the string.
            value_str = ""
            vpos = kpos + len(keyword) + 1
            end_delimiter = ""

            if delimiter in ("=", ":"):
                # If the delimiter is ':' or '=', the end of the value is the
                # end of the string or a ', '.
                value_parts = end_pattern.split(rest, 1)
                value_str = value_parts[0]
                next_kpos = vpos + len(value_str)

            elif delimiter == "(":
                # Find matching ")".
                level = 1
                index = 0
                value_parts = parenthesis.split(rest)
                for val in value_parts:
                    if val == "(":
                        level += 1
                    elif val == ")":
                        level -= 1
                    index += len(val)
                    if level == 0:
                        break

                if level != 0:
                    raise ParseError(
                        "Error parsing string {}: "
                        "Failed to find matching ')' in {}".format(
                            self._string, rest
                        )
                    )

                value_str = rest[: index - 1]
                next_kpos = vpos + len(value_str) + 1
                end_delimiter = ")"

                # Exceptionally, if after the () we find -> {}, do not treat
                # the content of the parenthesis as the value, consider
                # ({})->{} as the string value.
                if index < len(rest) - 2 and rest[index : index + 2] == "->":
                    extra_val = rest[index + 2 :].split(",")[0]
                    value_str = "({})->{}".format(value_str, extra_val)
                    # remove the first "(".
                    vpos -= 1
                    next_kpos = vpos + len(value_str)
                    end_delimiter = ""

            elif delimiter in end_of_string:
                # Key without a value.
                next_kpos = kpos + len(keyword)
                vpos = -1

            # 4. Use KVDecoders to decode the key-value.
            try:
                key, val = self._decoders.decode(keyword, value_str)
            except Exception as e:
                raise ParseError(
                    "Error parsing key-value ({}, {})".format(
                        keyword, value_str
                    )
                ) from e

            # Store the KeyValue object with the corresponding metadata.
            meta = KeyMetadata(
                kpos=kpos,
                vpos=vpos,
                kstring=keyword,
                vstring=value_str,
                delim=delimiter,
                end_delim=end_delimiter,
            )

            self._keyval.append(KeyValue(key, val, meta))

            kpos = next_kpos


def decode_nested_kv(decoders, value):
    """A key-value decoder that extracts nested key-value pairs and returns
    them in a dictionary.

    Args:
        decoders (KVDecoders): The KVDecoders to use.
        value (str): The value string to decode.
    """
    if not value:
        # Mark as flag
        return True

    parser = KVParser(value, decoders)
    parser.parse()
    return {kv.key: kv.value for kv in parser.kv()}


def nested_kv_decoder(decoders=None):
    """Helper function that creates a nested kv decoder with given
    KVDecoders."""
    return functools.partial(decode_nested_kv, decoders)
