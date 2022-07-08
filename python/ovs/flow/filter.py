""" Defines a Flow Filtering syntax.
"""
import pyparsing as pp
import netaddr
from functools import reduce
from operator import and_, or_

from ovs.flow.decoders import (
    decode_default,
    decode_int,
    Decoder,
    IPMask,
    EthMask,
)


class EvaluationResult(object):
    """An EvaluationResult is the result of an evaluation. It contains the
    boolean result and the list of key-values that were evaluated.

    Note that since boolean operations (and, not, or) are based only on
    __bool__ we use bitwise alternatives (&, ||, ~).
    """

    def __init__(self, result, *kv):
        self.result = result
        self.kv = kv if kv else list()

    def __and__(self, other):
        """Logical and operation."""
        return EvaluationResult(
            self.result and other.result, *self.kv, *other.kv
        )

    def __or__(self, other):
        """Logical or operation."""
        return EvaluationResult(
            self.result or other.result, *self.kv, *other.kv
        )

    def __invert__(self):
        """Logical not operation."""
        return EvaluationResult(not self.result, *self.kv)

    def __bool__(self):
        """Boolean operation."""
        return self.result

    def __repr__(self):
        return "{} [{}]".format(self.result, self.kv)


class ClauseExpression(object):
    """ A clause expression represents a specific expression in the filter.

    A clause has the following form:
        [field] [operator] [value]

    Valid operators are:
        = (equality)
        != (inequality)
        < (arithmetic less-than)
        > (arithmetic more-than)
        ~= (__contains__)

    When evaluated, the clause finds what relevant part of the flow to use for
    evaluation, tries to translate the clause value to the relevant type and
    performs the clause operation.

    Attributes:
        field (str): The flow field used in the clause.
        operator (str): The flow operator used in the clause.
        value (str): The value to perform the comparison against.
    """
    operators = {}
    type_decoders = {
        int: decode_int,
        netaddr.IPAddress: IPMask,
        netaddr.EUI: EthMask,
        bool: bool,
    }

    def __init__(self, tokens):
        self.field = tokens[0]
        self.value = ""
        self.operator = ""

        if len(tokens) > 1:
            self.operator = tokens[1]
            self.value = tokens[2]

    def __repr__(self):
        return "{}(field: {}, operator: {}, value: {})".format(
            self.__class__.__name__, self.field, self.operator, self.value
        )

    def _find_data_in_kv(self, kv_list):
        """Find a KeyValue for evaluation in a list of KeyValue.

        Args:
            kv_list (list[KeyValue]): list of KeyValue to look into.

        Returns:
            If found, tuple (kv, data) where kv is the KeyValue that matched
            and data is the data to be used for evaluation. None if not found.
        """
        key_parts = self.field.split(".")
        field = key_parts[0]
        kvs = [kv for kv in kv_list if kv.key == field]
        if not kvs:
            return None

        for kv in kvs:
            if kv.key == self.field:
                # exact match
                return (kv, kv.value)
            if len(key_parts) > 1:
                data = kv.value
                for subkey in key_parts[1:]:
                    try:
                        data = data.get(subkey)
                    except Exception:
                        data = None
                        break
                    if not data:
                        break
                if data:
                    return (kv, data)
        return None

    def _find_keyval_to_evaluate(self, flow):
        """Finds the key-value and data to use for evaluation on a flow.

        Args:
            flow(Flow): The flow where the lookup is performed.

        Returns:
            If found, tuple (kv, data) where kv is the KeyValue that matched
            and data is the data to be used for evaluation. None if not found.

        """
        for section in flow.sections:
            data = self._find_data_in_kv(section.data)
            if data:
                return data
        return None

    def evaluate(self, flow):
        """Returns whether the clause is satisfied by the flow.

        Args:
            flow (Flow): the flow to evaluate.
        """
        result = self._find_keyval_to_evaluate(flow)

        if not result:
            return EvaluationResult(False)

        keyval, data = result

        if not self.value and not self.operator:
            # just asserting the existance of the key
            return EvaluationResult(True, keyval)

        # Decode the value based on the type of data
        if isinstance(data, Decoder):
            decoder = data.__class__
        else:
            decoder = self.type_decoders.get(data.__class__) or decode_default

        decoded_value = decoder(self.value)

        if self.operator == "=":
            return EvaluationResult(decoded_value == data, keyval)
        elif self.operator == "<":
            return EvaluationResult(data < decoded_value, keyval)
        elif self.operator == ">":
            return EvaluationResult(data > decoded_value, keyval)
        elif self.operator == "~=":
            return EvaluationResult(decoded_value in data, keyval)


class BoolNot(object):
    def __init__(self, t):
        self.op, self.args = t[0]

    def __repr__(self):
        return "NOT({})".format(self.args)

    def evaluate(self, flow):
        return ~self.args.evaluate(flow)


class BoolAnd(object):
    def __init__(self, pattern):
        self.args = pattern[0][0::2]

    def __repr__(self):
        return "AND({})".format(self.args)

    def evaluate(self, flow):
        return reduce(and_, [arg.evaluate(flow) for arg in self.args])


class BoolOr(object):
    def __init__(self, pattern):
        self.args = pattern[0][0::2]

    def evaluate(self, flow):
        return reduce(or_, [arg.evaluate(flow) for arg in self.args])

    def __repr__(self):
        return "OR({})".format(self.args)


class OFFilter(object):
    """OFFilter represents an Open vSwitch Flow Filter.

    It is built with a filter expression string composed of logically-separated
    clauses (see ClauseExpression for details on the clause syntax).

    Args:
        expr(str): String filter expression.
    """
    w = pp.Word(pp.alphanums + "." + ":" + "_" + "/" + "-")
    operators = (
        pp.Literal("=")
        | pp.Literal("~=")
        | pp.Literal("<")
        | pp.Literal(">")
        | pp.Literal("!=")
    )

    clause = (w + operators + w) | w
    clause.setParseAction(ClauseExpression)

    statement = pp.infixNotation(
        clause,
        [
            ("!", 1, pp.opAssoc.RIGHT, BoolNot),
            ("not", 1, pp.opAssoc.RIGHT, BoolNot),
            ("&&", 2, pp.opAssoc.LEFT, BoolAnd),
            ("and", 2, pp.opAssoc.LEFT, BoolAnd),
            ("||", 2, pp.opAssoc.LEFT, BoolOr),
            ("or", 2, pp.opAssoc.LEFT, BoolOr),
        ],
    )

    def __init__(self, expr):
        self._filter = self.statement.parseString(expr)

    def evaluate(self, flow):
        """Evaluate whether the flow satisfies the filter.

        Args:
            flow(Flow): a openflow or datapath flow.

        Returns:
            An EvaluationResult with the result of the evaluation.
        """
        return self._filter[0].evaluate(flow)
