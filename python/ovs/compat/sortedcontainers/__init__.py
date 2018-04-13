"""Sorted Container Types: SortedList, SortedDict, SortedSet

SortedContainers is an Apache2 licensed containers library, written in
pure-Python, and fast as C-extensions.


Python's standard library is great until you need a sorted collections
type. Many will attest that you can get really far without one, but the moment
you **really need** a sorted list, dict, or set, you're faced with a dozen
different implementations, most using C-extensions without great documentation
and benchmarking.

In Python, we can do better. And we can do it in pure-Python!

::

    >>> from sortedcontainers import SortedList, SortedDict, SortedSet
    >>> sl = SortedList(xrange(10000000))
    >>> 1234567 in sl
    True
    >>> sl[7654321]
    7654321
    >>> sl.add(1234567)
    >>> sl.count(1234567)
    2
    >>> sl *= 3
    >>> len(sl)
    30000003

SortedContainers takes all of the work out of Python sorted types - making your
deployment and use of Python easy. There's no need to install a C compiler or
pre-build and distribute custom extensions. Performance is a feature and
testing has 100% coverage with unit tests and hours of stress.

:copyright: (c) 2016 by Grant Jenks.
:license: Apache 2.0, see LICENSE for more details.

"""


from .sortedlist import SortedList, SortedListWithKey
from .sortedset import SortedSet
from .sorteddict import SortedDict

__all__ = ['SortedList', 'SortedSet', 'SortedDict', 'SortedListWithKey']

__title__ = 'sortedcontainers'
__version__ = '1.5.9'
__build__ = 0x010509
__author__ = 'Grant Jenks'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2016 Grant Jenks'
