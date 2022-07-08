""" Defines the Flow class.
"""


class Section(object):
    """A flow can be seen as composed of different sections, e.g:

     [info] [match] actions=[actions]

    This class represents each of those sections.

    A section is basically a set of Key-Value pairs. Typically, they can be
    expressed as a dictionary, for instance the "match" part of a flow can be
    expressed as:
        {
            "nw_src": "192.168.1.1",
            "nw_dst": "192.168.1.2",
        }
    However, some of them must be expressed as a list which allows for
    duplicated keys. For instance, the "actions" section could be:
        [
            {
                "output": 32
            },
            {
                "output": 33
            }
        ]

    The is_list flag is used to discriminate this.

    Attributes:
        name (str): Name of the section.
        pos (int): Position within the overall flow string.
        string (str): Section string.
        data (list[KeyValue]): Parsed data of the section.
        is_list (bool): Whether the key-values shall be expressed as a list
        (i.e: it allows repeated keys).
    """

    def __init__(self, name, pos, string, data, is_list=False):
        self.name = name
        self.pos = pos
        self.string = string
        self.data = data
        self.is_list = is_list

    def __str__(self):
        return "{} (at {}): {}".format(self.name, self.pos, self.string)

    def __repr__(self):
        return "%s('%s')" % (self.__class__.__name__, self)

    def dict(self):
        return {self.name: self.format_data()}

    def format_data(self):
        """Returns the section's key-values formatted in a dictionary or list
        depending on the value of is_list flag.
        """
        if self.is_list:
            return [{item.key: item.value} for item in self.data]
        else:
            return {item.key: item.value for item in self.data}


class Flow(object):
    """The Flow class is a base class for other types of concrete flows
    (such as OFproto Flows or DPIF Flows).

    A flow is basically comprised of a number of sections.
    For each section named {section_name}, the flow object will have the
    following attributes:
     - {section_name} will return the sections data in a formatted way.
     - {section_name}_kv will return the sections data as a list of KeyValues.

    Args:
        sections (list[Section]): List of sections that comprise the flow
        orig (str): Original flow string.
        id (Any): Optional; identifier that clients can use to uniquely
            identify this flow.
    """

    def __init__(self, sections, orig="", id=None):
        self._sections = sections
        self._orig = orig
        self._id = id
        for section in sections:
            setattr(
                self, section.name, self.section(section.name).format_data()
            )
            setattr(
                self,
                "{}_kv".format(section.name),
                self.section(section.name).data,
            )

    def section(self, name):
        """Return the section by name."""
        return next(
            (sect for sect in self._sections if sect.name == name), None
        )

    @property
    def id(self):
        """Return the Flow ID."""
        return self._id

    @property
    def sections(self):
        """Return the all the sections in a list."""
        return self._sections

    @property
    def orig(self):
        """Return the original flow string."""
        return self._orig

    def dict(self):
        """Returns the Flow information in a dictionary."""
        flow_dict = {"orig": self.orig}
        for section in self.sections:
            flow_dict.update(section.dict())

        return flow_dict
