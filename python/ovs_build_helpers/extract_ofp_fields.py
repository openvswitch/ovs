import sys
import re

line = ""

# Maps from user-friendly version number to its protocol encoding.
VERSION = {
    "1.0": 0x01,
    "1.1": 0x02,
    "1.2": 0x03,
    "1.3": 0x04,
    "1.4": 0x05,
    "1.5": 0x06,
}
VERSION_REVERSE = dict((v, k) for k, v in VERSION.items())

TYPES = {
    "u8": (1, False),
    "be16": (2, False),
    "be32": (4, False),
    "MAC": (6, False),
    "be64": (8, False),
    "be128": (16, False),
    "tunnelMD": (124, True),
}

FORMATTING = {
    "decimal": ("MFS_DECIMAL", 1, 8),
    "hexadecimal": ("MFS_HEXADECIMAL", 1, 127),
    "ct state": ("MFS_CT_STATE", 4, 4),
    "Ethernet": ("MFS_ETHERNET", 6, 6),
    "IPv4": ("MFS_IPV4", 4, 4),
    "IPv6": ("MFS_IPV6", 16, 16),
    "OpenFlow 1.0 port": ("MFS_OFP_PORT", 2, 2),
    "OpenFlow 1.1+ port": ("MFS_OFP_PORT_OXM", 4, 4),
    "frag": ("MFS_FRAG", 1, 1),
    "tunnel flags": ("MFS_TNL_FLAGS", 2, 2),
    "TCP flags": ("MFS_TCP_FLAGS", 2, 2),
    "packet type": ("MFS_PACKET_TYPE", 4, 4),
}

PREREQS = {
    "none": "MFP_NONE",
    "Ethernet": "MFP_ETHERNET",
    "ARP": "MFP_ARP",
    "VLAN VID": "MFP_VLAN_VID",
    "IPv4": "MFP_IPV4",
    "IPv6": "MFP_IPV6",
    "IPv4/IPv6": "MFP_IP_ANY",
    "NSH": "MFP_NSH",
    "CT": "MFP_CT_VALID",
    "MPLS": "MFP_MPLS",
    "TCP": "MFP_TCP",
    "UDP": "MFP_UDP",
    "SCTP": "MFP_SCTP",
    "ICMPv4": "MFP_ICMPV4",
    "ICMPv6": "MFP_ICMPV6",
    "ND": "MFP_ND",
    "ND solicit": "MFP_ND_SOLICIT",
    "ND advert": "MFP_ND_ADVERT",
}

# Maps a name prefix into an (experimenter ID, class) pair, so:
#
#      - Standard OXM classes are written as (0, <oxm_class>)
#
#      - Experimenter OXM classes are written as (<oxm_vender>, 0xffff)
#
# If a name matches more than one prefix, the longest one is used.
OXM_CLASSES = {
    "NXM_OF_": (0, 0x0000, "extension"),
    "NXM_NX_": (0, 0x0001, "extension"),
    "NXOXM_NSH_": (0x005AD650, 0xFFFF, "extension"),
    "OXM_OF_": (0, 0x8000, "standard"),
    "OXM_OF_PKT_REG": (0, 0x8001, "standard"),
    "ONFOXM_ET_": (0x4F4E4600, 0xFFFF, "standard"),
    "ERICOXM_OF_": (0, 0x1000, "extension"),
    # This is the experimenter OXM class for Nicira, which is the
    # one that OVS would be using instead of NXM_OF_ and NXM_NX_
    # if OVS didn't have those grandfathered in.  It is currently
    # used only to test support for experimenter OXM, since there
    # are barely any real uses of experimenter OXM in the wild.
    "NXOXM_ET_": (0x00002320, 0xFFFF, "extension"),
}


def oxm_name_to_class(name):
    prefix = ""
    class_ = None
    for p, c in OXM_CLASSES.items():
        if name.startswith(p) and len(p) > len(prefix):
            prefix = p
            class_ = c
    return class_


def is_standard_oxm(name):
    oxm_vendor, oxm_class, oxm_class_type = oxm_name_to_class(name)
    return oxm_class_type == "standard"


def get_line():
    global line
    global line_number
    line = input_file.readline()
    line_number += 1
    if line == "":
        fatal("unexpected end of input")


n_errors = 0


def error(msg):
    global n_errors
    sys.stderr.write("%s:%d: %s\n" % (file_name, line_number, msg))
    n_errors += 1


def fatal(msg):
    error(msg)
    sys.exit(1)


def parse_oxms(s, prefix, n_bytes):
    if s == "none":
        return ()

    return tuple(parse_oxm(s2.strip(), prefix, n_bytes) for s2 in s.split(","))


match_types = dict()


def parse_oxm(s, prefix, n_bytes):
    global match_types

    m = re.match(
        r"([A-Z0-9_]+)\(([0-9]+)\) since(?: OF(1\.[0-9]+) and)? v([123]\.[0-9]+)$",  # noqa: E501
        s,
    )
    if not m:
        fatal("%s: syntax error parsing %s" % (s, prefix))

    name, oxm_type, of_version, ovs_version = m.groups()

    class_ = oxm_name_to_class(name)
    if class_ is None:
        fatal("unknown OXM class for %s" % name)
    oxm_vendor, oxm_class, oxm_class_type = class_

    if int(oxm_type) > 127:
        fatal("%s: OXM field is out of range (%s > 127)" % (name, oxm_type))

    if class_ in match_types:
        if oxm_type in match_types[class_]:
            fatal(
                "duplicate match type for %s (conflicts with %s)"
                % (name, match_types[class_][oxm_type])
            )
    else:
        match_types[class_] = dict()
    match_types[class_][oxm_type] = name

    # Normally the oxm_length is the size of the field, but for experimenter
    # OXMs oxm_length also includes the 4-byte experimenter ID.
    oxm_length = n_bytes
    if oxm_class == 0xFFFF:
        oxm_length += 4

    header = (oxm_vendor, oxm_class, int(oxm_type), oxm_length)

    if of_version:
        if oxm_class_type == "extension":
            fatal("%s: OXM extension can't have OpenFlow version" % name)
        if of_version not in VERSION:
            fatal("%s: unknown OpenFlow version %s" % (name, of_version))
        of_version_nr = VERSION[of_version]
        if of_version_nr < VERSION["1.2"]:
            fatal("%s: claimed version %s predates OXM" % (name, of_version))
    else:
        if oxm_class_type == "standard":
            fatal("%s: missing OpenFlow version number" % name)
        of_version_nr = 0

    return (header, name, of_version_nr, ovs_version)


def parse_field(mff, comment):
    f = {"mff": mff}

    # First line of comment is the field name.
    m = re.match(
        r'"([^"]+)"(?:\s+\(aka "([^"]+)"\))?(?:\s+\(.*\))?\.', comment[0]
    )
    if not m:
        fatal("%s lacks field name" % mff)
    f["name"], f["extra_name"] = m.groups()

    # Find the last blank line the comment.  The field definitions
    # start after that.
    blank = None
    for i in range(len(comment)):
        if not comment[i]:
            blank = i
    if not blank:
        fatal("%s: missing blank line in comment" % mff)

    d = {}
    for key in (
        "Type",
        "Maskable",
        "Formatting",
        "Prerequisites",
        "Access",
        "Prefix lookup member",
        "OXM",
        "NXM",
        "OF1.0",
        "OF1.1",
    ):
        d[key] = None
    for fline in comment[blank + 1 :]:
        m = re.match(r"([^:]+):\s+(.*)\.$", fline)
        if not m:
            fatal(
                "%s: syntax error parsing key-value pair as part of %s"
                % (fline, mff)
            )
        key, value = m.groups()
        if key not in d:
            fatal("%s: unknown key" % key)
        elif key == "Code point":
            d[key] += [value]
        elif d[key] is not None:
            fatal("%s: duplicate key" % key)
        d[key] = value
    for key, value in d.items():
        if not value and key not in (
            "OF1.0",
            "OF1.1",
            "Prefix lookup member",
            "Notes",
        ):
            fatal("%s: missing %s" % (mff, key))

    m = re.match(r"([a-zA-Z0-9]+)(?: \(low ([0-9]+) bits\))?$", d["Type"])
    if not m:
        fatal("%s: syntax error in type" % mff)
    type_ = m.group(1)
    if type_ not in TYPES:
        fatal("%s: unknown type %s" % (mff, d["Type"]))

    f["n_bytes"] = TYPES[type_][0]
    if m.group(2):
        f["n_bits"] = int(m.group(2))
        if f["n_bits"] > f["n_bytes"] * 8:
            fatal(
                "%s: more bits (%d) than field size (%d)"
                % (mff, f["n_bits"], 8 * f["n_bytes"])
            )
    else:
        f["n_bits"] = 8 * f["n_bytes"]
    f["variable"] = TYPES[type_][1]

    if d["Maskable"] == "no":
        f["mask"] = "MFM_NONE"
    elif d["Maskable"] == "bitwise":
        f["mask"] = "MFM_FULLY"
    else:
        fatal("%s: unknown maskable %s" % (mff, d["Maskable"]))

    fmt = FORMATTING.get(d["Formatting"])
    if not fmt:
        fatal("%s: unknown format %s" % (mff, d["Formatting"]))
    f["formatting"] = d["Formatting"]
    if f["n_bytes"] < fmt[1] or f["n_bytes"] > fmt[2]:
        fatal(
            "%s: %d-byte field can't be formatted as %s"
            % (mff, f["n_bytes"], d["Formatting"])
        )
    f["string"] = fmt[0]

    f["prereqs"] = d["Prerequisites"]
    if f["prereqs"] not in PREREQS:
        fatal("%s: unknown prerequisites %s" % (mff, d["Prerequisites"]))

    if d["Access"] == "read-only":
        f["writable"] = False
    elif d["Access"] == "read/write":
        f["writable"] = True
    else:
        fatal("%s: unknown access %s" % (mff, d["Access"]))

    f["OF1.0"] = d["OF1.0"]
    if d["OF1.0"] not in (None, "exact match", "CIDR mask"):
        fatal("%s: unknown OF1.0 match type %s" % (mff, d["OF1.0"]))

    f["OF1.1"] = d["OF1.1"]
    if d["OF1.1"] not in (None, "exact match", "bitwise mask"):
        fatal("%s: unknown OF1.1 match type %s" % (mff, d["OF1.1"]))

    f["OXM"] = parse_oxms(d["OXM"], "OXM", f["n_bytes"]) + parse_oxms(
        d["NXM"], "NXM", f["n_bytes"]
    )

    f["prefix"] = d["Prefix lookup member"]

    return f


def extract_ofp_fields(fn):
    global file_name
    global input_file
    global line_number
    global line

    file_name = fn
    input_file = open(file_name)
    line_number = 0

    fields = []

    while True:
        get_line()
        if re.match("enum.*mf_field_id", line):
            break

    while True:
        get_line()
        if (
            line.startswith("/*")
            or line.startswith(" *")
            or line.startswith("#")
            or not line
            or line.isspace()
        ):
            continue
        elif re.match(r"}", line) or re.match(r"\s+MFF_N_IDS", line):
            break

        # Parse the comment preceding an MFF_ constant into 'comment',
        # one line to an array element.
        line = line.strip()
        if not line.startswith("/*"):
            fatal("unexpected syntax between fields")
        line = line[1:]
        comment = []
        end = False
        while not end:
            line = line.strip()
            if line.startswith("*/"):
                get_line()
                break
            if not line.startswith("*"):
                fatal("unexpected syntax within field")

            line = line[1:]
            if line.startswith(" "):
                line = line[1:]
            if line.startswith(" ") and comment:
                continuation = True
                line = line.lstrip()
            else:
                continuation = False

            if line.endswith("*/"):
                line = line[:-2].rstrip()
                end = True
            else:
                end = False

            if continuation:
                comment[-1] += " " + line
            else:
                comment += [line]
            get_line()

        # Drop blank lines at each end of comment.
        while comment and not comment[0]:
            comment = comment[1:]
        while comment and not comment[-1]:
            comment = comment[:-1]

        # Parse the MFF_ constant(s).
        mffs = []
        while True:
            m = re.match(r"\s+(MFF_[A-Z0-9_]+),?\s?$", line)
            if not m:
                break
            mffs += [m.group(1)]
            get_line()
        if not mffs:
            fatal("unexpected syntax looking for MFF_ constants")

        if len(mffs) > 1 or "<N>" in comment[0]:
            for mff in mffs:
                # Extract trailing integer.
                m = re.match(".*[^0-9]([0-9]+)$", mff)
                if not m:
                    fatal("%s lacks numeric suffix in register group" % mff)
                n = m.group(1)

                # Search-and-replace <N> within the comment,
                # and drop lines that have <x> for x != n.
                instance = []
                for x in comment:
                    y = x.replace("<N>", n)
                    if re.search("<[0-9]+>", y):
                        if ("<%s>" % n) not in y:
                            continue
                        y = re.sub("<[0-9]+>", "", y)
                    instance += [y.strip()]
                fields += [parse_field(mff, instance)]
        else:
            fields += [parse_field(mffs[0], comment)]
        continue

    input_file.close()

    if n_errors:
        sys.exit(1)

    return fields
