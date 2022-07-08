""" Global flow library entrypoint.
"""
for libname in ["netaddr", "pyparsing"]:
    try:
        lib = __import__(libname)
    except ModuleNotFoundError as e:
        raise ImportError(
            f"OVS Flow library requires {libname} to be installed."
            " To install all the dependencies needed for the Flow library, run"
            " 'pip install -e ovs[flow]' (or 'pip install -e .[flow]' locally)"
        ) from e
    else:
        globals()[libname] = lib
