import json, string

def hexify(data, headline = None):
    """
    Print out the specified data as a hex dump.
    """
    if not headline is None:
        print headline.center(73, '=')
    for i in xrange(0, len(data), 16):
        print '%05x %s %s  %s' % (i, ''.join([' %02x' % ord(c) for c in data[i:i + 8]]).ljust(24), ''.join([' %02x' % ord(c) for c in data[i + 8:i + 16]]).ljust(24), ''.join([c if (not c in ['\t', '\n', '\r', '\f', '\v'] and c in string.printable) else '.' for c in data[i:i + 16]]))

def json_pretty(obj):
    """
    Return the specified object as a pretty printed JSON string.
    """
    return json.dumps(obj, indent = 4, separators = (',', ':'), sort_keys = True)
