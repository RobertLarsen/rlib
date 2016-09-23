def create(s):
    r"""
    Creates and returns a netstring from the specified data which may be binary.
    >>> create('Hello, World!')
    '13:Hello, World!,'
    >>> create('\x00\x01')
    '2:\x00\x01,'
    >>> create(create("Hello") + create("World"))
    '16:5:Hello,5:World,,'
    """
    return "%d:%s," % (len(s), s)

def parse(s, callback):
    """
    Parses a netstring, calling the specified callback for each string and returning the remaining part
    >>> strings = []
    >>> parse(create('Hello') + create('World') + create("Not finished")[0:10], lambda x: strings.append(x))
    '12:Not fin'
    >>> strings
    ['Hello', 'World']
    """
    i = 0
    l = 0
    remaining = s

    while i < len(s) and ord(s[i]) >= 0x30 and ord(s[i]) <= 0x39:
        l = l * 10 + ord(s[i]) - 0x30
        i += 1
    
    if i < len(s) and ord(s[i]) == 0x3a and l + 1 + i < len(s) and ord(s[l + i + 1]) == 0x2c:
        i += 1
        callback(s[i:l + i])
        remaining = s[l + i + 1:]
        remaining = parse(remaining, callback)

    return remaining

if __name__ == "__main__":
    import doctest
    doctest.testmod()
