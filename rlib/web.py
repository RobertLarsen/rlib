import re

def urlparse(url):
    """
    Parses a URL into its subcomponents.

    >>> urlparse('http://www.googl.dk:80/some/path')
    {'username': None, 'scheme': 'http', 'host': 'www.googl.dk', 'path': '/some/path', 'password': None, 'port': 80}
    >>> urlparse('http://bozo@www.googl.dk:80/some/path')
    {'username': 'bozo', 'scheme': 'http', 'host': 'www.googl.dk', 'path': '/some/path', 'password': None, 'port': 80}
    >>> urlparse('http://bozo:verysecret@www.googl.dk:80/some/path')
    {'username': 'bozo', 'scheme': 'http', 'host': 'www.googl.dk', 'path': '/some/path', 'password': 'verysecret', 'port': 80}

    """
    scheme_regex = '(.*)'
    credentials_regex = '(([^:@]*)(:(.*))?@)?'
    ip_regex = '(\\d+(\\.\\d{3}))'
    hostname_regex = '(\\w+(\\.\\w+)*)'
    host_regex = '(' + ip_regex + '|' + hostname_regex + ')'
    port_regex = '(:(\\d+))?'
    path_regex = '(.*)'

    regex = scheme_regex + '://' + credentials_regex + hostname_regex + port_regex + path_regex
    m = re.match(regex, url)
    res = {
        'scheme' : m.group(1),
        'username' : m.group(3),
        'password' : m.group(5),
        'host' : m.group(6),
        'port' : m.group(9),
        'path' : m.group(10)
    }
    if not res['port'] is None:
        res['port'] = int(res['port'])
    return res

if __name__ == "__main__":
    import doctest
    doctest.testmod()
