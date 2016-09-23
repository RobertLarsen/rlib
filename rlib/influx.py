import urllib2, base64

class influxdb:
    def __init__(self, database, scheme = 'http', host = 'localhost', port = 8086, username = 'root', password = 'root', precision = 'ms'):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.precision = precision

    def write_points(self, data):
        """
        Write the data points to InfluxDB. Data is an array of tuples formatted like this:
        [
            ('Ludo.io', {'in':572852, 'out':72395}, 1429707247000),
            ('Ludo.io', {'in':72582, 'out':72349}, 1429707248000)
        ]
        """
        data = '\n'.join(['%s %s %d' % (series, ','.join(['%s=%d' % kv for kv in kvs.items()]), ts) for series, kvs, ts in data]) + '\n'

        req = urllib2.Request('%s://%s:%d/write?db=%s&precision=%s&u=%s&p=%s' % (self.scheme, self.host, self.port, self.database, self.precision, self.username, self.password),
                              data, 
                              {
                                  'Content-Type':'application/binary',
                                  'Content-Length':len(data)
                              }
             )
        urllib2.urlopen(req)
