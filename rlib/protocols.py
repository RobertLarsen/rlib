import socket
import pcapy

ETHER_SIZE = 14
COOKED_SIZE = 16
IPV6_SIZE = 40
TCP_SIZE = 32
UDP_SIZE = 8
TYPE_IP = 0x800
TYPE_UDP = 17
TYPE_TCP = 6
TYPE_IPV6 = 0x86dd

def parse_packet(linktype, packet):
    """
    Parse packet into a three element tuple containing parsed versions of its 
    link layer, network layer and transport layer data.
    """
    link_layer = parse_Ethernet(packet) if linktype == pcapy.DLT_EN10MB else parse_Cooked(packet)
    if link_layer['payload_type'] in ['IPv4', 'IPv6']:
        network_layer = parse_IPv4(link_layer['payload']) if link_layer['payload_type'] == 'IPv4' else parse_IPv6(link_layer['payload'])
        if network_layer['payload_type'] in ['UDP', 'TCP']:
            transport_layer = parse_UDP(network_layer['payload']) if network_layer['payload_type'] == 'UDP' else parse_TCP(network_layer['payload'])
            return (link_layer, network_layer, transport_layer)

def parse_IPv4(packet):
    r"""
    >>> parse_IPv4('\x45\x00\x00\x22\x25\xee\x40\x00\x40\x11\x16\xdb\x7f\x00\x00\x01\x7f\x00\x00\x01\xe7\x2e\x1e\x61\x00\x0e\xfe\x21\x48\x65\x6c\x6c\x6f\x0a')
    {'addresses': ('127.0.0.1', '127.0.0.1'), 'proto': 17, 'fragment': 0, 'tos': 0, 'payload': '\xe7.\x1ea\x00\x0e\xfe!Hello\n', 'version': 5, 'flags': ['DF'], 'payload_type': 'UDP', 'ttl': 64, 'checksum': 5851, 'id': 9710, 'protocol_type': 'IPv4'}
    """
    def word(pos): return (ord(packet[pos]) << 8) + ord(packet[pos + 1])
    p = {"protocol_type":"IPv4"}
    p['version'] = ord(packet[0]) & 0xf
    p['tos'] = ord(packet[1])
    p['id'] = word(4)
    frag = word(6)
    p['flags'] = []
    if frag & (1 << 15): p['flags'].append('MF')
    if frag & (1 << 14): p['flags'].append('DF')
    p['fragment'] = frag & 0x1fff
    p['ttl'] = ord(packet[8])
    p['proto'] = t = ord(packet[9])
    p['payload_type'] = {TYPE_UDP:'UDP',TYPE_TCP:'TCP'}.get(t, t)
    p['checksum'] = word(10)
    p['addresses'] = (
        str(socket.inet_ntop(socket.AF_INET, packet[12:16])),
        str(socket.inet_ntop(socket.AF_INET, packet[16:20]))
    )
    ip_header_len = (ord(packet[0]) & 0xf) * 4
    ip_total_len = word(2)
    p['payload'] = packet[ip_header_len:ip_total_len]
    return p

def parse_IPv6(packet):
    r"""
    >>> parse_IPv6('\x60\x00\x00\x00\x00\x0e\x11\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xcf\x56\x1e\x61\x00\x0e\xee\x3c\x48\x65\x6c\x6c\x6f\x0a')
    {'addresses': ('::1', '::1'), 'class': 0, 'version': 6, 'payload_type': 'UDP', 'hop_limit': 64, 'next_header': 17, 'payload': '\xcfV\x1ea\x00\x0e\xee<Hello\n', 'protocol_type': 'IPv6'}
    """
    def word(pos): return (ord(packet[pos]) << 8) + ord(packet[pos + 1])
    p = {"protocol_type":"IPv6"}
    p['version'] = (ord(packet[0]) >> 4)
    p['class'] = ((ord(packet[0]) & 0xf) << 4) + (ord(packet[1]) >> 4)
    p['addresses'] = (
        str(socket.inet_ntop(socket.AF_INET6, packet[8:24])),
        str(socket.inet_ntop(socket.AF_INET6, packet[24:40]))
    )
    payload_len = word(4)
    p['payload'] = packet[IPV6_SIZE:payload_len + IPV6_SIZE]
    p['next_header'] = t = ord(packet[6])
    p['payload_type'] = {TYPE_UDP:'UDP',TYPE_TCP:'TCP'}.get(t, t)
    p['hop_limit'] = ord(packet[7])

    return p

def parse_Cooked(packet):
    def word(pos): return (ord(packet[pos]) << 8) + ord(packet[pos + 1])
    p = {"protocol_type":"LinuxCooked"}
    p['payload'] = packet[COOKED_SIZE:]
    p['protocol'] = t = word(14)
    p['payload_type'] = {TYPE_IP:'IPv4',TYPE_IPV6:'IPv6'}.get(t,t)
    
    return p

def parse_Ethernet(packet):
    r"""
    >>> parse_Ethernet('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x45\x00\x00\x22\x25\xee\x40\x00\x40\x11\x16\xdb\x7f\x00\x00\x01\x7f\x00\x00\x01\xe7\x2e\x1e\x61\x00\x0e\xfe\x21\x48\x65\x6c\x6c\x6f\x0a')
    {'frame_type': 2048, 'addresses': ('00:00:00:00:00:00', '00:00:00:00:00:00'), 'payload': 'E\x00\x00"%\xee@\x00@\x11\x16\xdb\x7f\x00\x00\x01\x7f\x00\x00\x01\xe7.\x1ea\x00\x0e\xfe!Hello\n', 'protocol_type': 'Ethernet', 'payload_type': 'IPv4'}
    """
    def word(pos): return (ord(packet[pos]) << 8) + ord(packet[pos + 1])
    p = {"protocol_type":"Ethernet"}
    p['payload'] = packet[ETHER_SIZE:]
    p['frame_type'] = t = word(12)
    p['payload_type'] = {TYPE_IP:'IPv4',TYPE_IPV6:'IPv6'}.get(t,t)
    p['addresses'] = (
        ':'.join(['%02x' % ord(c) for c in packet[0:6]]),
        ':'.join(['%02x' % ord(c) for c in packet[6:12]])
    )

    return p

def parse_UDP(packet):
    r"""
    >>> parse_UDP('\xe7\x2e\x1e\x61\x00\x0e\xfe\x21\x48\x65\x6c\x6c\x6f\x0a')
    {'checksum': 65057, 'payload': 'Hello\n', 'protocol_type': 'UDP', 'ports': (59182, 7777)}
    """
    def word(pos): return (ord(packet[pos]) << 8) + ord(packet[pos + 1])
    p = {"protocol_type":"UDP"}
    p['payload'] = packet[UDP_SIZE:]
    p['ports'] = (word(0), word(2))
    p['checksum'] = word(6)

    return p

def parse_TCP(packet):
    r"""
    >>> parse_TCP('\xaa\x36\x1e\x61\xb2\x87\xd8\xf5\x52\xc5\xd3\xe3\x80\x18\x01\x56\xfe\x2e\x00\x00\x01\x01\x08\x0a\x02\xed\xd5\xef\x02\xed\xd3\xa9\x48\x65\x6c\x6c\x6f\x0a')
    {'urg': 0, 'seq': 2995247349, 'ack': 1388696547, 'checksum': 65070, 'ports': (43574, 7777), 'window': 342, 'flags': ['PSH', 'ACK'], 'payload': 'Hello\n', 'protocol_type': 'TCP'}
    """
    def word(pos): return (ord(packet[pos]) << 8) + ord(packet[pos + 1])
    def dword(pos): return (word(pos) << 16) + word(pos + 2)

    p = {"protocol_type":"TCP"}
    tcp_offset = (ord(packet[12]) >> 4) * 4
    p['payload'] = packet[tcp_offset:]
    p['ports'] = (word(0), word(2))
    p['seq'] = dword(4)
    p['ack'] = dword(8)
    flags = word(12)
    p['flags'] = []
    if flags & (1 << 0): p['flags'].append('FIN') 
    if flags & (1 << 1): p['flags'].append('SYN')
    if flags & (1 << 2): p['flags'].append('RST')
    if flags & (1 << 3): p['flags'].append('PSH')
    if flags & (1 << 4): p['flags'].append('ACK')
    if flags & (1 << 5): p['flags'].append('URG')
    p['window'] = word(14)
    p['checksum'] = word(16)
    p['urg'] = word(18)

    return p

def parse_DNS(packet):
    r"""
    >>> parse_DNS('\xcf\x27\x81\x80\x00\x01\x00\x01\x00\x03\x00\x04\x03\x77\x77\x77\x05\x68\x65\x6c\x6c\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x04\x96\x00\x04\x82\xd3\x8e\x22\xc0\x10\x00\x02\x00\x01\x00\x02\xa0\x8e\x00\x12\x03\x6e\x73\x35\x0b\x64\x6e\x73\x6d\x61\x64\x65\x65\x61\x73\x79\xc0\x16\xc0\x10\x00\x02\x00\x01\x00\x02\xa0\x8e\x00\x06\x03\x6e\x73\x36\xc0\x3f\xc0\x10\x00\x02\x00\x01\x00\x02\xa0\x8e\x00\x06\x03\x6e\x73\x37\xc0\x3f\xc0\x3b\x00\x01\x00\x01\x00\x02\x8c\xd1\x00\x04\xd0\x5e\x94\x0d\xc0\x3b\x00\x1c\x00\x01\x00\x02\x8c\xd1\x00\x10\x26\x00\x18\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0\x59\x00\x01\x00\x01\x00\x02\x8c\xd1\x00\x04\xd0\x50\x7c\x0d\xc0\x6b\x00\x01\x00\x01\x00\x02\x8c\xd1\x00\x04\xd0\x50\x7e\x0d')
    {'additional': [{'ipv4': '208.94.148.13', 'ttl': 167121, 'type': 'A', 'name': 'ns5.dnsmadeeasy.com', 'class': 1}, {'ipv6': '2600:1800:5::1', 'ttl': 167121, 'type': 'AAAA', 'name': 'ns5.dnsmadeeasy.com', 'class': 1}, {'ipv4': '208.80.124.13', 'ttl': 167121, 'type': 'A', 'name': 'ns6.dnsmadeeasy.com', 'class': 1}, {'ipv4': '208.80.126.13', 'ttl': 167121, 'type': 'A', 'name': 'ns7.dnsmadeeasy.com', 'class': 1}], 'answers': [{'ipv4': '130.211.142.34', 'ttl': 1174, 'type': 'A', 'name': 'www.hello.com', 'class': 1}], 'flags': {'aa': 0, 'rcode': 0, 'rd': 1, 'opcode': 0, 'ra': 1, 'type': 'response', 'tc': 0}, 'authority': [{'ns': 'ns5.dnsmadeeasy.com', 'ttl': 172174, 'type': 'NS', 'name': 'hello.com', 'class': 1}, {'ns': 'ns6.dnsmadeeasy.com', 'ttl': 172174, 'type': 'NS', 'name': 'hello.com', 'class': 1}, {'ns': 'ns7.dnsmadeeasy.com', 'ttl': 172174, 'type': 'NS', 'name': 'hello.com', 'class': 1}], 'questions': [{'type': 'A', 'name': 'www.hello.com', 'class': 1}], 'identification': 53031, 'protocol_type': 'DNS'}

    """
    def word(pos):
        return (ord(packet[pos]) << 8) + ord(packet[pos + 1])
    def dword(pos):
        return (word(pos) << 16) + word(pos + 2)
    def resource_record(idx):
        rr_idx = idx
        name, idx = read_label(idx)
        tp = word(idx)
        cls = word(idx + 2)
        ttl = dword(idx + 4)
        rlen = word(idx + 8)
        rr = {
            'name' : name,
            'type' : rr_types.get(tp, tp),
            'class' : cls,
            'ttl' : ttl
        }

        rrdata = packet[idx + 10:idx + 10 + rlen]
        if tp == 1:
            rr['ipv4'] = socket.inet_ntop(socket.AF_INET, rrdata)
        elif tp == 28:
            rr['ipv6'] = socket.inet_ntop(socket.AF_INET6, rrdata)
        elif tp == 2:
            rr['ns'], _ = read_label(idx + 10)
        elif tp == 12:
            rr['ptr'], _ = read_label(idx + 10)
        elif tp == 5:
            rr['cname'], _ = read_label(idx + 10)
        elif tp == 15:
            rr['preference'] = word(idx + 10)
            rr['mx'], _ = read_label(idx + 12)
        elif tp == 41:
            #Opt type
            pass
        elif tp == 6:
            rr['soa'] = soa = {}
            soa_idx = idx + 10
            soa['mname'], soa_idx = read_label(soa_idx)
            soa['rname'], soa_idx = read_label(soa_idx)
            soa['serial']  = dword(soa_idx +  0)
            soa['refresh'] = dword(soa_idx +  4)
            soa['retry']   = dword(soa_idx +  8)
            soa['expire']  = dword(soa_idx + 12)
            soa['minimum'] = dword(soa_idx + 16)
        elif tp in [16, 99]:
            name = 'txt' if tp == 16 else 'spf'
            rr[name] = []
            i = 0
            while i < len(rrdata):
                l = ord(rrdata[i])
                i += 1
                rr[name].append(rrdata[i:i + l])
                i += l
        else:
            rr['UNKNOWN'] = rrdata
            rr['rlen'] = rlen
        return (rr, idx + rlen + 10)

    def resource_records(idx, count):
        answers = []
        for _ in range(count):
            rr, idx = resource_record(idx)
            answers.append(rr)

        return (answers, idx)

    def questions(idx):
        questions = []
        for _ in range(word(4)):
            #Name has been read
            name, idx = read_label(idx)
            t = word(idx)
            questions.append({
                'name' : name,
                'type' : rr_types.get(t, t),
                'class' : word(idx + 2)
            })
            idx += 4
        return (questions, idx)

    def read_label(idx):
        qname = []
        while True:
            l = ord(packet[idx])
            if l >> 6 == 3:
                #Ptr
                qname.append(read_label(word(idx) & 0x3fff)[0])
                idx += 2
                break
            else:
                #String
                idx += 1
                if l is 0:
                    break
                qname.append(packet[idx:idx + l])
                idx += l
        return ('.'.join(qname), idx)
        

    rr_types = { 1 : 'A', 28 : 'AAAA', 5 : 'CNAME', 15 : 'MX', 2 : 'NS', 12 : 'PTR', 6 : 'SOA', 33 : 'SRV', 16 : 'TXT', 99 : 'SPF' }
    p = {"protocol_type" : "DNS"}

    p['identification'] = word(0)
    f = word(2)
    p['flags'] = {
        'type' : 'response' if f & 0x8000 else 'query',
        'opcode' : (f >> 11) & 0xf,
        'aa' : (f >> 10) & 1,
        'tc' : (f >> 9) & 1,
        'rd' : (f >> 8) & 1,
        'ra' : (f >> 7) & 1,
        'rcode' : f & 0xf
    }

    p['questions'], idx = questions(12)
    p['answers'], idx = resource_records(idx, word(6))
    p['authority'], idx = resource_records(idx, word(8))
    p['additional'], idx = resource_records(idx, word(10))

    return p

if __name__ == "__main__":
    import doctest
    doctest.testmod()
