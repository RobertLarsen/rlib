import pcapy
import os

def pcap_files(fpath):
    yield fpath
    count = 0
    while True:
        count += 1
        fname = '%s%d' % (fpath, count)
        if os.path.isfile(fname): yield fname
        else: break

def pcap_packets(fpath):
    """
    Iterates through all pcap files specified by specified filename, opens each and yields all packets within.
    Yields pcap header, packet and pcap object.
    """
    for f in pcap_files(fpath):
        p = pcapy.open_offline(f)
        while True:
            hdr, packet = p.next()
            if hdr is None: break
            yield (hdr, packet, p)
