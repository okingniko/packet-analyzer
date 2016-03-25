import dpkt
import socket
import struct
import math
import binascii
import getopt, sys
import os
from collections import defaultdict



# Global header for pcap 2.4
pcap_global_header = ('D4 C3 B2 A1'
                      '02 00'  # File format major revision (i.e. pcap <2>.4)
                      '04 00'  # File format minor revision (i.e. pcap 2.<4>)
                      '00 00 00 00'
                      '00 00 00 00'
                      'FF FF 00 00'
                      '01 00 00 00')

# pcap packet header that must preface every packet
pcap_packet_header = ('AA 77 9F 47'
                      '90 A2 04 00'
                      'XX XX XX XX'  # Frame Size (little endian)
                      'YY YY YY YY')  # Frame Size (little endian)


class CTAConfig():
    keyip = "202.119.209.199"
    keymask = 32
    # keyip  = ""
    srcdir = "original"
    dstdir = "handled"


class FlowEntry():
    def __init__(self, key):
        self.entryID = key
        self.filename = self.entryID
        self.fullfilename = ""
        self.fh = None

    def initPcapFile(self, pcap_header):
        self.fullfilename = os.path.join(CTAConfig.dstdir, self.filename)
        self.fh = open(self.fullfilename, 'wb')
        self.fh.write(pcap_header)

    def openPcapFile(self):
        self.fh = open(self.fullfilename, 'ab')

    def addPacket(self, ts, snaplenbuf, pktlenbuf, pkt):
        if (self.fh != None):
            self.fh.write(ts)
            self.fh.write(snaplenbuf)
            self.fh.write(pktlenbuf)
            self.fh.write(pkt)

    def closePcap(self):
        self.fh.close()


def makeKey(srcip, dstip):
    key = ""
    if srcip == CTAConfig.keyip:
        key = srcip + "--" + dstip
    else:
        key = dstip + '--' + srcip

    return key


def splitTraffic(filename, flowEntryDict):
    # filename = "202.119.209.199.pcap"

    p = open(filename, "rb")
    pcap_header = p.read(24)

    count = 0
    while True:
        ts = p.read(8)
        if (len(ts)) <= 0:
            break
        snaplenbuf = p.read(4)
        snaplen = socket.ntohl(struct.unpack("!I", snaplenbuf)[0])
        pktlenbuf = p.read(4)
        pktlen = socket.ntohl(struct.unpack("!I", pktlenbuf)[0])
        pkt = p.read(int(snaplen))
        # print pktlen, snaplen

        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data
        srcint = struct.unpack("!L", ip.src)[0]
        srcstr = socket.inet_ntoa(ip.src)
        dstint = struct.unpack("!L", ip.dst)[0]
        dststr = socket.inet_ntoa(ip.dst)
        # print pktlen, len(pkt), socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        count += 1

        key = makeKey(srcstr, dststr)
        if (key in flowEntryDict):
            flowEntryDict[key].addPacket(ts, snaplenbuf, pktlenbuf, pkt)

        else:
            flowEntryDict[key] = FlowEntry(key);
            flowEntryDict[key].initPcapFile(pcap_header);
            flowEntryDict[key].addPacket(ts, snaplenbuf, pktlenbuf, pkt)

        if (count % 10000) == 0:
            print
            count

    p.close()


def processTraffic():
    flowEntryDict = {}
    for filename in os.listdir(CTAConfig.srcdir):
        fullfilename = os.path.join(CTAConfig.srcdir, filename)
        print
        fullfilename
        splitTraffic(fullfilename, flowEntryDict)
    f = open("pcaplist", 'w')
    for key, flowEntry in flowEntryDict.iteritems():
        flowEntry.closePcap()
        f.write(flowEntry.filename + "\n")
    f.close()


def usage():
    print
    "Please see '-h' or '--help' option"
    pass


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hk:s:d:', ["help", "keyip=", "srcdir=", "dstdir="])
    except getopt.GetoptError as err:
        print
        str(err)
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-k", "--keyip"):
            if a.find("/") != -1:
                toks = a.split("/")
                CTAConfig.keyip = toks[0]
                CTAConfig.keymask = int(toks[1])
            else:
                CTAConfig.keyip = a
                CTAConfig.keymask = 32
            print
            'key', CTAConfig.keyip, CTAConfig.keymask

        elif o in ("-s", "--srcdir"):
            CTAConfig.srcdir = a
        elif o in ("-d", "--dstdir"):
            CTAConfig.dstdir = a
        else:
            assert False, "unhandled option"

    print
    "KEYIP", CTAConfig.keyip
    print
    "SRCDIR", CTAConfig.srcdir
    print
    "DSTDIR", CTAConfig.dstdir

    processTraffic()


if __name__ == '__main__':
    main()
