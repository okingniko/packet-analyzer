import os
import dpkt
import socket
import struct
import math
import binascii
import getopt, sys
import os.path
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
    # keyip  = ""
    srcdir = "original"
    dstdir = "handled"


class FlowEntry():
    def __init__(self, key):
        self.entryID = key
        self.filename = self.entryID
        self.newFilename = self.entryID
        self.fh = None
        self.srcportSet = set()
        self.dstportSet = set()
        self.protocol = 0
        self.pktnum = 0
        self.sport = -1
        self.dport = -1

    def sortKey(self):
        return self.newFilename

    def spec(self):
        fmtstr = "%-60s %5d %5d proto %3d pktcnt %6d sportcnt %4d dportcnt %4d "
        s = fmtstr % (self.newFilename, self.sport, self.dport, self.protocol, self.pktnum, len(self.srcportSet),
                      len(self.dstportSet))
        return s

    def addPacket(self, ts, snaplenbuf, pktlenbuf, pkt, srcip, srcport, dstport, proto):
        # if (self.fh == None):

        self.protocol = proto
        self.pktnum += 1
        if srcip == CTAConfig.keyip:
            self.srcportSet.add(srcport)
            self.dstportSet.add(dstport)
            self.sport = srcport
            self.dport = dstport
        else:
            self.srcportSet.add(dstport)
            self.dstportSet.add(srcport)
            self.sport = dstport
            self.dport = srcport

    def reName(self):
        if self.protocol == 1:
            self.newFilename += '--' + 'icmp';
        else:
            if len(self.srcportSet) != 1:
                self.sport = 000
            self.newFilename += '--' + str(self.sport)

            if len(self.dstportSet) != 1:
                self.dport = 000
            self.newFilename += '--' + str(self.dport)

        self.newFilename += ".pcap"
        srcfullname = os.path.join(CTAConfig.dstdir, self.filename)
        dstfullname = os.path.join(CTAConfig.dstdir, self.newFilename)
        os.rename(srcfullname, dstfullname)
        print
        self.newFilename


def makeKey(srcip, dstip):
    key = ""
    if srcip == CTAConfig.keyip:
        key = srcip + "--" + dstip
    else:
        key = dstip + '--' + srcip

    return key


def calcFlowProp(filename, flowList):
    fullfilename = os.path.join(CTAConfig.dstdir, filename)
    p = open(fullfilename, "rb")
    pcap_header = p.read(24)

    count = 0
    flow = FlowEntry(filename);
    while True:
        ts = p.read(8)
        if (len(ts)) <= 0:
            break
        snaplenbuf = p.read(4)
        snaplen = socket.ntohl(struct.unpack("!I", snaplenbuf)[0])
        pktlenbuf = p.read(4)
        pktlen = socket.ntohl(struct.unpack("!I", pktlenbuf)[0])
        # print pktlen, snaplen

        pkt = p.read(int(snaplen))
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data

        srcint = struct.unpack("!L", ip.src)[0]
        srcstr = socket.inet_ntoa(ip.src)
        dstint = struct.unpack("!L", ip.dst)[0]
        dststr = socket.inet_ntoa(ip.dst)
        # print pktlen, len(pkt), socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        srcport = -1
        dstport = -1
        count += 1
        if ip.p == 6:
            tcp = ip.data
            srcport = tcp.sport
            dstport = tcp.dport
        elif ip.p == 17:
            udp = ip.data
            srcport = udp.sport
            dstport = udp.dport
        elif ip.p == 1:
            pass
        else:
            pass

        flow.addPacket(ts, snaplenbuf, pktlenbuf, pkt, srcstr, srcport, dstport, ip.p)

        if (count % 10000) == 0:
            print
            count
    p.close()
    flow.reName()
    flowList.append(flow)
    flow = None


def processTraffic(listfilename):
    filenamelist = []
    flowList = []
    f = open(listfilename)
    for line in f:
        line = line.strip()
        filenamelist.append(line)
    f.close()

    for filename in filenamelist:
        calcFlowProp(filename, flowList)

    f = open('flowspec', "w")
    flowList.sort(key=FlowEntry.sortKey)
    for flow in flowList:
        f.write(flow.spec() + "\n")
    f.close()

    return


def usage():
    pass


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hk:d:', ["help", "keyip=", "dstdir="])
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
            print
            'key', a
            CTAConfig.keyip = a
        elif o in ("-d", "--dstdir"):
            CTAConfig.dstdir = a
        else:
            assert False, "unhandled option"

    print
    "KEYIP", CTAConfig.keyip
    print
    "DSTDIR", CTAConfig.dstdir

    processTraffic("pcaplist")


if __name__ == '__main__':
    main()
