#make directory
#ICMP : all icmp packets
#DNS  : all dst 53 packets and src 53 packets
#SCAN and MISC : all flow with packets num <= 2
#insideserver : ports <=1024 3306, 3389
#outside      : 80, 443,   
#? how to detect ssh, telnet service password crack down mutilple dstport? similar connection length, short connection length, short connection time
#? how to detect ddos attack
import os
import os.path
import shutil
import getopt
import sys





class CTAConfig():
	keyip  = "202.119.209.199"
	#keyip  = ""
	srcdir = "original"
	dstdir = "handled"
	serverSet = set()
	remoteServerSet = set()

class FlowSpec():
	def __init__(self, tokens):
		self.filename = tokens[0]
		self.sport  = int(tokens[1])
		self.dport  = int(tokens[2])
		self.proto  = int(tokens[4])
		self.pktcnt = int(tokens[6])
		self.sportcnt  = int(tokens[8])
		self.dportcnt  = int(tokens[10])

	def classify(self):
		#print self.proto, self.pktcnt, self.sport, self.dport
		if self.proto == 1:
			self.moveToDir("icmp")
		elif (self.sport == 53) or (self.dport == 53):
			self.moveToDir("dns")
		elif self.pktcnt <= 2:
			self.moveToDir("misc")
		elif ((self.sport > 0) and (self.sport <=1024)) or (self.sport in CTAConfig.serverSet):
			self.moveToDir("inside"+str(self.sport))
		elif (self.dport in CTAConfig.remoteServerSet):
			self.moveToDir("outside"+str(self.dport))
		else:
			pass

	def moveToDir(self,subdir):
		fulldir = os.path.join(CTAConfig.dstdir, subdir)
		if not os.path.exists(fulldir):
			os.mkdir(fulldir)
		srcfile = os.path.join(CTAConfig.dstdir, self.filename)
		dstfile = os.path.join(fulldir, self.filename)
		shutil.move(srcfile, dstfile)

def processTraffic(specfile):
	f = open(specfile)
	flowlist = []
	for line in f:
		tokens = line.split()
		if(len(tokens) != 11):
			continue
		flow = FlowSpec(tokens)
		flowlist.append(flow)
	f.close()

	for flow in flowlist:
		flow.classify()
		

def initConfig():
	CTAConfig.serverSet.add(3306)
	CTAConfig.serverSet.add(3389)
	CTAConfig.serverSet.add(1433)

	CTAConfig.remoteServerSet.add(80)
	CTAConfig.remoteServerSet.add(443)
	
def Usage():
	pass

def main():
	try: 
		opts, args = getopt.getopt(sys.argv[1:], 'hk:d:', ["help", "keyip=", "dstdir="])
	except getopt.GetoptError as err:
		print str(err)
		usage()
		sys.exit(2)

	for o, a in opts:
		if o in ("-h", "--help"):
			usage()
			sys.exit()
		elif o in ("-k", "--keyip"):
			print 'key', a
			CTAConfig.keyip = a
		elif o in ("-d", "--dstdir"):
			CTAConfig.dstdir = a
		else:
			assert False, "unhandled option"
	initConfig()
	print "KEYIP", CTAConfig.keyip
	print "DSTDIR", CTAConfig.dstdir


	processTraffic("flowspec")


if __name__ == '__main__':
	main()
