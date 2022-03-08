#!/usr/bin/env python

import sys, re, random, time
import urllib.parse
import asyncio
from optparse import OptionParser, OptionGroup
import socket
from utils import Utils
from scan import Scan


def optionControl(utils):
	parser = OptionParser(usage='%prog [options]\r\nexample: python3 %prog -T 127.0.0.1\r\nexample: python3 %prog -T www.example.com -T 127.0.0.1', version="%prog 0.1")
	
	parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Show all output")
	parser.add_option("-q", "--quiet", action="store_false", dest="quiet", default=False, help="Minimize output")
	parser.add_option("-t", "--threads", default=10, dest="threads", help="Number of worker threads to spawn")
	parser.add_option("-w", "--timeout", default=5, dest="timeout", help="Maximum time to wait for a response (in seconds)")
	parser.add_option("-r", "--retries", default=3, dest="retries", help="Number of times to retry a probe before dropping it")
	parser.add_option('-O', '--out', default=None, dest='write', help="File to which to write the program's output")
	
	scanGroup = OptionGroup(parser, "Scan Types", "Select a type of scan to run. (Default is SYN)")
	scanGroup.add_option("-A", "--ack", action="store_const", const='ack', dest='scan', help="Perform ACK scan.")
	scanGroup.add_option("-F", "--fin", action="store_const", const='fin', dest='scan', help="Perform FIN scan.")
	scanGroup.add_option("-N", "--null", action="store_const", const='null', dest='scan', help="Perform NULL scan.")
	scanGroup.add_option("-S", "--syn", action="store_const", const='syn', dest='scan', help="Perform SYN scan.")
	scanGroup.add_option("-B", "--tcp", action="store_const", const='tcp', dest='scan', help="Basic TCP scan.")
	scanGroup.add_option("-U", "--udp", action="store_const", const='udp', dest='scan', help="Perform UDP scan.")
	parser.add_option_group(scanGroup)
	scanGroup.add_option("-X", "--xmas", action="store_const", const='xmas', dest='scan', help="Perform XMAS scan.")
	
	targetGroup = OptionGroup(parser, "Target Information", "Information about the target(s)")
	targetGroup.add_option('--targets', '-T', dest='targets', action='append', help='*REQUIRED* The targets you would like to scan. Can be a domain, IP address, range of IP addresses, or CIDR range.')
	targetGroup.add_option('--ports', '-p', dest='ports', action='store', default='basic', help='Ports to scan. Can be "basic" (1-1024), "all" (1-65536), or a comma-separated list of ports. Defaults to "basic".')
	parser.add_option_group(targetGroup)
	
	options, args = parser.parse_args()
	if options.scan is None:
		options.scan = 'syn'
	
	if options.targets is None:
		parser.print_help()
		exit(1)
	
	return (options, args)


def main():
	utils = Utils()
	(options, args) = optionControl(utils)
	
	utils.msg("Port Scanner by Jason O'Neal", 'title')
	utils.msg('Please use responsibly.', 'title')
	
	if options.write is not None:
		sys.stdout = open(options.write, "a")
	
	targetList = []
	
	for target in options.targets:
		if '/' in target:
			valid = utils.urlValidator(target)
			if valid is not False:
				domain = valid.netloc
				target = socket.gethostbyname(domain)
				targetList.append(target)
			else:
				ips = utils.returnCIDR(target)
				for ip in ips:
					targetList.append(ip)
		elif '-' in target:
			ips = utils.iprange(target)
			for ip in ips:
				targetList.append(ip)
		else:
			targetList.append(socket.gethostbyname(target))
	
	for t in targetList:
		if not options.quiet:
			utils.msg('Preparing to scan %s' % t, 'info')
		
		ports = []
		if options.ports:
			if options.ports == 'all':
				ports = list(range(1, 65536))
			elif options.ports == 'basic':
				ports = list(range(1, 1025))
			else:
				for x in options.ports.split(','):
					ports.append(int(x.strip()))
		else:
			ports = range(1, 1025)
		
		startTime = time.time()
		random.shuffle(ports)
		
		try:
			scan = Scan(t, ports, options, utils)
			scan.run()
		except KeyboardInterrupt:
			print("\n\n")
			utils.msg('Program halted by user', 'error')
			utils.msg('Shutting down.', 'error')
			sys.exit(1)
		
		utils.msg('Scan completed in %d seconds.' % (time.time() - startTime), 'info')
		sys.stdout.close()
		exit(0)

if __name__ == '__main__':
	main()