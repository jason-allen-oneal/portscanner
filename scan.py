#!/usr/bin/env python

import math
import threading
import socket
import random
from queue import Queue
from probe import Probe
from scapy.all import *
from scapy.all import TCP_SERVICES,UDP_SERVICES
from tabulate import tabulate

class Scan:
	def __init__(self, ip, ports, options, utils):
		self.utils = utils
		self.ip = ip
		self.ports = ports
		self.options = options
		self.queue = Queue()
		self.openPorts = []
		self.filtered = []
		self.unfiltered = []
	
	def worker(self):
		while not self.queue.empty():
			port = self.queue.get()
			result = self.scan(port)
			
			# closed port
			if result == -1:
				if self.options.verbose:
					self.utils.msg("Port: "+str(port)+": Closed", 'info')
			
			# filtered port
			if result == 0:
				self.filtered.append(port)
				if self.options.verbose:
					self.utils.msg("Port "+str(port)+": Filtered", 'info')
			
			# unfiltered port
			if result == 1:
				self.unfiltered.append(port)
				if self.options.verbose:
					self.utils.msg("Port "+str(port)+": Unfiltered", 'info')
					
			# open port
			if result == 2:
				self.openPorts.append(port)
				if not self.options.quiet:
					self.utils.msg('Port '+str(port)+': Open', 'success')
			
			# open|filtered port
			if result == 3:
				self.filtered.append(port)
				if not self.options.quiet:
					self.utils.msg("Port "+str(port)+": Open|Filtered", 'info')
		
	def run(self):
		resp = sr1(IP(dst=self.ip)/ICMP(), timeout=self.options.timeout, verbose=0)
		if resp == None:
			self.utils.msg("This host is not responding. Exiting...", 'error')
			exit(1)
		
		for port in self.ports:
			self.queue.put(port)
		
		self.utils.msg('Host is up. Beginning %s scan of %d ports on %s' % (self.options.scan, len(self.ports), self.ip), 'info')
		thread_list = []
		
		for t in range(self.options.threads):
			thread = threading.Thread(target=self.worker)
			thread_list.append(thread)
		
		for thread in thread_list:
			thread.start()
		
		for thread in thread_list:
			thread.join()
		
		openPorts = []
		for p in self.openPorts:
			service = socket.getservbyport(p)
			openPorts.append([p, service])
		
		testedCt = len(self.ports)
		openCt = len(openPorts)
		filteredCt = len(self.filtered)
		closedCt = ((testedCt - openCt) - filteredCt)
		
		print("")
		self.utils.msg('Scan complete.', 'info')
		self.utils.msg(str(closedCt)+' closed ports.', 'info')
		print("")
		if openCt > 0:
			self.utils.msg('Open ports', 'success')
			print(tabulate(openPorts, ['Port', 'Service'], tablefmt="github"))
		print("")
		if filteredCt > 0:
			self.utils.msg('Filtered ports', 'warn')
			print(tabulate(self.filtered, ['Port', 'Service'], tablefmt='github'))
	
	def scan(self, port):
		probe = Probe(self.ip, port, self.options, self.utils)
		return probe.run()