#!/usr/bin/env python2.7
""" tcpextract - pcap file extractor
    Copyright (C) 2012  https://www.abnorm.org/contact/

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from sys import argv,exit,stderr
from os import mkdir,geteuid,getpid
from os.path import isdir,isfile
from TcpExtract import Nids
from TcpExtract import Parser
import argparse

def main():
	parser = argparse.ArgumentParser(description='Extract files from captured TCP sessions. Support live streams and pcap files.\nLive sniffing is really slow. If you can, use tcpdump or something else to capture data.')
	parser.add_argument('-f','--pcap-file',help='Set pcap file name to be opened.')
	parser.add_argument('-i','--interface',default='all',help='Set interface to sniff on (default %(default)s).')
	parser.add_argument('-d','--output-directory',default='./output',help='Set extracted file destination (default %(default)s).')
	args=parser.parse_args(argv[1:])
	
	directory=args.output_directory
	iface=args.interface
	fname=args.pcap_file
	
	if fname and not isfile(fname):
		stderr.write('ERROR: %s does not exist.\n'%fname)
		exit(2)
		
	if not fname and geteuid()!=0:
		stderr.write('ERROR: You need to be superuser to sniff live streams.\n')
		exit(3)
	
	if not isdir(directory) and not isfile(directory):
		mkdir(directory)
	elif isfile(directory):
		stderr.write('ERROR: %s is not a directory.\n'%directory)
		exit(1)
	
	if not fname:
		print 'To stop: kill %d'%getpid()
	
	NidsTh=Nids(fname=fname,iface=iface)
	NidsTh.start()
	Pth=Parser(NidsTh,directory)
	Pth.start()

if __name__ == '__main__':
	main()
