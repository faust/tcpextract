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
import threading
from Nids import Nids
from TcpExtract import FileExtractor,ProtocolNotSupported

class Parser(threading.Thread):
	def __init__(self,nids,directory):
		threading.Thread.__init__(self)
		self.nids=nids
		self.directory=directory
		self.files=[]
	def run(self):
		i=0
		while self.nids.isAlive() or not Nids.queue.empty():
			try:
				tmp=Nids.queue.get()
				s=FileExtractor(tmp)
			except ProtocolNotSupported:
				continue
			s.getFiles()
			for f in s.files:
				if f[0]:
					fd=open(self.directory+'/'+f[0],'w')
				else:
					fd=open(self.directory+'/file%02d.%s'%(i,f[1]),'w')
					i+=1
				fd.write(f[2])
				fd.close()
