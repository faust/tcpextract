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
import re
from modules import modules,prot_match

class ProtocolNotSupported(BaseException):
	def __init__(self, e):
		self.val=e
	def __str__(self):
		return 'Protocol "%s" not supported.'%self.val

class FileExtractor:
	
	def __init__(self,data=None,protocol=None):
		self.matched=0
		self.files=[]
		self.supported_protocols=tuple(prot_match.keys())
		if data:
			self.setData(data,protocol)
		
	def setData(self,data,protocol=None):
		self.data=data
		if not protocol:
			self.autoDetect()
		elif protocol in self.supported_protocols:
			self.protocol=protocol
		else:
			raise ProtocolNotSupported(protocol)
	
	def autoDetect(self):
		if self.data[0]=='' or self.data[1]=='':
			raise ProtocolNotSupported('Unidentified')
		head_0=self.data[0].splitlines(True)[0]
		head_1=self.data[1].splitlines(True)[0]
		for prot,mls in prot_match.iteritems():
			for ml in mls:
				if re.match(ml,head_0):
					self.protocol=prot
					self.matched=0
					return
				elif re.match(ml,head_1):
					self.protocol=prot
					self.matched=1
					return
		raise ProtocolNotSupported('Unidentified')
	
	def getFiles(self):
		plugin=modules[self.protocol](self.data,self.matched)
		plugin.getFiles()
		self.files.extend(plugin.files)