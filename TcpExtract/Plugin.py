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
import abc 

class Plugin():
	__metaclass__ = abc.ABCMeta
	def __init__(self,data,matched):
		self.matched=matched
		self.matched_stream=data[matched::2]
		self.other_stream=data[matched^1::2]
		self.files=[]
	
	@abc.abstractmethod
	def getFile(self):
		pass
	
	def getFiles(self):
		while len(self.matched_stream) and len(self.other_stream):
			self.getFile()