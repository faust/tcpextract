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
from TcpExtract.Plugin import Plugin

matchlist=('^GET [^\s]+ HTTP/1\.\d{1}\r\n$',)

class HttpGet(Plugin):
	
	def readServerOutput(self,data):
		lines=data.splitlines(True)
		for l in lines[:]:
			lines=lines[1:]
			if l.startswith('Content-Type:'):
				ext=l.split(':')[1].split('/')[1].strip()
			elif l=='\r\n':
				break
		return (None,ext,''.join(lines))
	
	def readClientOutput(self,data):
		lines=data.splitlines(True)
		fn=lines[0].split()[1]
		for l in lines[1:]:
			if l.startswith('Host:'):
				host=l.split(':')[1].strip()
		filename=host+fn.replace('/','_')
		return filename
	
	def getFile(self):
		tmp=self.other_stream[0].splitlines(True)
		if self.other_stream[0]=='' or self.matched_stream[0]=='' or not tmp[0].endswith('200 OK\r\n'):
			self.matched_stream=self.matched_stream[1:]
			self.other_stream=self.other_stream[1:]	
			return
		filename=self.readClientOutput(self.matched_stream[0])
		self.matched_stream=self.matched_stream[1:]
		tmp=list(self.readServerOutput(self.other_stream[0]))
		tmp[0]=filename
		self.files.append(tuple(tmp))
		self.other_stream=self.other_stream[1:]	