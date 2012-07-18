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
from os import getcwd,path
from glob import iglob
from re import compile

modules={}
prot_match={}

p=path.dirname(__file__)

for f in iglob(p+'/*.py'):
	f=path.basename(f)[:-3]
	if f[:2]=='__':
		continue
	tmp=__import__('TcpExtract.modules.'+f, fromlist=[f,])
	modules[f]=getattr(tmp,f)
	prot_match[f]=[]
	for m in tmp.matchlist:
		prot_match[f].append(compile(m))
	prot_match[f]=tuple(prot_match[f])
del m,f,iglob,getcwd,path,compile,p
