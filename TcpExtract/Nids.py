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
from Queue import Queue
import threading,nids

class Nids(threading.Thread):
	queue=Queue()
	end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
	
	def __init__(self,fname=None,iface='all'):
		threading.Thread.__init__(self)
		nids.param("scan_num_hosts", 0)
		nids.chksum_ctl([('0.0.0.0/0', False)])
		if fname:
			nids.param("filename", fname)
		else:
			nids.param("device", iface)
		nids.init()
		nids.register_tcp(Nids.handler)
	
	@staticmethod
	def handler(tcp):
		if tcp.nids_state == nids.NIDS_JUST_EST:
			tcp.client.collect = 1
			tcp.server.collect = 1
		elif tcp.nids_state == nids.NIDS_DATA:
			tcp.discard(0)
		elif tcp.nids_state in Nids.end_states:
			Nids.queue.put((tcp.server.data[:tcp.server.count],tcp.client.data[:tcp.client.count]))
	
	def run(self):
		nids.run()