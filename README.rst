==========
tcpextract
==========

https://www.abnorm.org/projects/tcpextract/
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Extract files from captured TCP sessions. Support live streams and pcap files.

Supported protocols are:

* HTTP (GET)

Requirements
------------
* Python 2.5 or Python 3 or later
* pynids (http://jon.oberheide.org/pynids/)

Install
-------

To install last stable release or older releases `dowload <https://github.com/faust/tcpextract/downloads>`_ the tarball
and extract it::

	$ tar xzvvf tcpextract-*.tar.gz
	$ cd tcpextract-*
	$ sudo python setup.py install

To install from git please run::

	$ git clone https://github.com/faust/tcpextract.git
	$ cd tcpextract
	$ sudo python setup.py install

Usage
-----
When you run tcpextract, by default, it will listen on any avaible interface and will put extracted files in './output'.
Please remember that capturing live streams will require root privileges.
Live sniffing is really slow. If you can, use tcpdump or something else to capture data.

If you want further information on how to change default behavior please run::

	$ tcpextract --help

Extending
---------
tcpextract is modular, so it is easy to extend.

Modules are in TcpExtract.modules package. All you need to do to create your own module is to
create a new file in that directory. Your module must contain a global variable called "matchlist"
which is a python list or tuple containing one or more regexp needed to recognize the protocol.

You will also need to create a new class with the same name of the module which is inherited from
TcpExtract.Plugin. Your class must implements the "getFile" method which can use "self.other_stream" and
"self.matched_stream" lists to read the next file and append it to "self.files" list as a tuple in this format::

	(Filename, # Can be None
	file_extension, # if Filename is given this will not be used
	file_contents)

Licensing
---------
tcpextract is released under `GPLv3 <https://www.gnu.org/licenses/gpl-3.0.html>`_ or later.

Contact
-------
You can contact the Author using `this form  <https://www.abnorm.org/contact/>`_
