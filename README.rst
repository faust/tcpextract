==========
tcpextract
==========

https://www.abnorm.org/projects/tcpextract/
-------------------------------------------

Extract files from captured TCP sessions. Support live streams and pcap files.

Supported protocols are:

* HTTP (GET)

Requirements
^^^^^^^^^^^^
* Python 2.5 or Python 3 or later
* pynids (http://jon.oberheide.org/pynids/)

Install
^^^^^^^
Gentoo users:
-------------
You should enable the `Abnorm Overlay <https://www.abnorm.org/portage/>`_ then you can install it::
emerge tcpextract

Using pip:
----------
::
pip install tcpextract

Manual installation and git installation:
-----------------------------------------
To manually install last stable release or older releases `dowload <https://github.com/faust/tcpextract/downloads>`_ the tarball
and extract it::

	$ tar xzvvf tcpextract-*.tar.gz
	$ cd tcpextract-*
	$ sudo python setup.py install

To install from git please run::

	$ git clone https://github.com/faust/tcpextract.git
	$ cd tcpextract
	$ sudo python setup.py install

Usage
^^^^^
When you run tcpextract, by default, it will listen on any avaible interface and will put extracted files in './output'.
Please remember that capturing live streams will require root privileges.
Live sniffing is really slow. If you can, use tcpdump or something else to capture data.

If you want further information on how to change default behavior please run::

	$ tcpextract --help

Extending
^^^^^^^^^
tcpextract is modular, so it is easy to extend.

If you are looking for further information about writing modules to support more protocols please read the `Wiki <https://github.com/faust/tcpextract/wiki/Extending>`_

Licensing
^^^^^^^^^
tcpextract is released under `GPLv3 <https://www.gnu.org/licenses/gpl-3.0.html>`_ or later.

Contact
^^^^^^^
You can contact the Author using `this form  <https://www.abnorm.org/contact/>`_
