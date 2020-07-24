#!/usr/bin/env python

import os
import logging

from optparse import OptionParser

from . import Injector, InjectorException
from .__info__ import __authors__, __version__, __description__

# Enable logging
logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
LOG_OK = 25
logging.addLevelName(LOG_OK, "OK")
logger = logging.getLogger('mlibinjector')


def main():
	desc = '''[mlibinjector %s] -  %s - %s''' % (__version__, __description__, ' & '.join(__authors__))

	parser = OptionParser(description=desc, version='mlibinjector version: 1.0', usage="usage: %prog [options] apkfile")
	parser.add_option('-s', action='store_true', dest='sign', help='Sign apk')
	parser.add_option('-d', action='store_true', dest='decompile', help='Decompile using apktool')
	parser.add_option('-b', action='store_true', dest='build', help='Build & Sign & Zipalign')
	parser.add_option('-e', action='store_true', dest='enableDebug', help='Enable debug mode for apk')
	parser.add_option('-n', action='store_true', dest='injectNetconf', help='Inject a custon network_security_config.xml file')
	parser.add_option('-i', action='store_true', dest='injectFrida', help='Inject frida-gadget in *listen* mode (requires -p)')
	parser.add_option('-p', action='store', dest='libPath', help='Absolute path to downloaded frida-gadgets (.so) files')
	parser.add_option('-c', action='store', dest='confpath', help='Absolute path to the frida-gadgets config file (.config.so)')
	parser.add_option('-f', action='store_true', dest='force', help='Force decompilation and overwrite previous one')
	parser.add_option('--use-aapt2', action='store_true', dest='aapt2', help='Use aapt2 when rebuilding APKs')
	parser.add_option('--no-src', action='store_true', dest='nosrc', help='Decompile APK without decompiling DEX classes')
	parser.add_option('--no-res', action='store_true', dest='nores', help='Decompile APK without decoding resources')
	parser.add_option('--network', action='store', dest='netconfpath', help='Absolute path to the network_security_config.xml file')
	parser.add_option('--port', action='store', type=int, dest='port', help='Listen frida-gadget on port number in *listen mode*')
	parser.add_option('--host', action='store', dest='host', help='Listen frida-gadget on specific network interface in *listen mode*')
	parser.add_option('--script-file', action='store', dest='scriptfile', help='Path to script file on the device')
	parser.add_option('--script-dir', action='store', dest='scriptdir', help='Path to directory containing frida scripts on the device')
	parser.add_option('--native-lib', action='store', dest='nativelib', help='Name of exisiting native lib. Example "libnative-lib.so"')
	parser.add_option('--arch', action='store', dest='arch', help='Add frida gadget for particular arch.(arm64-v8a|armeabi-v7a|x86|x86_64)')
	parser.add_option('--random', action='store_true', dest='randomize', help='Randomize frida-gadget name')
	parser.add_option('-V', action='store_true', dest='verbose', help='Verbose')
	parser.add_option('-q', action='store_true', dest='quiet', help='Quiet (will only print errors and warnings)')

	(v, args) = parser.parse_args()
	if len(args) != 1:
		logger.error('Please Provide at least one argument')
		parser.print_help()
		os._exit(1)
	apkname = args[0]

	try:
		inj = Injector(apkname)
	except InjectorException as e:
		logger.error(e)
		parser.print_help()
		os._exit(1)

	# Injector flags
	if((v.port) and (v.port in range(1, 65535))):
		inj.port = v.port

	if v.host:
		inj.host = v.host

	if v.force:
		inj.force = v.force

	if v.netconfpath:
		inj.netconfpath = v.netconfpath

	if v.confpath:
		inj.confpath = v.confpath

	if v.scriptfile:
		inj.scriptfile = v.scriptfile

	if v.scriptdir:
		inj.scriptdir = v.scriptdir

	if v.nativelib:
		inj.nativelib = v.nativelib

	if v.randomize:
		inj.randomize_lib()

	if v.verbose:
		logger.setLevel(logging.DEBUG)

	if v.quiet:
		logger.setLevel(logging.WARN)

	if v.arch:
		archs = v.arch.split(',')
		for a in archs:
			if a not in Injector.abi:
				logger.error('"{}" arch is not supported'.format(a))
				os._exit(1)

		inj.arch = archs

	# Injector actions
	try:
		if(v.sign):
			inj.sign_apk()

		elif(v.decompile):
			inj.decompile_apk(v.nores, v.nosrc)

		elif(v.build):
			inj.build_and_sign(v.aapt2)

		elif(v.enableDebug):
			inj.enable_debugging()

		elif(v.injectNetconf):
			inj.inject_network_security_config()

		elif(v.injectFrida and v.libPath):
			inj.inject_frida_gadget(v.libPath)

		else:
			logger.error('No action specified')
			os._exit(1)
	except InjectorException as e:
		logger.error(e)
		os._exit(1)

if __name__ == '__main__':
	main()
