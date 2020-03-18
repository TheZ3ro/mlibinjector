#!/usr/bin/env python

__author__ = 'TheZero'
__description__ = 'A handy script to inject Frida-Gadgets and enable debugging in Android applications'

import os

from optparse import OptionParser
from termcolor import colored

from . import Injector, InjectorException

def main():
	desc = '''[mlibinjector] -  %s - %s''' % (__description__, __author__)

	parser = OptionParser(description=desc, version='mlibinjector version: 1.0', usage="usage: %prog [options] apkfile")
	parser.add_option('-s', action='store_true', dest='sign', help='Sign apk')
	parser.add_option('-d', action='store_true', dest='decompile', help='Decompile using apktool')
	parser.add_option('-b', action='store_true', dest='build', help='Build & Sign & Zipalign')
	parser.add_option('-e', action='store_true', dest='enableDebug', help='Enable debug mode for apk')
	parser.add_option('-i', action='store_true', dest='injectFrida', help='Inject frida-gadget in *listen* mode (requires -p)')
	parser.add_option('-p', action='store', dest='libPath', help='Absolute path to downloaded frida-gadgets (.so) files')
	parser.add_option('-c', action='store', dest='confpath', help='Absolute path to the frida-gadgets config file (.config.so)')
	parser.add_option('-f', action='store_true', dest='force', help='Force decompilation and overwrite previous one')
	parser.add_option('--port', action='store', type=int, dest='port', help='Listen frida-gadget on port number in *listen mode*')
	parser.add_option('--host', action='store', dest='host', help='Listen frida-gadget on specific network interface in *listen mode*')
	parser.add_option('--script-file', action='store', dest='scriptfile', help='Path to script file on the device')
	parser.add_option('--script-dir', action='store', dest='scriptdir', help='Path to directory containing frida scripts on the device')
	parser.add_option('--native-lib', action='store', dest='nativelib', help='Name of exisiting native lib. Example "libnative-lib.so"')
	parser.add_option('--arch', action='store', dest='arch', help='Add frida gadget for particular arch.(arm64-v8a|armeabi-v7a|x86|x86_64)')
	parser.add_option('--random', action='store_true', dest='randomize', help='Randomize frida-gadget name')
	parser.add_option('-V', action='store_true', dest='verbose', help='Verbose')

	(v, args) = parser.parse_args()
	if len(args) != 1:
		parser.print_help()
		print(colored('E: Please Provide at least one argument', color='red'))
		os._exit(1)
	apkname = args[0]

	try:
		inj = Injector(apkname)
	except InjectorException as e:
		parser.print_help()
		print(colored(e, color='red'))
		os._exit(1)

	# Injector flags
	if((v.port) and (v.port in range(1, 65535))):
		inj.port = v.port

	if v.host:
		inj.host = v.host

	if v.force:
		inj.force = v.force

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
		inj._verbose = True

	if v.arch:
		archs = v.arch.split(',')
		for a in archs:
			if a not in Injector.abi:
				print(colored('%s arch is not supported' % a))
				os._exit(1)

		inj.arch = archs

	# Injector actions
	try:
		if(v.sign):
			inj.sign_apk()

		elif(v.decompile):
			inj.decompile_apk()

		elif(v.build):
			inj.build_and_sign()

		elif(v.enableDebug):
			inj.enable_debugging()

		elif(v.injectFrida and v.libPath):
			inj.inject_frida_gadget(v.libPath)

		else:
			parser.print_help()
	except InjectorException as e:
		parser.print_help()
		print(colored(e, color='red'))
		os._exit(1)

if __name__ == '__main__':
	main()
