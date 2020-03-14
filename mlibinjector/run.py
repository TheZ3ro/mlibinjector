#!/usr/bin/env python

__author__ = 'TheZero'
__description__ = 'A handy script to inject Frida-Gadgets and enable debugging in Android applications'

import os

from re import match
from lief import parse as liefparse
from json import dumps as jsondumps
from optparse import OptionParser
from subprocess import check_output as execute, STDOUT
from termcolor import colored
from xml.etree import ElementTree as ET
from shutil import copyfile
from glob import glob
from random import randint, sample
from string import ascii_lowercase
from binascii import hexlify


file_types = {
	'armeabi-v7a': '7f454c4601010100000000000000000003002800010000000000000034000000',
	'arm64-v8a': '7f454c460201010000000000000000000300b700010000000000000000000000',
	'x86': '7f454c4601010100000000000000000003000300010000000000000034000000',
	'x86_64': '7f454c4602010100000000000000000003003e00010000000000000000000000'
}

libdir = {'arm64-v8a': '', 'armeabi-v7a': '', 'x86': '', 'x86_64': ''}
android_namespace = 'http://schemas.android.com/apk/res/android'
ET.register_namespace('android', android_namespace)

tools = os.path.join(os.path.dirname(__file__), 'tools')
apktool = os.path.join(tools, 'apktool.jar')
sign = os.path.join(tools, 'sign.jar')


class Injector():

	def __init__(self):
		self.port = None
		self.host = None
		self.confpath = None
		self.scriptfile = None
		self.scriptdir = None
		self.nativelib = None
		self._verbose = False
		self.gadgetfile = 'libfrida-gadget.so'
		self.configfile = 'libfrida-gadget.config.so'
		return

	def randomize_lib(self, port):
		name = ''.join(x for x in sample(ascii_lowercase, randint(6, 15)))
		self.gadgetfile = 'lib%s.so' % name
		self.configfile = 'lib%s.config.so' % name

	def verbose(self, str):
		if self._verbose:
			print(colored('>>> %s' % str, 'yellow'))

	def exec_cmd(self, cmd):
		self.verbose(' '.join(cmd))
		r = execute(cmd, stderr=STDOUT).decode()
		return r

	def inject_lib(native_lib, gadget_lib):
		"""
		Inject library dependency to pre-existing native lib
		requires android.permission.INTERNET in AndroidManifest.xml
		when using server mode for frida-gadget.
		"""
		native = liefparse(native_lib)
		native.add_library(gadget_lib)
		native.write(native_lib)

	def get_launchable_activity(apk_name):
		"""
		Parses AndroidManifest.xml and returns all launchable activities
		will throw an error for corrupted xml documents
		"""
		manifest_file = apk_name.split('.apk')[0] + '/AndroidManifest.xml'
		name = '{http://schemas.android.com/apk/res/android}name'
		try:
			main_activities = []
			parser = ET.parse(manifest_file)
			root = parser.getroot()
			package_name = root.attrib['package']
			activities = root.findall('application')[0].findall('activity')
			activity_alias = root.findall('application')[0].findall('activity-alias')

			# TODO: Fix this other mess
			if len(activities) > 0:
				for activity in activities:
					intent_filters = activity.findall('intent-filter')
					if len(intent_filters) > 0:
						for intent in intent_filters:
							categories = intent.findall('category')
							if len(categories) > 0:
								for category in categories:
									for val in category.attrib.values():
										if val == 'android.intent.category.LAUNCHER':
											activity_name = activity.attrib[name]
											if activity_name.startswith('.'):
												main_activities.append(package_name + activity_name)
											elif match(r'^[a-zA-Z0-9-_]+$', activity_name):
												main_activities.append(package_name + '.' + activity_name)
											else:
												main_activities.append(activity_name)
			if len(activity_alias) > 0:
				for activity in activity_alias:
					intent_filters = activity.findall('intent-filter')
					if len(intent_filters) > 0:
						for intent in intent_filters:
							categories = intent.findall('category')
							if len(categories) > 0:
								for category in categories:
									for val in category.attrib.values():
										if val == 'android.intent.category.LAUNCHER':
											activity_name = activity.attrib[name]
											if activity_name.startswith('.'):
												main_activities.append(package_name + activity_name)
											elif match(r'^[a-zA-Z0-9-_]+$', activity_name):
												main_activities.append(package_name + '.' + activity_name)
											else:
												main_activities.append(activity_name)
			return main_activities
		except Exception:
			pass

	def decompile_apk(self, apkname):
		"""
		Decompile apk file using apktool.jar
		"""
		self.verbose('Decompiling %s' % (apkname))
		r = self.exec_cmd(["java", "-jar", apktool, "d", "-f", apkname])
		self.verbose(r)
		print(colored('I: Decompiled %s' % (apkname), color='green'))

	def sign_apk(self, apkname):
		"""
		sign apk using default developer certificate via sign.jar
		"""
		self.verbose('Signing %s' % (apkname))
		r = self.exec_cmd(["java", "-jar", sign, apkname])
		self.verbose(r)
		print(colored('I: Signed %s' % (apkname), color='green'))

	def build_and_sign(self, apkname):
		"""
		Build using apktool.jar
		sign again using sign.jar
		"""
		if os.path.isdir(apkname):
			dirname = apkname
			if dirname[-1] == '/':
				dirname = dirname[:-1]
		else:
			dirname = apkname.split('.apk')[0]
		self.verbose('Building apk file')
		r = self.exec_cmd(["java", "-jar", apktool, "b", "-f", dirname])
		self.verbose(r)
		print(colored('I: Build done', color='green'))
		apkname = '%s/dist/%s' % (dirname, dirname + '.apk')
		self.sign_apk(apkname)

	def enable_debugging(self, apkname):
		"""
		Enable debug flag in AndroidManifest.xml
		Uses apktool.jar and sign.jar
		"""
		self.decompile_apk(apkname)
		dirname = apkname.split('.apk')[0]
		filename = dirname + '/AndroidManifest.xml'
		self.verbose('Enabling android-debug:true in %s' % filename)
		fp = open(filename, 'r')
		parser = ET.parse(fp)
		application = parser.getroot().findall('application')[0]
		keyname = '{http://schemas.android.com/apk/res/android}debuggable'
		application.attrib[keyname] = 'true'
		parser.write(filename, encoding='utf-8', xml_declaration=True)
		print(colored('I: Enabled android-debug:true in %s' % filename, color='green'))
		self.build_and_sign(dirname)

	def check_permission(filename, filter):
		"""
		Check apk permission specified in filter by parsing AndroidManifest.xml
		Currently used for checking android.permission.INTERNET permission.
		"""
		verbose('Checking permissions in %s' % filename)
		parser = ET.parse(filename)
		manifest = parser.getroot()
		permissions = manifest.findall('uses-permission')
		if len(permissions) > 0:
			for perm in permissions:
				name = '{%s}name' % android_namespace
				verbose('uses-permission: %s' % (perm.attrib[name]))
				if perm.attrib[name] == filter:
					return True
					break
				else:
					return False
		else:
			verbose('No permissions are defined in %s' % (filename))
			return False

	def add_permission(filename, permission_name):
		"""
		Add permissions to apkfile specified in filter by parsing AndroidManifest.xml
		Currently used for adding android.permission.INTERNET permission.
		"""
		verbose('Adding %s permission to %s' % (permission_name, filename))
		parser = ET.parse(filename)
		manifest = parser.getroot()
		perm_element = ET.Element('uses-permission')
		name = '{%s}name' % android_namespace
		perm_element.attrib[name] = permission_name
		manifest.append(perm_element)
		parser.write(filename, encoding='utf-8', xml_declaration=True)
		print(colored('I: Added %s permission to %s' % (permission_name, filename), 'green'))

	def write_config(filename, host=None, port=None, s_file=None, s_dir=None):
		"""
		Generates frida config file based on supplied parameters
		"""
		frida_conf = {"interaction": {}}
		if (host and port):
			frida_conf["interaction"]["type"] = "listen"
			frida_conf["interaction"]["address"] = host
			frida_conf["interaction"]["port"] = port
			frida_conf["interaction"]["on_load"] = "wait"
		elif port:
			frida_conf["interaction"]["type"] = "listen"
			frida_conf["interaction"]["address"] = "127.0.0.1"
			frida_conf["interaction"]["port"] = port
			frida_conf["interaction"]["on_load"] = "wait"
		elif host:
			frida_conf["interaction"]["type"] = "listen"
			frida_conf["interaction"]["address"] = host
			frida_conf["interaction"]["port"] = "27042"
			frida_conf["interaction"]["on_load"] = "wait"
		elif s_file:
			frida_conf["interaction"]["type"] = "script"
			frida_conf["interaction"]["path"] = s_file
			frida_conf["interaction"]["on_change"] = "reload"
		elif s_dir:
			frida_conf["interaction"]["type"] = "script-directory"
			frida_conf["interaction"]["path"] = s_dir
			frida_conf["interaction"]["on_change"] = "rescan"
		data = jsondumps(frida_conf, indent=2)
		verbose(data)
		open(filename, 'w').write(data)

	def copy_libs(libpath, dirname):
		"""
		copy frida gadgets into /lib/<arch> folders
		"""
		global libdir
		libs = {}
		if len(arch) > 0:
			for k in libdir:
				if k in arch:
					libs[k] = libdir[k]
		# TODO: FIX THIS MESS
		libdir = libs
		for dir in libdir:
			libdir[dir] = os.path.join(dirname, 'lib', dir)
			verbose(libdir[dir])
			if not os.path.exists(libdir[dir]):
				os.makedirs(libdir[dir])
			else:
				verbose('Dir %s already exists' % (libdir[dir]))
		if os.path.exists(libpath):
			lib_files = glob(libpath + '/*.so')
			for src in lib_files:
				sig = hexlify(open(src, 'rb').read(32)).decode()
				for key in libdir:
					if sig == file_types[key]:
						dest = os.path.join(libdir[key], gadgetfile)
						_configfile = os.path.join(libdir[key], configfile)
						verbose('%s --> %s' % (src, dest))
						copyfile(src, dest)
						if confPath is None:
							write_config(_configfile, host=host, port=port, s_file=scriptfile, s_dir=scriptdir)
						else:
							copyfile(confPath, _configfile)

		else:
			print(colored('E: Please provide the path to frida-gadget lib(.so) files', color='red'))
			os._exit(1)

	def inject_smali(filename):
		"""
		Injects smali prologue or smali direct methods in
		launchable activities by parsing smali code  to load frida-gadgets.
		"""
		if nativelib:
			verbose(libdir)
			for key, dir in libdir.iteritems():
				_nativelib = os.path.join(dir, nativelib)
				verbose(_nativelib)
				inject_lib(_nativelib, gadgetfile)
		else:
			_filename = os.path.basename(filename)
			prologue_stmt = """

		const-string v0, "%s"

		invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

	""" % (gadgetfile.split('.so')[0][3:])
			direct_method = """

	.method static constructor <clinit>()V
		.locals 1

		.prologue
		const-string v0, "%s"

		invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

		return-void
	.end method


	""" % (gadgetfile.split('.so')[0][3:])
			verbose('Injecting smali code in %s' % (_filename))
			rf = open(filename, 'r')
			lines = rf.readlines()
			rf.close()
			cursor = None
			s_constructor = False
			eof = len(lines) - 1
			for index, line in enumerate(lines):
				if '# direct methods' in line:
					cursor = index + 1

				if '.method static constructor <clinit>()V' in line:
					cursor = index + 1
					method_start = cursor
					s_constructor = True

				if (s_constructor):
					if (index == cursor):
						# print("Cursor is at %d" %cursor)
						# Found prologue write after it

						if '.prologue' in line:
							lines.insert(cursor + 2, prologue_stmt)
							verbose('Smali prologue injected')
							break

						# No .prologue found write after constructor
						elif '.end method' in line:
							lines.insert(method_start + 1, prologue_stmt)
							verbose('Smali prologue injected')
							break
						else:
							cursor += 1

				# Couldn't find the static constructor, injecting static constructor
				elif (s_constructor is False and cursor is not None and index == eof):
					# print("Index is at %d" %index)
					# print("Cursor is at %d" %cursor)
					lines.insert(cursor, direct_method)
					verbose('Static constructor injected')
					break

			wf = open(filename, 'w')
			wf.writelines(lines)
			wf.close()
			print(colored('I: Smali code written to %s' % (_filename), color='green'))

	def inject_frida_gadget(apkname, libpath):
		"""
		Handles process of injecting Frida gadgets
		"""
		verbose('Injecting frida gagdet in %s' % apkname)
		decompile_apk(apkname)
		dirname = apkname.split('.apk')[0].replace('\\', '/')
		androidmanifest = dirname + '/AndroidManifest.xml'
		name = '{%s}name' % android_namespace
		permission_name = 'android.permission.INTERNET'

		activity_names = get_launchable_activity(apkname)

		if not(scriptfile or scriptdir):
			if check_permission(androidmanifest, permission_name) is False:
				add_permission(androidmanifest, permission_name)
				copy_libs(libpath, dirname)

			else:
				copy_libs(libpath, dirname)
		else:
			copy_libs(libpath, dirname)

		for activity_name in activity_names:
			activity_file_path = activity_name.replace('.', '/')
			main_activityfile = dirname + '/smali/' + activity_file_path + '.smali'
			inject_smali(main_activityfile)

		build_and_sign(apkname)
		print(colored('I: Frida Gadget injected', 'green'))
		print(colored('I: Use command frida -U -n Gadget to connect to gadget :)', 'green'))


def main():
	global _verbose, arch, nativelib, host, port, confPath
	global scriptfile, scriptdir, gadgetfile, configfile

	arch = []

	desc = '''[mlibinjector] -  %s - %s''' % (__description__, __author__)

	parser = OptionParser(description=desc, version='mlibinjector version: 1.0', usage="usage: %prog [options] apkfile")
	parser.add_option('-s', action='store_true', dest='sign', help='Sign apk')
	parser.add_option('-d', action='store_true', dest='decompile', help='Decompile using apktool')
	parser.add_option('-b', action='store_true', dest='build', help='Build & Sign & Zipalign')
	parser.add_option('-e', action='store_true', dest='enableDebug', help='Enable debug mode for apk')
	parser.add_option('-i', action='store_true', dest='injectFrida', help='Inject frida-gadget in *listen* mode (requires -p)')
	parser.add_option('-p', action='store', dest='libPath', help='Absolute path to downloaded frida-gadgets (.so) files')
	parser.add_option('-c', action='store', dest='confpath', help='Absolute path to the frida-gadgets config file (.config.so)')
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

	inj = Injector()

	if((v.port) and (v.port in range(1, 65535))):
		inj.port = v.port

	if v.host:
		inj.host = v.host

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
			if a not in libdir.keys():
				print(colored('%s arch is not supported' % a))
				os._exit(1)

		inj.arch = archs

	if (apkname and os.path.isfile(apkname) and os.access(apkname, os.R_OK)):
		if(v.sign):
			inj.sign_apk(apkname)

		elif(v.decompile):
			inj.decompile_apk(apkname)

		elif(v.build):
			inj.build_and_sign(apkname)

		elif(v.enableDebug):
			inj.enable_debugging(apkname)

		elif(v.injectFrida and v.libPath):
			inj.inject_frida_gadget(apkname, v.libPath)

		else:
			parser.print_help()

	elif v.build and (apkname and os.path.isdir(apkname)):
		inj.build_and_sign(apkname)

	else:
		parser.print_help()
		print(colored('E: Please Provide a valid apk file or a directory', color='red'))
		os._exit(1)

if __name__ == '__main__':
	main()
