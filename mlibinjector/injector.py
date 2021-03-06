import os
import logging

from re import match
from lief import parse as liefparse
from json import dumps as jsondumps
from subprocess import Popen, STDOUT, PIPE, CalledProcessError
from termcolor import colored
from xml.etree import ElementTree as ET
from shutil import copyfile
from glob import glob
from random import randint, sample
from string import ascii_lowercase
from binascii import hexlify

from .helpers import smali_prologue, smali_direct_method, xml_netsecconf

android_namespace = 'http://schemas.android.com/apk/res/android'
ET.register_namespace('android', android_namespace)

tools = os.path.join(os.path.dirname(__file__), 'tools')
apktool = os.path.join(tools, 'apktool.jar')
sign = os.path.join(tools, 'sign.jar')

logger = logging.getLogger('mlibinjector')


class InjectorException(Exception):
	pass

class Injector():
	abi = {
		'armeabi-v7a': '7f454c4601010100000000000000000003002800010000000000000034000000',
		'arm64-v8a': '7f454c460201010000000000000000000300b700010000000000000000000000',
		'x86': '7f454c4601010100000000000000000003000300010000000000000034000000',
		'x86_64': '7f454c4602010100000000000000000003003e00010000000000000000000000'
	}

	def __init__(self, apkname):
		self.port = None
		self.host = None
		self.force = False
		self.confpath = None
		self.netconfpath = None
		self.scriptfile = None
		self.scriptdir = None
		self.nativelib = None
		self.gadgetfile = 'libfrida-gadget.so'
		self.configfile = 'libfrida-gadget.config.so'

		self.arch = list()

		if apkname and os.path.isfile(apkname) and os.access(apkname, os.R_OK):
			if apkname[-4:] != '.apk':
				raise InjectorException("E: Please Provide a valid apk file: {}".format(apkname))
			self.apkname = apkname
			self.dirname = self.apkname.split('.apk')[0].replace('\\', '/')
			self.apk = True
		elif apkname and os.path.isdir(apkname):
			self.dirname = apkname
			if self.dirname[-1] == '/':
				self.dirname = self.dirname[:-1]
			self.apk = False
		else:
			raise InjectorException("E: Please Provide a valid apk file or a directory: {}".format(apkname))
		return

	def randomize_lib(self):
		name = ''.join([x for x in sample(ascii_lowercase, randint(6, 15))])
		self.gadgetfile = 'lib%s.so' % name
		self.configfile = 'lib%s.config.so' % name

	def exec_cmd(self, cmd):
		logger.debug(' '.join(cmd))
		try:
			command = Popen(cmd, stdout=PIPE, stderr=STDOUT)
			while True:
				output = command.stdout.readline()
				if not output and command.poll() is not None:
					break
				if output:
					logger.debug(str(output.strip(), 'utf-8'))
			return command.poll()
		except CalledProcessError as e:
			logger.error(e)
			return -1
		return 42 # should never reach this point

	def inject_lib(native_lib, gadget_lib):
		"""
		Inject library dependency to pre-existing native lib
		requires android.permission.INTERNET in AndroidManifest.xml
		when using server mode for frida-gadget.
		"""
		native = liefparse(native_lib)
		native.add_library(gadget_lib)
		native.write(native_lib)

	def launchable_generator(self, activities):
		"""
		A generator that returns every launchable activity from a list of activities
		"""
		name = '{http://schemas.android.com/apk/res/android}name'
		for activity in activities:
			intent_filters = activity.findall('intent-filter')
			if len(intent_filters) < 0:
				return

			for intent in intent_filters:
				categories = intent.findall('category')
				if len(categories) < 0:
					return

				for category in categories:
					for val in category.attrib.values():
						if val == 'android.intent.category.LAUNCHER':
							activity_name = activity.attrib[name]
							if activity_name.startswith('.'):
								yield self.package_name + activity_name
							elif match(r'^[a-zA-Z0-9-_]+$', activity_name):
								yield self.package_name + '.' + activity_name
							else:
								yield activity_name

	def get_launchable_activity(self):
		"""
		Parses AndroidManifest.xml and returns all launchable activities
		will throw an error for corrupted xml documents
		"""
		try:
			main_activities = []
			parser = ET.parse(self.manifest)
			root = parser.getroot()
			self.package_name = root.attrib['package']
			activities = root.findall('application')[0].findall('activity')
			activity_alias = root.findall('application')[0].findall('activity-alias')

			if len(activities) > 0:
				main_activities.extend([activity for activity in self.launchable_generator(activities)])

			if len(activity_alias) > 0:
				main_activities.extend([activity for activity in self.launchable_generator(activity_alias)])

			return main_activities
		except Exception as e:
			logger.error(e)
			exit(1)
			pass

	def decompile_apk(self, nores=False, nosrc=False):
		"""
		Decompile apk file using apktool.jar
		"""
		if not self.apk:
			raise InjectorException("E: Please Provide a valid apk file")
		logger.debug('Decompiling %s' % (self.apkname))
		if self.force or not os.path.isdir(self.dirname):
			self.exec_cmd([
				"java",
				"-jar",
				apktool,
				"d",
				"--no-src" if nosrc else "",
				"--no-res" if nores else "",
				"-f",
				self.apkname
			])
			logger.info('Decompiled %s' % (self.apkname))
		else:
			logger.info('APK already decompiled previously. Using cache for %s' % (self.apkname))

	def sign_apk(self):
		"""
		Sign apk using default developer certificate via sign.jar
		"""
		if not self.apk:
			raise InjectorException("E: Please Provide a valid apk file")
		logger.debug('Signing %s' % (self.apkname))
		self.exec_cmd([
			"java",
			"-jar",
			sign,
			self.apkname
		])
		if os.stat(self.apkname).st_size == 0:
			logger.warn('Cannot sign %s' % (self.apkname))
		logger.info('Signed %s' % (self.apkname))

	def build_and_sign(self, aapt2=False):
		"""
		Build using apktool.jar
		sign again using sign.jar
		"""
		logger.debug('Building apk file from %s' % (self.dirname))
		self.exec_cmd([
			"java",
			"-jar",
			apktool,
			"b",
			"-f",
			self.dirname,
			"--use-aapt2" if aapt2 else "",
		])
		logger.info('Build done')
		self.apkname = '%s/dist/%s' % (self.dirname, self.dirname + '.apk')
		self.sign_apk()

	def enable_debugging(self):
		"""
		Enable debug flag in AndroidManifest.xml
		Uses apktool.jar and sign.jar
		"""
		if not self.apk:
			raise InjectorException("E: Please Provide a valid apk file")
		self.decompile_apk()
		self.manifest = self.dirname + '/AndroidManifest.xml'
		logger.debug('Enabling android-debug:true in %s' % self.manifest)
		fp = open(self.manifest, 'r')
		parser = ET.parse(fp)
		application = parser.getroot().findall('application')[0]
		keyname = '{http://schemas.android.com/apk/res/android}debuggable'
		application.attrib[keyname] = 'true'
		parser.write(self.manifest, encoding='utf-8', xml_declaration=True)
		logger.info('Enabled android-debug:true in %s' % self.manifest)
		self.build_and_sign()

	def check_permission(self, perm_filter):
		"""
		Check apk permission specified in filter by parsing AndroidManifest.xml
		Currently used for checking android.permission.INTERNET permission.
		"""
		logger.debug('Checking permissions in %s' % self.manifest)
		parser = ET.parse(self.manifest)
		manifest = parser.getroot()
		permissions = manifest.findall('uses-permission')
		if len(permissions) > 0:
			for perm in permissions:
				name = '{%s}name' % android_namespace
				logger.debug('uses-permission: %s' % (perm.attrib[name]))
				if perm.attrib[name] == perm_filter:
					return True
				else:
					return False
		else:
			logger.debug('No permissions are defined in %s' % (self.manifest))
			return False

	def add_permission(self, permission_name):
		"""
		Add permissions to apkfile specified in filter by parsing AndroidManifest.xml
		Currently used for adding android.permission.INTERNET permission.
		"""
		logger.debug('Adding %s permission to %s' % (permission_name, self.manifest))
		parser = ET.parse(self.manifest)
		manifest = parser.getroot()
		perm_element = ET.Element('uses-permission')
		name = '{%s}name' % android_namespace
		perm_element.attrib[name] = permission_name
		manifest.append(perm_element)
		parser.write(self.manifest, encoding='utf-8', xml_declaration=True)
		logger.info('Added %s permission to %s' % (permission_name, self.manifest))

	def write_config(self, filename):
		"""
		Generates frida config file based on supplied parameters
		"""
		frida_conf = {"interaction": {}}
		if (self.host and self.port):
			frida_conf["interaction"]["type"] = "listen"
			frida_conf["interaction"]["address"] = self.host
			frida_conf["interaction"]["port"] = self.port
			frida_conf["interaction"]["on_load"] = "wait"
		elif self.port:
			frida_conf["interaction"]["type"] = "listen"
			frida_conf["interaction"]["address"] = "127.0.0.1"
			frida_conf["interaction"]["port"] = self.port
			frida_conf["interaction"]["on_load"] = "wait"
		elif self.host:
			frida_conf["interaction"]["type"] = "listen"
			frida_conf["interaction"]["address"] = self.host
			frida_conf["interaction"]["port"] = "27042"
			frida_conf["interaction"]["on_load"] = "wait"
		elif self.scriptfile:
			frida_conf["interaction"]["type"] = "script"
			frida_conf["interaction"]["path"] = self.scriptfile
			frida_conf["interaction"]["on_change"] = "reload"
		elif self.scriptdir:
			frida_conf["interaction"]["type"] = "script-directory"
			frida_conf["interaction"]["path"] = self.scriptdir
			frida_conf["interaction"]["on_change"] = "rescan"
		data = jsondumps(frida_conf, indent=2)
		logger.debug(data)
		open(filename, 'w').write(data)

	def copy_libs(self, libpath):
		"""
		copy frida gadgets into /lib/<arch> folders
		"""
		libdir = {}
		if len(self.arch) > 0:
			for k in Injector.abi:
				if k in self.arch:
					libdir[k] = {}

		for lib in libdir:
			libdir[lib] = os.path.join(self.dirname, 'lib', lib)
			if not os.path.exists(libdir[lib]):
				os.makedirs(libdir[lib])
			else:
				logger.debug('Dir %s already exists' % (libdir[lib]))

		lib_files = []
		if os.path.exists(libpath) and os.path.isfile(libpath) and os.access(libpath, os.R_OK):
			lib_files.append(libpath)
		elif os.path.exists(libpath) and os.path.isdir(libpath):
			lib_files.extend(glob(libpath + '/*.so'))
		else:
			logger.error('Please provide the path to frida-gadget lib(.so) files')
			exit(1)

		# For each .so file, find its abi and copy in the lib folder
		for src in lib_files:
			if '.config.so' in src:
				continue
			sig = hexlify(open(src, 'rb').read(32)).decode()
			# for every supoprted abi, get the one with matching signature with the current .so
			abi = [abi for abi, signature in Injector.abi.items() if signature == sig]
			if len(abi) == 0:
				logger.error('Arch not supported for file {}'.format(src))
				continue
			abi = abi[0]
			if abi in libdir:
				logger.info('Found {} with arch "{}"'.format(src, abi))
				dest = os.path.join(libdir[abi], self.gadgetfile)
				copyfile(src, dest)
				logger.debug('%s --> %s' % (src, dest))
				_configfile = os.path.join(libdir[abi], self.configfile)
				if self.confpath is None:
					self.write_config(_configfile)
				else:
					copyfile(self.confpath, _configfile)
			else:
				logger.warn('Arch "{}" not selected for file {}'.format(abi, src))

	def inject_smali(self, filename):
		"""
		Injects smali prologue or smali direct methods in
		launchable activities by parsing smali code  to load frida-gadgets.
		"""
		if self.nativelib:
			logger.debug(self.libdir)
			for key, ldir in self.libdir.iteritems():
				_nativelib = os.path.join(ldir, self.nativelib)
				logger.debug(_nativelib)
				self.inject_lib(_nativelib, self.gadgetfile)
		else:
			_filename = os.path.basename(filename)
			prologue_stmt = smali_prologue % (self.gadgetfile.split('.so')[0][3:])
			direct_method = smali_direct_method % (self.gadgetfile.split('.so')[0][3:])
			logger.debug('Injecting smali code in %s' % (_filename))
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
						# Found prologue write after it

						if '.prologue' in line:
							lines.insert(cursor + 2, prologue_stmt)
							logger.debug('Smali prologue injected')
							break

						# No .prologue found write after constructor
						elif '.end method' in line:
							lines.insert(method_start + 1, prologue_stmt)
							logger.debug('Smali prologue injected')
							break
						else:
							cursor += 1

				# Couldn't find the static constructor, injecting static constructor
				elif (s_constructor is False and cursor is not None and index == eof):
					lines.insert(cursor, direct_method)
					logger.debug('Static constructor injected')
					break

			wf = open(filename, 'w')
			wf.writelines(lines)
			wf.close()
			logger.info('Smali code written to %s' % (_filename))

	def inject_frida_gadget(self, libpath):
		"""
		Handles process of injecting Frida gadgets
		"""
		if not self.apk:
			raise InjectorException("E: Please Provide a valid apk file")
		logger.debug('Injecting frida gagdet in %s' % self.apkname)
		self.decompile_apk()
		self.manifest = self.dirname + '/AndroidManifest.xml'
		# name = '{%s}name' % android_namespace
		permission_name = 'android.permission.INTERNET'

		activity_names = self.get_launchable_activity()

		if not (self.scriptfile or self.scriptdir):
			if self.check_permission(permission_name) is False:
				self.add_permission(permission_name)

		self.copy_libs(libpath)

		for activity_name in activity_names:
			activity_file_path = activity_name.replace('.', '/')
			main_activityfile = os.path.join(self.dirname, 'smali', activity_file_path + '.smali')
			self.inject_smali(main_activityfile)

		self.build_and_sign()
		logger.info('Frida Gadget injected')
		logger.info('Use command frida -U -n Gadget to connect to gadget :)')

	def inject_network_security_config(self):
		"""
		Inject a network-security-config in AndroidManifest.xml and in APK file
		Uses apktool.jar and sign.jar
		"""
		if not self.apk:
			raise InjectorException("E: Please Provide a valid apk file")
		self.decompile_apk()
		self.manifest = self.dirname + '/AndroidManifest.xml'
		logger.debug('Injecting network_security_config.xml file in %s' % self.manifest)
		if self.netconfpath and os.path.isfile(self.netconfpath) and os.access(self.netconfpath, os.R_OK):
			copyfile(self.netconfpath, os.path.join(self.dirname, 'res', 'xml'))
		else:
			xmldir = os.path.join(self.dirname, 'res', 'xml')
			if not os.path.isdir(xmldir):
				os.makedirs(xmldir)
			netsecfile = open(os.path.join(xmldir, 'network_security_config.xml'), 'w')
			netsecfile.write(xml_netsecconf)
			netsecfile.close()
		fp = open(self.manifest, 'r')
		parser = ET.parse(fp)
		application = parser.getroot().findall('application')[0]
		keyname = '{http://schemas.android.com/apk/res/android}networkSecurityConfig'
		application.attrib[keyname] = '@xml/network_security_config'
		parser.write(self.manifest, encoding='utf-8', xml_declaration=True)
		logger.info('Successfully injected network_security_config.xml in %s' % self.manifest)
		self.build_and_sign()
