# set noet ci pi sts=0 sw=4 ts=4
r"""Module for SCA Pattern Development Tools
Copyright (C) 2023 SUSE LLC

 Modified:     2023 Jul 03
-------------------------------------------------------------------------------
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <http://www.gnu.org/licenses/>.

  Authors/Contributors:
     Jason Record <jason.record@suse.com>

"""

import os
import re
import sys
import datetime
import requests
import configparser
from shutil import copyfile
from glob import glob
import subprocess as sp

# public symbols
__all__ = [
	'__version__',
	'check_directories',
]

__version__ = "0.0.7"

SUMMARY_FMT = "{0:25} {1:g}"
distribution_log_filename = "distribution.log"
distribution_log_section = "metadata"
seperator_len = 77
LOG_QUIET = 0	# turns off messages
LOG_MIN = 1	# minimum messages with progress bar
LOG_NORMAL = 2	# normal messages without progress bar
LOG_VERBOSE = 3	# detailed messages
LOG_DEBUG = 4	# debug-level messages
log_level = LOG_MIN


def title(title_str, version_str):
	separator_line("#")
	print("# {}, v{}".format(title_str, version_str))
	separator_line("#")

def sub_title(subtitle_str):
	print("# {}".format(subtitle_str))
	separator_line("-")

def separator_line(use_char):
	print("{}".format(use_char*seperator_len))

def check_directories(_config):
	"""check_directories(configparser_object)
	Checks if the config file directories are present. Returns True if they are and False otherwise."""
	dir_list = []
	dir_list_errors = []
	dir_list.append(_config.get("Common", "sca_arch_dir"))
	dir_list.append(_config.get("Common", "sca_lib_dir"))
	dir_list = dir_list + _config.get("Security", "dir_list").split(',')
	for dir in dir_list:
		if not os.path.isdir(dir):
			dir_list_errors.append(dir)
	if( len(dir_list_errors) > 0 ):
		print("Error: Missing directories")
		for dir in dir_list_errors:
			print("  + {0}".format(dir))
		return False
	else:
		return True


def show_config_file(_config_file, _config):
	"""Dump the current configuration file object"""
	sub_title("List Configuration Data")
	print("Config File: {0}\n".format(_config_file))
	for section in _config.sections():
		print("[%s]" % section)
		for options in _config.options(section):
			print("%s = %s" % (options, _config.get(section, options)))
		print()

class LogFile():
	"""Initialize and write data to a log file"""
	def __init__(self, logfile):
		self.logfile = logfile
	
	def __str__(self):
		return 'class %s(\n  logfile=%r\n)' % (self.__class__.__name__, self.logfile)

	def log(self):
		pass

	def msg(self):
		pass

	def msgn():
		pass


class ProgressBar():
	"""Initialize and update progress bar class"""
	def __init__(self, prefix, bar_width, total):
		self.prefix = prefix
		self.bar_width = bar_width
		self.total = total
		self.out = sys.stdout

	def __str__(self):
		return 'class %s(\n  prefix=%r \n  bar_width=%r \n  total=%r\n)' % (self.__class__.__name__, self.prefix, self.bar_width, self.total)

	def update(self, count):
		percent_complete = int(100*count/self.total)
		current_progress = int(self.bar_width*count/self.total)
		print("{}[{}{}] {:3g}% {:3g}/{}".format(self.prefix, "#"*current_progress, "."*(self.bar_width-current_progress), percent_complete, count, self.total), end='\r', file=self.out, flush=True)

	def finish(self):
		print("\n", flush=True, file=self.out)

def get_uncommitted_repo_list():
	print("Searching for local uncommitted security patterns")
	patterns = []
	prog = "git status"
	pattern_file = re.compile("patterns/.*_SUSE-SU")

	p = sp.run(prog, shell=True, check=True, stdout=sp.PIPE, stderr=sp.PIPE, universal_newlines=True)
	# There are two possible output formats from this command:
	# 	new file:   patterns/SLE/sle15sp4/xterm_SUSE-SU-2023_0221-1_sles_15.4.py
	#   patterns/SLE/sle15sp4/xterm_SUSE-SU-2023_0221-1_sles_15.4.py
	# This currently handles both formats

	for l in p.stdout.splitlines():
		line = l.lstrip()
		if pattern_file.search(line):
			patterns.append(line.split()[-1])
	if( patterns ):
		print("  + Found {0} patterns".format(len(patterns)))
	return patterns

def _get_committed_repo_range():
	prog = "git --no-pager branch -a"
	head_remote = ''
	head_local = ''
	repo_range = ''
	head_name = re.compile("HEAD.*origin/")

	p = sp.run(prog, shell=True, check=True, stdout=sp.PIPE, stderr=sp.PIPE, universal_newlines=True)

	for l in p.stdout.splitlines():
		line = l.lstrip()
		if head_name.search(line):
			head_remote = line.split()[-1]

	head_local = head_remote.split("/")[-1]
	repo_range = head_remote + ".." + head_local

	return repo_range
	
def _get_committed_repo_uuid_list(_repo_range):
	prog = "git --no-pager log " + _repo_range
	commits_to_check = []

	p = sp.run(prog, shell=True, check=True, stdout=sp.PIPE, stderr=sp.PIPE, universal_newlines=True)

	for l in p.stdout.splitlines():
		line = l.lstrip()
		if( line.startswith("commit ") ):
			commits_to_check.append(line.split()[1])
	
	return commits_to_check


def get_committed_repo_list():
	print("Searching for local committed security patterns not pushed")
	prog = "git diff-tree --no-commit-id --name-only -r "
	patterns = []
	repo_range = _get_committed_repo_range()
	commit_list = _get_committed_repo_uuid_list(repo_range)
	pattern = re.compile("patterns/.*_SUSE-SU")
	
	for _commit in commit_list:
		p = sp.run(prog + _commit, shell=True, check=True, stdout=sp.PIPE, stderr=sp.PIPE, universal_newlines=True)

		for l in p.stdout.splitlines():
			line = l.lstrip()
			if pattern.search(line):
				patterns.append(line)
	if( patterns ):
		print("  + Found {0} patterns".format(len(patterns)))
	return patterns

def get_repo_spec_ver(filepath):
	version_str = "Unknown"
	this_version = ""
	version = re.compile("^Version:\s.*[0-9]", re.IGNORECASE)
	spec_file = os.path.basename(filepath)

	fd = open(filepath, "r")
	lines = fd.readlines()
	for line in lines:
		if version.search(line):
			this_version = line.split()[-1]
			break
	fd.close()
	if( this_version ):
		parts = this_version.split('.')
		bumped = str(int(parts[-1]) + 1)
		parts[-1] = str(bumped)
		bumped_version = '.'.join(parts)
		version_str = bumped_version
		print("Bumping package version from {0} to {1}".format(this_version, bumped_version))
	else:
		print("Could not find package version in {0}".format(filepath))

	#print("Found version " + version_str + " in " + filepath)

	return version_str



def validate_sa_patterns(_config):
	sub_title("Validate Patterns")
	print("Searching for Security Patterns to Validate")
	pat_dir = _config.get("Security", "pat_dir")
	pat_error_dir = _config.get("Security", "pat_error")
	pat_logs_dir = _config.get("Security", "pat_logs")
	pat_dups_dir = _config.get("Security", "pat_dups")
	patterns = []
	pattern_cache = []
	#print("Directory: {0}".format(pat_dir))
	for file in glob(pat_dir + "/*.py"):
		patterns.append(file)
	for file in glob(pat_dir + "/*.pl"):
		patterns.append(file)
	#print("Number of Patterns: {0}".format(len(patterns)))
	total = len(patterns)
	if( total < 1 ):
		print("+ Warning: No security patterns found, run sagen\n")
		return total
	else:
		print("+ Patterns Found: {0}\n".format(total))
	size = len(str(total))

	print("Building Pre-existing Pattern Cache")
	sca_repo_dir = _config.get("Common", "sca_repo_dir")
	for root, dirs, files in os.walk(sca_repo_dir):
		for name in files:
			pattern_cache.append(name)
	print("+ Patterns Found: {0}\n".format(len(pattern_cache)))

	count = 0
	fatal = []
	duplicates = []
	valid = 0
	bar_width = 50
	bar = ProgressBar("Validating: ", bar_width, total)
	for pattern in patterns:
		count += 1
		pattern_file = os.path.basename(pattern)
		if( pattern_file in pattern_cache ):
			pattern_dup = pat_dups_dir + '/' + pattern_file
			os.rename(pattern, pattern_dup)
			duplicates.append(pattern_dup)
		else:
			prog = "pat -q " + pattern
			p = sp.run(prog, shell=True, check=False)
			if p.returncode != 0:
				pattern_error = pat_error_dir + '/' + pattern_file
				os.rename(pattern, pattern_error)
				fatal.append(pattern_error)
			else:
				valid += 1
		bar.update(count)
	bar.finish()
	fatal_count = len(fatal)
	dup_count = len(duplicates)
	print("Summary")
	print(SUMMARY_FMT.format("Total", total))
	print(SUMMARY_FMT.format("Valid", valid))
	print(SUMMARY_FMT.format("Fatal", fatal_count))
	print(SUMMARY_FMT.format("Duplicates", dup_count))
	print()

	if( fatal_count > 0 ):
		print("Failed Patterns:")
		for failure in fatal:
			print(failure)
		print()

	if( dup_count > 0 ):
		print("Duplicate Patterns:")
		for dup in duplicates:
			print(dup)
		print()

	return total

def distribute_sa_patterns(_config):
	"""Distribute python patterns generated by sagen"""
	sub_title("Distribute Patterns")
	print("Retrieving pattern list to distribute")
	pat_dir = _config.get("Security", "pat_dir")
	pat_logs_dir = _config.get("Security", "pat_logs")
	sca_repo_dir = _config.get("Common", "sca_repo_dir")
	distro_list = _config.get("Distribution", "supported").split(",")
	log_file = pat_logs_dir + "/" + distribution_log_filename
	pattern_list = []
	#print("Directory: {0}".format(pat_dir))
	for file in glob(pat_dir + "/*.py"):
		pattern_list.append(file)
	#print("Number of Patterns: {0}".format(len(pattern_list)))
	total = len(pattern_list)
	if( total < 1 ):
		print("+ Warning: No security patterns found, run sagen\n")
		return total
	else:
		print("+ Patterns Found: {0}\n".format(total))

	print("Distributing patterns for associated distributions")
	log = configparser.ConfigParser()
	log.optionxform = str # Ensures manifest keys are saved as case sensitive and not lowercase
	# Remove any obsolete log entries
	if os.path.exists(log_file):
		log.read(log_file)
		for _file, value in log.items(distribution_log_section):
			if not os.path.exists(_file):
				log.remove_option(distribution_log_section, _file)
	else:
		log.add_section(distribution_log_section)
	for distro in distro_list:
#		print(distro)
		count = 0
		distro_major = re.sub(r"sle(\d.*)sp(\d)", r"\1", distro)
		distro_version = re.sub(r"sle(\d.*)sp(\d)", r"\1.\2", distro)
		distro_str = "_" + str(distro_version) + ".*py$"
		matchdistro = re.compile(distro_str)
		for pattern in pattern_list:
#			print("+ {}".format(pattern))
			if matchdistro.search(pattern):
#				print(" + Distro {}".format('MATCHED'))
				count += 1
				pattern_file = os.path.basename(pattern)
				distributed_dir = sca_repo_dir + "/sca-patterns-sle" + str(distro_major) + "/patterns/SLE/" + distro
				if( os.path.exists(distributed_dir) ):
					distributed_pattern = distributed_dir + "/" + pattern_file
#					print("+ File {}".format(distributed_pattern))
					if( os.path.isfile(distributed_pattern) ):
						print("Error: Duplicate file found - {0}".format(distributed_pattern))
					else:
						#print("Copy {0}\n{1}".format(pattern, distributed_pattern))
						copyfile(pattern, distributed_pattern)
						log[distribution_log_section][distributed_pattern] = 'true'
				else:
					print("Error: Directory not found - {0}".format(distributed_dir))
#			else:
#				print(" + Distro {}".format('SKIPPED'))

		print(SUMMARY_FMT.format("+ " + distro + ":", count))
		with open(log_file, 'w') as logfile:
			log.write(logfile)
	print()

	return total

def remove_sa_patterns(_config):
	sub_title("Remove Uncommitted Patterns")
	pat_logs_dir = _config.get("Security", "pat_logs")
	log_file = pat_logs_dir + "/" + distribution_log_filename
	log = configparser.ConfigParser()
	log.optionxform = str # Ensures manifest keys are saved as case sensitive and not lowercase
	# Remove any obsolete log entries
	if os.path.exists(log_file):
		log.read(log_file)
		for _file, value in log.items(distribution_log_section):
			if os.path.exists(_file):
				print("Deleting {}".format(_file))
				os.remove(_file)
		os.remove(log_file)
		print()
		return True
	else:
		print("Error: File not found - {}".format(log_file))
		return False

def show_status(_config):
	sub_title("Show Status")
	print("Pattern List - PENDING")
	print("Repository Status - PENDING")
	print("Distribution Log - PENDING")
	print()


class DisplayMessages():
	"Display message string for a given log level"
	LOG_QUIET	= 0	# turns off messages
	LOG_MIN		= 1	# minimum messages
	LOG_NORMAL	= 2	# normal, but significant, messages
	LOG_VERBOSE	= 3	# detailed messages
	LOG_DEBUG	= 4	# debug-level messages
	DISPLAY = "{0:25} = {1}"

	def __init__(self, level=LOG_MIN):
		self.level = level
	def __str__ (self):
		return "class %s(level=%r)" % (self.__class__.__name__,self.level)

	def get_level(self):
		return self.level

	def set_level(self, level):
		if( level >= self.LOG_DEBUG ):
			self.level = self.LOG_DEBUG
		else:
			self.level = level

	def __write_msg(self, level, msgtag, msgstr):
		if( level <= self.level ):
			print(self.DISPLAY.format(msgtag, msgstr))

	def min(self, msgtag, msgstr):
		"Write the minium amount of messages"
		self.__write_msg(self.LOG_MIN, msgtag, msgstr)

	def normal(self, msgtag, msgstr):
		"Write normal, but significant, messages"
		self.__write_msg(self.LOG_NORMAL, msgtag, msgstr)

	def verbose(self, msgtag, msgstr):
		"Write more verbose informational messages"
		self.__write_msg(self.LOG_VERBOSE, msgtag, msgstr)

	def debug(self, msgtag, msgstr):
		"Write all messages, including debug level"
		self.__write_msg(self.LOG_DEBUG, " > " + str(msgtag), msgstr)

class SecurityAnnouncement():
	"Security announcement class"
	IDX_LAST = -1
	IDX_FIRST = 0

	def __init__(self, _msg, _config, url_date, _file, _version):
		self.msg = _msg
		self.pat_logs_dir = _config.get("Security", "pat_logs")
		self.pat_dir = _config.get("Security", "pat_dir")
		self.author = _config.get("Common", "author").strip("\'\"")
		self.bin_version = _version
		self.file = _file
		self.url_date = url_date
		self.safilepath = self.pat_logs_dir + self.file
		self.sauri = self.url_date + self.file
		self.loaded_file = []
		self.main_package = ''
		self.announcement_id = ''
		self.rating = ''
		self.package_lists = []
		self.this_package_list = {}
		self.patterns_created = {}
		self.stat = {'patterns_evaluated': 0, 'patterns_generated': 0, 'patterns_duplicated': 0, 'a_errors': 0, 'p_errors': 0}
		self.__load_file()
		self.__get_metadata()
		self.__get_package_lists()

	def __str__(self):
		return 'class %s(\n  package_lists=%r \n  safilepath=%r \n  sauri=%r \n  main_package=%r \n  announcement_id=%r \n  rating=%r\n)' % (self.__class__.__name__,self.package_lists, self.safilepath, self.sauri, self.main_package, self.announcement_id, self.rating)

	def __cleanup(self):
		print("!Cleanup skipped")
		pass

	def __load_file(self):
		self.msg.debug('Loading file', self.safilepath)
		try:
			f = open(self.safilepath, "r")
		except Exception as error:
			self.msg.min("ERROR: Cannot open", str(self.safilepath) + ": " + str(error))
			self.stat['a_errors'] += 1
			self.__cleanup()
			sys.exit()

		invalid = re.compile(r'>Object not found!<', re.IGNORECASE)
		for line in f.readlines():
			line = line.strip("\n")
			if invalid.search(line):
				self.loaded_file = []
				self.msg.min("ERROR: Invalid file", str(safilepath))
				self.stat['a_errors'] += 1
				f.close()
				self.__cleanup()
				sys.exit()
			self.loaded_file.append(line)
		f.close()

	def __get_metadata(self):
		"Pulls the package name, announcement ID and rating"
		suse_update = re.compile("SUSE Security Update:|# Security update for ", re.IGNORECASE)
		for line in self.loaded_file:
			text = line.strip().replace('<br>', '') # clean up line
			if suse_update.search(text):
				if "java" in text.lower():
					self.main_package = "Java"
				elif "apache" in text.lower():
					self.main_package = "Apache"
				elif "kerberos" in text.lower():
					self.main_package = "Kerberos"
				else:
					update_str = text.split('(')[self.IDX_FIRST]
					self.main_package = re.sub('[,]', '', update_str.split()[self.IDX_LAST])
			elif text.startswith("Announcement ID:"):
				self.announcement_id = text.split()[self.IDX_LAST]
			elif text.startswith("Rating:"):
				self.rating = text.split()[self.IDX_LAST].title()
		self.msg.debug('self.main_package', self.main_package)
		self.msg.debug('self.announcement_id', self.announcement_id)
		self.msg.debug('self.rating', self.rating)
		
	def __deconstruct_header(self, info):
		self.msg.debug("Header:", str(info))
		"Extracts the label, major and minor versions, and architectures from the header info provided"
		parts = info.split('(')
		self.this_package_list['label'] = parts[self.IDX_FIRST].replace('-', ' ')[2:].strip() #Everything to the left of the first ( excluding the leading "- ".
		self.this_package_list['archs'] = parts[self.IDX_LAST].rstrip("):").split()
		parts = self.this_package_list['label'].split()
		for part in parts:
			if part[:1].isdigit():
				if( "." in part ):
					self.this_package_list['major'], self.this_package_list['minor'] = part.split('.')
				else:
					self.this_package_list['major'] = part
			elif( part.startswith('SP') ):
				self.this_package_list['minor'] = part[2:] # remove the SP in part
			elif( 'ltss' in part.lower() ):
				self.this_package_list['ltss'] = True
		if( int(self.this_package_list['minor']) < 0 ):
			self.this_package_list['minor'] = 0
		if( "SP" not in parts[self.IDX_LAST] and 'ltss' not in parts[self.IDX_LAST].lower() and not parts[self.IDX_LAST][:1].isdigit() ):
			self.this_package_list['tag'] = parts[self.IDX_LAST]

	def __deconstruct_package(self, info):
		"Extracts the package name and version information"
		LIMIT_HIGH = 10
		LIMIT_LOW = 3
		info = info.lstrip('* ')
		if " " in info:
			# Package names don't include spaces
			return False
		pkg_parts = info.split('-')
		pkg_parts_len = len(pkg_parts)
		self.msg.debug(" Package:", str(info) + " => (" + str(pkg_parts_len) + ") " + str(pkg_parts))
		pkg_version = pkg_parts[-2] + '-' + pkg_parts[-1]
		del pkg_parts[-1]
		del pkg_parts[-1]
		pkg_name = '-'.join(pkg_parts)
		if( LIMIT_LOW <= pkg_parts_len and pkg_parts_len < LIMIT_HIGH ):
			self.this_package_list['packages'][pkg_name] = pkg_version
			return True
		else:
			# This was not a package
			return False

	def __get_package_lists(self):
		"Creates a list of dictionaries for each distribution found"
		in_package_list = False
		in_header = False
		in_packages = False
		header_line = ''
		header_start = re.compile("SUSE |openSUSE |Module ", re.IGNORECASE)
		header_finish = re.compile("\)$|\):$")
		self.this_package_list = {}
		for line in self.loaded_file:
			text = line.strip().replace('<br>', '') # clean up line
			if( in_package_list ):
				if( in_packages ):
					if text.endswith('References:'):
						if self.this_package_list:
							self.package_lists.append(self.this_package_list)
						in_package_list = False
						in_header = False
						in_packages = False
						header_line = ''
						self.this_package_list = {}
						break
					elif header_start.search(text):
						# I encountered the next header, so save the previous this_package_list to package_lists
						if self.this_package_list:
							self.package_lists.append(self.this_package_list)
						self.this_package_list = {'label': '', 'major': -1, 'minor': -1, 'ltss': False, 'tag': '', 'archs': [], 'packages': {}}
						header_line = header_line + " " + text
						if header_finish.search(header_line):
							self.__deconstruct_header(header_line)
							in_header = False
							in_packages = True
							header_line = ''
						elif( "(" in header_line ):
							in_header = False
							in_packages = False
						else:
							in_header = True
							in_packages = False
					elif( len(text) > 0 ):
						if not self.__deconstruct_package(text):
							if self.this_package_list:
								self.package_lists.append(self.this_package_list)
							in_package_list = False
							in_header = False
							in_packages = False
							header_line = ''
							self.this_package_list = {}
							break
				elif( in_header ):
					header_line = header_line + " " + text
					if header_finish.search(header_line):
						self.__deconstruct_header(header_line)
						in_header = False
						in_packages = True
						header_line = ''
					elif( "(" in header_line ):
						in_header = False
						in_packages = False
				elif text.endswith('References:'):
					in_package_list = False
					in_header = False
					in_packages = False
					header_line = ''
					break
				elif header_start.search(text):
					self.this_package_list = {'label': '', 'major': -1, 'minor': -1, 'ltss': False, 'tag': '', 'archs': [], 'packages': {}}
					header_line = header_line + " " + text
					if header_finish.search(header_line):
						self.__deconstruct_header(header_line)
						in_header = False
						in_packages = True
						header_line = ''
					elif( "(" in header_line ):
						in_header = False
						in_packages = False
					else:
						in_header = True
						in_packages = False
			elif text.endswith('Package List:'):
				in_package_list = True
#		for pkgdict in self.package_lists:
#			for key,value in pkgdict.items():
#				print("{0:10} : {1}".format(key, value))
#			print("\n")
		self.msg.debug('self.package_lists', self.package_lists)

	def __create_pattern(self, distro_index, pattern_tag):
		TODAY = datetime.date.today()
		base_indent = '\t'
		if( len(pattern_tag) > 0 ):
			tag = "_" + str(pattern_tag) + "_"
		else:
			tag = "_"
		if( self.package_lists[distro_index]['ltss'] ):
			add_ltss_string = ".ltss"
		else:
			add_ltss_string = ""
		pattern_filename = str(self.main_package).lower() + "_" + str(self.announcement_id) + str(tag) + str(self.package_lists[distro_index]['major']) + "." + str(self.package_lists[distro_index]['minor']) + add_ltss_string + ".py"
		pattern_filename = pattern_filename.replace(':', '_')

		# Build pattern file content
		CONTENT = "#!/usr/bin/python3\n#\n"
		CONTENT += "# Title:       " + str(self.rating) +" Security Announcement for " + str(self.main_package).replace(':', '') + " " + str(self.announcement_id) + "\n"
		if( self.package_lists[distro_index]['ltss'] ):
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise " + str(self.package_lists[distro_index]['major']) + " SP" + str(self.package_lists[distro_index]['minor']) + " LTSS\n"
		else:
			CONTENT += "# Description: Security fixes for SUSE Linux Enterprise " + str(self.package_lists[distro_index]['major']) + " SP" + str(self.package_lists[distro_index]['minor']) + "\n"
		CONTENT += "# URL:         "  + str(self.sauri) + "\n"
		CONTENT += "# Source:      Security Announcement Generator (sagen.py) v" + str(self.bin_version) + "\n"
		CONTENT += "# Modified:    " + str(TODAY.strftime("%Y %b %d")) + "\n"
		CONTENT += "#\n##############################################################################\n"
		CONTENT += "# Copyright (C) " + str(TODAY.year) + " SUSE LLC\n"
		CONTENT += "##############################################################################\n#\n"
		CONTENT += "# This program is free software; you can redistribute it and/or modify\n"
		CONTENT += "# it under the terms of the GNU General Public License as published by\n"
		CONTENT += "# the Free Software Foundation; version 2 of the License.\n#\n"
		CONTENT += "# This program is distributed in the hope that it will be useful,\n"
		CONTENT += "# but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
		CONTENT += "# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
		CONTENT += "# GNU General Public License for more details.\n#\n"
		CONTENT += "# You should have received a copy of the GNU General Public License\n"
		CONTENT += "# along with this program; if not, see <http://www.gnu.org/licenses/>.\n#\n"
		CONTENT += "#  Authors/Contributors:\n#   " + self.author + "\n#\n"
		CONTENT += "##############################################################################\n\n"
		CONTENT += "import os\n"
		CONTENT += "import Core\n"
		CONTENT += "import SUSE\n\n"
		CONTENT += "meta_class = \"Security\"\n"
		CONTENT += "meta_category = \"SLE\"\n"
		CONTENT += "meta_component = \"" + str(self.main_package) + "\"\n"
		CONTENT += "pattern_filename = os.path.basename(__file__)\n"
		CONTENT += "primary_link = \"META_LINK_Security\"\n"
		CONTENT += "overall = Core.TEMP\n"
		CONTENT += "overall_info = \"NOT SET\"\n"
		CONTENT += "other_links = \"META_LINK_Security=" + str(self.sauri) + "\"\n"
		CONTENT += "Core.init(meta_class, meta_category, meta_component, pattern_filename, primary_link, overall, overall_info, other_links)\n\n"

		CONTENT += "def main():\n"
		if( self.package_lists[distro_index]['ltss'] ):
			CONTENT += base_indent + "ltss = True\n"
		else:
			CONTENT += base_indent + "ltss = False\n"
		CONTENT += base_indent + "name = '" + self.main_package + "'\n"
		CONTENT += base_indent + "main = ''\n"
		CONTENT += base_indent + "severity = '" + self.rating + "'\n"
		CONTENT += base_indent + "tag = '" + self.announcement_id + "'\n"
		CONTENT += base_indent + "packages = {}\n"
		CONTENT += base_indent + "server = SUSE.getHostInfo()\n\n"
		CONTENT += base_indent + "if ( server['DistroVersion'] == " + str(self.package_lists[distro_index]['major']) + "):\n"
		CONTENT += base_indent + "\tif ( server['DistroPatchLevel'] == " +  str(self.package_lists[distro_index]['minor']) + " ):\n"
		CONTENT += base_indent + "\t\tpackages = {\n"

		for key in sorted(self.package_lists[distro_index]['packages'].keys()):
			CONTENT += base_indent + "\t\t\t'" + str(key) + "': '" + str(self.package_lists[distro_index]['packages'][key]) + "',\n"

		CONTENT += base_indent + "\t\t}\n"
		CONTENT += base_indent + "\t\tSUSE.securityAnnouncementPackageCheck(name, main, ltss, severity, tag, packages)\n"
		CONTENT += base_indent + "\telse:\n"
		CONTENT += base_indent + "\t\tCore.updateStatus(Core.ERROR, \"ERROR: \" + name + \" Security Announcement: Outside the service pack scope\")\n"
		CONTENT += base_indent + "else:\n"
		CONTENT += base_indent + "\tCore.updateStatus(Core.ERROR, \"ERROR: \" + name + \" Security Announcement: Outside the distribution scope\")\n\n"
		CONTENT += base_indent + "Core.printPatternResults()\n\n"

		CONTENT += "if __name__ == \"__main__\":\n"
		CONTENT += "\tmain()\n\n"


		# Write the content to a pattern on disk
		pattern_file = self.pat_dir + pattern_filename
		self.stat['patterns_evaluated'] += 1
		if( os.path.exists(pattern_file) ):
			self.msg.debug('Pattern', str(pattern_filename) + " (" +  str(len(self.package_lists[distro_index]['packages'])) + " packages)")
			self.msg.debug("ERROR Duplicate", "Pattern " + pattern_file)
			self.stat['patterns_duplicated'] += 1
#			cleanUp()
	#		sys.exit(4)
		else:
			try:
				f = open(pattern_file, "w")
				f.write(CONTENT)
				f.close()
				os.chmod(pattern_file, 0o755)
				self.msg.verbose(' + Pattern', str(pattern_filename) + " (" +  str(len(self.package_lists[distro_index]['packages'])) + " packages)")
				self.stat['patterns_generated'] += 1
				self.patterns_created[pattern_filename] = len(self.package_lists[distro_index]['packages'])
			except Exception as error:
				self.msg.verbose(" + ERROR: Cannot create " + str(pattern_file) + ": " + str(error))
				self.stat['p_errors'] += 1

	def get_stats(self):
		"Return the class statistics"
		self.msg.debug("Stats", str(self.stat))
		return self.stat

	def get_patterns(self):
		"Return the patterns created with the number of associated packages"
		self.msg.debug("Patterns", str(self.patterns_created))
		return self.patterns_created

	def get_list(self, regexstr):
		"Return a list of indeces for the matching package list(s) based on the regex expression given. The regex ignores case."
		getdistro = re.compile(regexstr, re.IGNORECASE)
		distros = []
		for i in range(len(self.package_lists)):
			if getdistro.search(self.package_lists[i]['label']):
				distros.append(i)
		return distros

	def create_patterns(self, create_list, pattern_tag):
		"Create patterns for the given index list"
		if( len(create_list) > 0 ):
			for i in create_list:
				self.__create_pattern(i, pattern_tag)

def convert_sa_date(given_str, _today, _msg):
	"Converts given string to valid date for URL retrival"
	converted_str = 'INVALID'
	MONTHS = {1: 'January', 2: 'February', 3: 'March', 4: 'April', 5: 'May', 6: 'June', 
	7: 'July', 8: 'August', 9: 'September', 10: 'October', 11: 'November', 12: 'December', 
	'jan': 'January', 'feb': 'February', 'mar': 'March', 'apr': 'April', 'may': 'May', 'jun': 'June', 
	'jul': 'July', 'aug': 'August', 'sep': 'September', 'oct': 'October', 'nov': 'November', 'dec': 'December'}
	MONTHS_DIGIT = {'January': '01', 'February': '02', 'March': '03', 'April': '04', 'May': '05', 'June': '06', 
	'July': '07', 'August': '08', 'September': '09', 'October': '10', 'November': '11', 'December': '12'}
	this_year = _today.strftime("%Y")
	this_month = _today.strftime("%B")
	use_year = ''
	use_month = ''
	if( len(given_str) > 0 ):
		if( '-' in given_str ):
			parts = given_str.split('-')
		elif( '/' in given_str ):
			parts = given_str.split('/')
		else:
			parts = [given_str, '0']

		#print(parts)
		for part in parts:
			if( part.isdigit() ):
				part = int(part)
				if( part > 0 ):
					if( part > 12 ): # Assume it's the requested year
						if( part > 99 ):
							use_year = str(part)
						else:
							use_year = "20" + str(part)
					else: # Assume it's the requested month
						if( part in MONTHS.keys() ):
							use_month = MONTHS[part]
						else:
							msg.min("ERROR", "Invalid date string - " + str(given_str))
							sys.exit(3)
			else:
				part = part[:3].lower()
				if( part in MONTHS.keys() ):
					use_month = MONTHS[part]
				else:
					msg.min("ERROR", "Invalid date string - " + str(given_str))
					sys.exit(3)
		if( len(use_year) == 0 ):
			use_year = this_year
		if( len(use_month) == 0 ):
			use_month = this_month
		converted_str = str(use_year) + "-" + str(use_month)
	else:
		converted_str = _today.strftime("%Y-%B")
	_msg.debug("Date Conversion", "given_str=" + str(given_str) + ", converted_str=" + str(converted_str))
	return converted_str

def get_pattern_list(this_path, _recurse):
	this_list = []
	include_file = re.compile(".py$|.pl$")
	for dirpath, subdirs, files in os.walk(this_path, topdown = True):
		for file in files:
			if include_file.search(file):
				this_list.append(os.path.join(dirpath, file))
		if not _recurse:
			break
	return this_list

def get_links_from_pattern_file(this_pattern):
	these_urls = []
	try:
		f = open(this_pattern, "r")
	except Exception as error:
		print("Error: Cannot open pattern: ", str(error))
		return these_urls

	type_python = False
	type_perl = False
	
	for line in f.readlines():
		line = line.strip("\n")
		if type_python:
			if find_links.search(line):
				links = line.split('"')[1].split("|")
				for link in links:
					url = link.split('=', 1)[1]
					these_urls.append(url)
		elif type_perl:
			if find_links.search(line):
				url = line.split('=', 1)[1].rstrip("\",'")
				these_urls.append(url)
		else:
			if "#!/usr/bin/python" in line:
				type_python = True
				find_links = re.compile('^OTHER_LINKS = "', re.IGNORECASE)
			elif "#!/usr/bin/perl" in line:
				type_perl = True
				find_links = re.compile('^.*"META_LINK_.*=', re.IGNORECASE)
	f.close()
#	print(these_urls)

	return these_urls

def validate_link_list(link_list, _c_, _verbose):
	bad_links = {}
	vdisplay = "  {0:23} {1}"
	oldhosts = re.compile("novell.com|microfocus.com", re.IGNORECASE)
	for link in link_list:
		_c_['link_total'] += 1
		status = "+ Confirmed"
		_c_['active_link'] = link
		try:
			x = requests.get(link, timeout=10)
			x.raise_for_status()
		except requests.exceptions.HTTPError as errh:
			status = "- Invalid URL"
			_c_['badurl'] += 1
			bad_links[link] = "Invalid URL"
			if _verbose:
				print(vdisplay.format(status, link))
			continue
		except requests.exceptions.ConnectionError as errc:
			status = "- Invalid Connection"
			_c_['badconnection'] += 1
			bad_links[link] = "Invalid Connection"
			if _verbose:
				print(vdisplay.format(status, link))
			continue
		except requests.exceptions.Timeout as errt:
			status = "- Server Timeout"
			_c_['ping'] += 1
			bad_links[link] = "Server Timeout"
			if _verbose:
				print(vdisplay.format(status, link))
			continue
		except requests.exceptions.RequestException as err:
			status = "- Invalid URL"
			_c_['badurl'] += 1
			bad_links[link] = "Invalid URL"
			if _verbose:
				print(vdisplay.format(status, link))
			continue
		except Exception as error:
			status = "- Unknown Error"
			_c_['ping'] += 1
			bad_links[link] = "Unknown Error"
			if _verbose:
				print(vdisplay.format(status, link))
			continue


		urlhost = link.split('/')[2]
		if oldhosts.search(urlhost):
			status = "- Old Host"
			_c_['oldhosts'] += 1
			bad_links[link] = "Old Host"
			if _verbose:
				print(vdisplay.format(status, link))
			continue

		if( x.status_code == 200 ):
			data = x.text.split('\n')
			badlink = re.compile('Invalid Bug ID')
			badvideo = re.compile('This video isn\'t available anymore', re.IGNORECASE)
			for line in data:
				if badlink.search(line):
					status = "- Invalid BUG"
					_c_['bugid'] += 1
					bad_links[link] = "Invalid BUG"
					break
				elif badvideo.search(line):
					status = "- Invalid URL"
					_c_['badurl'] += 1
					bad_links[link] = "Invalid URL"
					break
		if _verbose:
			print(vdisplay.format(status, link))
	return bad_links, _c_

def update_git_repos(_config):
	sub_title("GitHub Repository Clones")
	sca_repo_dir = _config.get("Common", "sca_repo_dir")
	github_uri_base = _config.get("GitHub", "uri_base")
	patdev_repos = _config.get("GitHub", "patdev_repos").split(',')

	for repo in patdev_repos:
		repo_path = sca_repo_dir + repo
		if os.path.exists(repo_path):
			print("Updating Local " + repo + " Repository")
			prog = "git -C " + repo_path + " pull"
		else:
			print("Cloning GitHub " + repo + " Repository")
			prog = "git -C " + sca_repo_dir + " clone " + github_uri_base + "/" + repo + ".git"

		p = sp.run(prog, shell=True, check=False)
		if p.returncode != 0:
			print("+ ERROR: Command failed - " + prog)
		print()

