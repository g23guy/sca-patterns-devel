# set noet ci pi sts=0 sw=4 ts=4
r"""Module for SCA Pattern Development Tools
Copyright (C) 2023 SUSE LLC

 Modified:     2023 Aug 04
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
import stat
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

__version__ = "0.0.17"

SUMMARY_FMT = "{0:30} {1:g}"
distribution_log_filename = "distribution.log"
distribution_log_section = "metadata"
seperator_len = 85
config_file = "/etc/opt/patdevel/patdev.ini"

def title(title_str, version_str):
	separator_line("#")
	print("# {}, v{}".format(title_str, version_str))
	separator_line("#")

def sub_title(subtitle_str):
	print("# {}".format(subtitle_str))
	separator_line("-")

def separator_line(use_char = '#'):
	print("{}".format(use_char*seperator_len))

class ProgressBar():
	"""Initialize and update progress bar class"""
	def __init__(self, prefix, total, bar_width = seperator_len):
		self.base_len = seperator_len
		self.bar_width_orig = bar_width
		self.bar_width = bar_width
		self.prefix = prefix
		self.total = total
		self.count = 0
		self.out = sys.stdout
		if ( self.bar_width_orig == self.base_len ):
			self.bar_width = self.base_len - len(self.prefix) - 2

	def __str__(self):
		return 'class %s(\n  prefix=%r \n  bar_width=%r \n  total=%r\n)' % (self.__class__.__name__, self.prefix, self.bar_width, self.total)

	def set_prefix(self, _prefix):
		self.prefix = _prefix
		if ( self.bar_width_orig == self.base_len ):
			self.bar_width = self.base_len - len(self.prefix) - 2
		else:
			self.bar_width = self.bar_width_orig

	def set_total(self, _new_total):
		self.total = _new_total

	def inc_count(self, increment = 1):
		"""Increments one by default"""
		self.count += increment

	def get_total(self):
		return self.total

	def get_count(self):
		return self.count

	def update(self):
		percent_complete = int(100*self.count/self.total)
		current_progress = int(self.bar_width*self.count/self.total)
		print("{}[{}{}] {:3g}% {:3g}/{}".format(self.prefix, "#"*current_progress, "."*(self.bar_width-current_progress), percent_complete, self.count, self.total), end='\r', file=self.out, flush=True)

	def finish(self):
		print("\n", flush=True, file=self.out)

class PatternTemplate():
	content = ''
	content_kernel = ''
	content_package = ''
	content_service = ''

	def __init__(self, script_name, script_version, _config, _msg):
		self.meta_class = ''
		self.meta_category = ''
		self.meta_component = ''
		self.pattern_base = ''
		self.pattern_filename = ''
		self.tid_number = '0'
		self.bug_number = '0'
		self.conditions = 0
		self.flat = False
		self.basic = True
		self.override_validation = False
		self.kernel_version = '0'
		self.package_name = ''
		self.package_version = '0'
		self.service_name = ''
		self.tid_url = ''
		self.bug_url = ''
		self.other_url = ''
		self.primary_link = "META_LINK_TID"
		self.title = ''
		self.script_name = script_name
		self.script_version = script_version
		self._config = _config
		self.msg = _msg
		self.link_results = []
		self.duplicate_patterns = {}
		self.author = config_entry(_config.get("Common", "author"))
		self.tid_base_url = config_entry(_config.get("Common", "tid_base_url"))
		self.bug_base_url = config_entry(_config.get("Common", "bug_base_url"))
		self.pat_repos_dir = config_entry(_config.get("Common", "sca_repo_dir"))
		self.pattern_dir = config_entry(_config.get("Security", "pat_dir"), '/')
		self.patdev_repos = config_entry(_config.get("GitHub", "patdev_repos")).split(',')
		self.check_duplicates = True
		self.links = ''
		self.bar_total = len(self.patdev_repos) + 3
		self.bar = ProgressBar('Generating Pattern: ', self.bar_total)

	def __str__ (self):
		return "class %s(\n  meta_class=%r, \n  meta_category=%r, \n  meta_component=%r, \n  pattern_base=%r, \n  tid_number=%r, \n  bug_number=%r, \n  conditions=%r, \n  flat=%r, \n  kernel_version=%r, \n  package_name=%r, \n  package_version=%r, \n  service_name=%r, \n  tid_url=%r,\n  bug_url=%r,\n  other_url=%r,\n  primary_link=%r,\n  links=%r,\n  pattern_filename=%r,\n  title=%r\n)" % \
(self.__class__.__name__, 
self.meta_class, 
self.meta_category, 
self.meta_component, 
self.pattern_base, 
self.tid_number, 
self.bug_number, 
self.conditions, 
self.flat,
self.kernel_version, 
self.package_name, 
self.package_version, 
self.service_name, 
self.tid_url, 
self.bug_url, 
self.other_url, 
self.primary_link,
self.links,
self.pattern_filename,
self.title
)

	def __check_for_duplicates(self):
		"Checks for pre-existing patterns with the same TID and/or BUG number"
		if self.check_duplicates:
			self.msg.normal("Updating Pattern Repositories")
			if self.msg.get_level() >= self.msg.LOG_VERBOSE:
				update_git_repos(self._config, self.msg, self.bar)
			else:
				update_git_repos(self._config, self.msg, self.bar)

			self.msg.normal("Checking for Duplicates")
			self.duplicate_patterns = {}
			output_string = ''
			duplicate_tids = sp.getoutput("find " + self.pat_repos_dir + " -type f -exec grep " + self.tid_number + " {} \+ | grep META_LINK_TID")
			if len(self.bug_number) > 1:
				duplicate_bugs = sp.getoutput("find " + self.pat_repos_dir + " -type f -exec grep " + self.bug_number + " {} \+ | grep META_LINK_BUG")
			else:
				duplicate_bugs = ''

			if len(duplicate_tids) > 0:
				for dup in duplicate_tids.split("\n"):
					self.duplicate_patterns[dup.split(':')[0]] = True
			if len(duplicate_bugs) > 0:
				for dup in duplicate_bugs.split("\n"):
					self.duplicate_patterns[dup.split(':')[0]] = True

			if len(self.duplicate_patterns) > 0:
				if len(duplicate_bugs) > 0:
					self.msg.normal("+ Duplicate(s) found using TID{0} or BUG{1}".format(self.tid_number, self.bug_number))
				else:
					self.msg.normal("+ Duplicate(s) found using TID{0}".format(self.tid_number))
				for dup in self.duplicate_patterns.keys():
					self.msg.normal("  - " + dup)
		else:
			self.msg.normal("Checking for Duplicates")
			self.msg.normal("+ Skipped by User")
			self.bar.inc_count(len(self.patdev_repos))
		if( self.msg.get_level() == self.msg.LOG_MIN ):
			self.bar.update()

	def __validate_links(self):
		"Validate URLs built from user inputs"
		self.msg.normal("Validating Solution Links")
		DISPLAY = "{0:21} {1:25} {2}"
		invalid = False
		link_list = self.links.split("|")
		for link in link_list:
			_result = {}
			_result['tag'], _result['url'] = link.split("=", 1)
			_result['status'] = "+ Confirmed"
			_result['valid'] = True
			self.msg.verbose("+ Checking", _result['url'])
			try:
				x = requests.get(_result['url'])
			except Exception as error:
				_result['status'] = "- Invalid Connection"
				_result['valid'] = False

			if( x.status_code != 200 ):
				_result['status'] = "- Invalid URL"
				invalid = True
				_result['valid'] = False
			else:
				data = x.text.split('\n')
				badlink = re.compile('Invalid Bug ID|You must enter a valid bug number', re.IGNORECASE)
				for line in data:
					if badlink.search(line):
						_result['status'] = "- Invalid Content"
						invalid = True
						_result['valid'] = False
						break
			self.link_results.append(_result)
			self.bar.inc_count()
			if( self.msg.get_level() == self.msg.LOG_MIN ):
				self.bar.update()

		for result in self.link_results:
			self.msg.normal(DISPLAY.format(result['status'], result['tag'], result['url']))

	def __get_tid_title(self):
		self.msg.normal("Retrieving TID Title")
		this_title = "Unknown - Manually enter the TID title"
		try:
			x = requests.get(self.tid_url)
		except Exception as error:
			self.msg.normal("+ Warning: Couldn't connect to the TID URL, manually enter the title.")

		if( x.status_code == 200 ):
			data = x.text.split('\n')
			urltitle = re.compile('\<title\>.*\</title\>', re.IGNORECASE)
			for line in data:
				if urltitle.search(line):
					this_title = line.split('<title>')[1].split('</title>')[0].replace(' | Support | SUSE', '')
		else:
			self.msg.normal("+ Warning: Couldn't get title from TID URL, enter in manually.")

		return this_title

	def __create_header(self):
		today = datetime.date.today()
		self.content = "#!/usr/bin/python3\n#\n"
		self.content += "# Title:       " + self.title + "\n"
		self.content += "# Description: Pattern for TID" + self.tid_number + "\n"
		self.content += "# Template:    " + self.script_name + " v" + str(self.script_version) + "\n"
		self.content += "# Modified:    " + str(today.strftime("%Y %b %d")) + "\n"
		self.content += "#\n##############################################################################\n"
		self.content += "# Copyright (C) " + str(today.year) + " SUSE LLC\n"
		self.content += "##############################################################################\n#\n"
		self.content += "# This program is free software; you can redistribute it and/or modify\n"
		self.content += "# it under the terms of the GNU General Public License as published by\n"
		self.content += "# the Free Software Foundation; version 2 of the License.\n#\n"
		self.content += "# This program is distributed in the hope that it will be useful,\n"
		self.content += "# but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
		self.content += "# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
		self.content += "# GNU General Public License for more details.\n#\n"
		self.content += "# You should have received a copy of the GNU General Public License\n"
		self.content += "# along with this program; if not, see <http://www.gnu.org/licenses/>.\n#\n"
		self.content += "#  Authors/Contributors:\n#   " + self.author + "\n#\n"
		self.content += "##############################################################################\n\n"
		if( self.conditions > 0 ):
			self.content += "import re\n"
		self.content += "import os\n"
		self.content += "import Core\n"
		if( len(self.kernel_version) > 1 or len(self.service_name) > 0 or len(self.package_name) > 0 ):
			self.content += "import SUSE\n"
		self.content += "\nmeta_class = \"" + self.meta_class + "\"\n"
		self.content += "meta_category = \"" + self.meta_category + "\"\n"
		self.content += "meta_component = \"" + self.meta_component + "\"\n"
		self.content += "pattern_id = os.path.basename(__file__)\n"
		self.content += "primary_link = \"" + self.primary_link + "\"\n"
		self.content += "overall = Core.TEMP\n"
		self.content += "overall_info = \"NOT SET\"\n"
		self.content += "other_links = \"" + self.links + "\"\n"
		self.content += "Core.init(meta_class, meta_category, meta_component, pattern_id, primary_link, overall, overall_info, other_links)\n\n"

	def __create_footer(self):
		self.content += "\tCore.printPatternResults()\n\n"
		self.content += "if __name__ == \"__main__\":\n"
		self.content += "\tmain()\n\n"

	def __create_condition_functions(self):
		if( self.conditions > 0 ):
			limit = self.conditions + 1
			self.content += "##############################################################################\n"
			self.content += "# Local Function Definitions\n"
			self.content += "##############################################################################\n\n"

			for condition in range(1, limit):
				self.content += "def condition" + str(condition) + "():\n"
				self.content += "\tfile_open = \"filename.txt\"\n"
				self.content += "\tsection = \"CommandToIdentifyFileSection\"\n"
				self.content += "\tcontent = []\n"
				self.content += "\tconfirmed = re.compile(\"\", re.IGNORECASE)\n"
				self.content += "\tif Core.isFileActive(file_open):\n"
				self.content += "\t\tif Core.getRegExSection(file_open, section, content):\n"
				self.content += "\t\t\tfor line in content:\n"
				self.content += "\t\t\t\tif confirmed.search(line):\n"
				self.content += "\t\t\t\t\treturn True\n"
				self.content += "\treturn False\n\n"

	def __create_conditions_indented(self, indent_to_level, condition_count):
		indent = ''
		these_conditions = ''

		for i in range(int(indent_to_level)):
			indent += '\t'

		if( condition_count == 0 ):
			these_conditions += str(indent) + "Core.updateStatus(Core.WARN, \"No conditions required\")\n"
		elif( condition_count == 1 ):
			these_conditions += str(indent) + "if( condition1() ):\n"
			these_conditions += str(indent) + "\tCore.updateStatus(Core.CRIT, \"Condition1 Met\")\n"
			these_conditions += str(indent) + "else:\n"
			these_conditions += str(indent) + "\tCore.updateStatus(Core.WARN, \"Condition1 not found\")\n"
		elif( condition_count == 2 ):
			these_conditions += str(indent) + "if( condition1() ):\n"
			these_conditions += str(indent) + "\tif( condition2() ):\n"
			these_conditions += str(indent) + "\t\tCore.updateStatus(Core.CRIT, \"Condition2 Met\")\n"
			these_conditions += str(indent) + "\telse:\n"
			these_conditions += str(indent) + "\t\tCore.updateStatus(Core.WARN, \"Condition2 not found\")\n"
			these_conditions += str(indent) + "else:\n"
			these_conditions += str(indent) + "\tCore.updateStatus(Core.ERROR, \"Condition1 not found\")\n"
		elif( condition_count == 3 ):
			these_conditions += str(indent) + "if( condition1() ):\n"
			these_conditions += str(indent) + "\tif( condition2() ):\n"
			these_conditions += str(indent) + "\t\tif( condition3() ):\n"
			these_conditions += str(indent) + "\t\t\tCore.updateStatus(Core.CRIT, \"Condition3 Met\")\n"
			these_conditions += str(indent) + "\t\telse:\n"
			these_conditions += str(indent) + "\t\t\tCore.updateStatus(Core.WARN, \"Condition3 not found\")\n"
			these_conditions += str(indent) + "\telse:\n"
			these_conditions += str(indent) + "\t\tCore.updateStatus(Core.ERROR, \"Condition2 not found\")\n"
			these_conditions += str(indent) + "else:\n"
			these_conditions += str(indent) + "\tCore.updateStatus(Core.ERROR, \"Condition1 not found\")\n"

		return these_conditions

	def __test_prep(self):
		base_indent = "\t"
		if( self.kernel_version != "0" ):
			self.content += base_indent + "kernel_version_fixed = '" + self.kernel_version + "'\n"
		if( self.package_name != ''):
			self.content += base_indent + "package = '" + self.package_name + "'\n"
		if( self.package_version != "0" ):
			self.content += base_indent + "package_version_fixed = '" + self.package_version + "'\n"
		if( self.service_name != "" ):
			self.content += base_indent + "service_name = '" + self.service_name + "'\n"
		if not self.basic:
			self.content += "\n"

	def __test_kernel(self, indent_to_level):
		indent = ''

		for i in range(int(indent_to_level)):
			indent += '\t'

		self.content += str(indent) + "kernel_version_installed = SUSE.compareKernel(kernel_version_fixed)\n"
		self.content += str(indent) + "if( kernel_version_installed >= 0 ):\n"
		self.content += str(indent) + "\tCore.updateStatus(Core.IGNORE, \"Bug fixes applied in kernel version \" + kernel_version_fixed + \" or higher\")\n"
		self.content += str(indent) + "else:\n"

	def __test_package_start(self, indent_to_level):
		indent = ''

		for i in range(int(indent_to_level)):
			indent += '\t'

		self.content += str(indent) + "if( SUSE.packageInstalled(package) ):\n"
		if( self.package_version != "0" ):
			self.content += str(indent) + "\tpackage_version_installed = SUSE.compareRPM(package, package_version_fixed)\n"
			self.content += str(indent) + "\tif( package_version_installed >= 0 ):\n"
			self.content += str(indent) + "\t\tCore.updateStatus(Core.IGNORE, \"Bug fixes applied for \" + package + \"\")\n"
			self.content += str(indent) + "\telse:\n"

	def __test_package_finish(self, indent_to_level):
		indent = ''

		for i in range(int(indent_to_level)):
			indent += '\t'

		self.content += str(indent) + "else:\n"
		self.content += str(indent) + "\tCore.updateStatus(Core.ERROR, \"ERROR: RPM package \" + package + \" not installed\")\n"

	def __test_service_start(self, indent_to_level):
		indent = ''

		for i in range(int(indent_to_level)):
			indent += '\t'

		self.content += str(indent) + "service_info = SUSE.getServiceDInfo(service_name)\n"
		self.content += str(indent) + "if( service_info ):\n"
		self.content += str(indent) + "\tif( service_info['UnitFileState'] == 'enabled' ):\n"
		self.content += str(indent) + "\t\tif( service_info['SubState'] == 'failed' ):\n"

	def __test_service_finish(self, indent_to_level):
		indent = ''

		for i in range(int(indent_to_level)):
			indent += '\t'

		self.content += str(indent) + "\t\telse:\n"
		self.content += str(indent) + "\t\t\tCore.updateStatus(Core.IGNORE, \"Service did not fail: \" + str(service_name))\n"
		self.content += str(indent) + "\telse:\n"
		self.content += str(indent) + "\t\tCore.updateStatus(Core.ERROR, \"Service is disabled: \" + str(service_name))\n"
		self.content += str(indent) + "else:\n"
		self.content += str(indent) + "\tCore.updateStatus(Core.ERROR, \"Service details not found: \" + str(service_name))\n"

	def __create_pattern_main(self):
		indent_kernel = 1
		indent_package = 1
		indent_service = 1
		indent_conditions = 1

		self.content += "##############################################################################\n"
		self.content += "# Main\n"
		self.content += "##############################################################################\n\n"
		self.content += "def main():\n"
		self.__test_prep()

		if( self.flat ):
			if( self.kernel_version != "0" ):
				indent_conditions = indent_kernel + 1
				self.__test_kernel(indent_kernel)
				self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
				self.content += "\n"

			if( self.package_name != ''):
				self.__test_package_start(indent_package)
				if( self.package_version != "0" ):
					indent_conditions = indent_package + 2
					self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
				else:
					indent_conditions = indent_package + 1
					self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
				self.__test_package_finish(indent_package)
				self.content += "\n"

			if( self.service_name != "" ):
				indent_conditions = indent_service + 3
				self.__test_service_start(indent_service)
				self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
				self.__test_service_finish(indent_service)
				self.content += "\n"

			if( self.basic ):
				self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
		else:
			if( self.kernel_version != "0" ):
				# Priority order: kernel > package > service > conditions
				indent_kernel = 1
				indent_package = indent_kernel + 1
				indent_conditions = indent_package + 1
				self.__test_kernel(indent_kernel)
				if( self.package_name != ''):
					self.__test_package_start(indent_package)
					if( self.package_version != "0" ):
						indent_service = indent_package + 2
						indent_conditions = indent_package + 2
					else:
						indent_service = indent_package + 1
						indent_conditions = indent_package + 1

					if( self.service_name != "" ):
						indent_conditions = indent_service + 3
						self.__test_service_start(indent_service)
						self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
						self.__test_service_finish(indent_service)
					else:
						self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
					self.__test_package_finish(indent_package)
				elif( self.service_name != "" ):
					indent_service = indent_kernel + 1
					indent_conditions = indent_service + 3
					self.__test_service_start(indent_service)
					self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
					self.__test_service_finish(indent_service)
				else:
					self.content += self.__create_conditions_indented(1, self.conditions)
			elif( self.package_name != ''):
				indent_package = 1
				self.__test_package_start(indent_package)
				if( self.package_version != "0" ):
					indent_service = indent_package + 2
					indent_conditions = indent_package + 2
				else:
					indent_service = indent_package + 1
					indent_conditions = indent_package + 1

				if( self.service_name != "" ):
					indent_conditions = indent_service + 3
					self.__test_service_start(indent_service)
					self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
					self.__test_service_finish(indent_service)
				else:
					self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
				self.__test_package_finish(indent_package)
			elif( self.service_name != "" ):
					indent_conditions = indent_service + 3
					self.__test_service_start(indent_service)
					self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
					self.__test_service_finish(indent_service)
			else:
				self.content += self.__create_conditions_indented(indent_conditions, self.conditions)
		self.content += "\n"
		
	def __save_pattern(self):
		try:
			file_open = open(self.pattern_filename, "w")
			file_open.write(self.content)
			file_open.close()
			os.chmod(self.pattern_filename, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
			self.bar.inc_count()
			if( self.msg.get_level() == self.msg.LOG_MIN ):
				self.bar.update()
		except OSError:
			print((" ERROR: Cannot create " + str(self.pattern_filename) + ": " + str(error)))

	def set_metadata(self, mdlist):
		"Set the metadata values from the ordered list mdlist"
		IDX_CLASS = 0
		IDX_CATEGORY = 1
		IDX_COMPONENT = 2
		IDX_FILENAME = 3
		IDX_TID = 4
		IDX_BUG = 5
		mdcount_min = 5

		self.meta_class = mdlist[IDX_CLASS]
		self.meta_category = mdlist[IDX_CATEGORY]
		self.meta_component = mdlist[IDX_COMPONENT]
		self.pattern_base = mdlist[IDX_FILENAME]
		self.tid_number = str(mdlist[IDX_TID])
		self.msg.min("Evaluating TID", str(self.tid_number))
		self.tid_url = self.tid_base_url + self.tid_number
		self.pattern_filename = self.pattern_dir + self.pattern_base + "-" + self.tid_number + ".py"
		self.links = "META_LINK_TID=" + self.tid_url
		if( len(mdlist) > mdcount_min ):
			self.bug_number = str(mdlist[IDX_BUG])
			if( len(self.bug_number) > 1 ):
				self.bug_url = self.bug_base_url + self.bug_number
				self.links = self.links + "|META_LINK_BUG=" + self.bug_url
		if( len(self.other_url) > 0 ):
			self.links = self.links + "|" + self.other_url
		link_list = self.links.split("|")
		self.bar.set_total(self.bar.get_total() + len(link_list))
		if( self.msg.get_level() == self.msg.LOG_MIN ):
			self.msg.min()
			self.bar.update()
		self.__validate_links()
		self.__check_for_duplicates()
		self.title = self.__get_tid_title()
		self.bar.inc_count()
		if( self.msg.get_level() == self.msg.LOG_MIN ):
			self.bar.update()

	def set_conditions(self, conditions):
		self.conditions = conditions

	def set_flat(self, status):
		self.flat = status
		
	def set_override_validation(self, status):
		self.override_validation = status

	def set_check_duplicates(self, status):
		self.check_duplicates = status

	def set_kernel(self, kernel_version):
		self.kernel_version = kernel_version
		if( self.kernel_version != "0" ):
			self.basic = False

	def set_package(self, package_name, package_version):
		self.package_name = package_name
		self.package_version = package_version
		if( self.package_name != ''):
			self.basic = False

	def set_service(self, service_name):
		self.service_name = service_name
		if( self.service_name != "" ):
			self.basic = False

	def set_other_url(self, other_url):
		url_parts = other_url.split("=")
		if( len(url_parts) > 1 ):
			url_tag = "META_LINK_" + str(url_parts[0])
			url_body = url_parts[1]
		else:
			url_body = url_parts[0]
			if( "documentation.suse.com" in url_body ):
				url_tag = "META_LINK_DOC"
			elif( "www.suse.com/support/kb" in url_body ):
				url_tag = "META_LINK_TID2"
			elif( url_body.startswith("CVE-") ):
				url_tag = "META_LINK_" + str(url_body)
				url_body = "https://www.suse.com/security/cve/" + url_body + "/"
			else:
				url_tag = "META_LINK_OTHER"

		self.other_url = url_tag + "=" + url_body

	def create_pattern(self):
		"Create and save the pattern. Requires set_metadata to be called first."
		self.__create_header()
		if( self.basic ):
			if( self.conditions < 1 ):
				self.set_conditions(1)
		self.__create_condition_functions()
		self.__create_pattern_main()
		self.__create_footer()
		self.__save_pattern()
		self.bar.inc_count()
		if( self.msg.get_level() == self.msg.LOG_MIN ):
			self.bar.update()
		self.msg.debug("  <> Pattern", self.pattern_filename)
		self.msg.debug("  <> Content", self.content)
		
	def show_summary(self):
		"Show a summary of the pattern created"

		if( self.msg.get_level() == self.msg.LOG_MIN ):
			self.bar.finish()
		else:
			self.msg.normal()
			separator_line('-')
		self.msg.min("Title", self.title)
		self.msg.min("Pattern", self.pattern_filename)
		self.msg.min("Basic", self.basic)
		self.msg.min("Solution Links", len(self.link_results))
		for this_link in self.link_results:
			if not this_link['valid']:
				self.msg.min(this_link['status'], this_link['url'])
		self.msg.min("Duplicate Patterns", str(len(self.duplicate_patterns)))
		for this_pattern in self.duplicate_patterns.keys():
			self.msg.min("+ Duplicate", this_pattern)
		if( self.flat ):
			self.msg.min("Ordering", "Flat")
		else:
			self.msg.min("Ordering", "Stacked")
		if( self.kernel_version != "0" ):
			self.msg.min("Kernel Version", self.kernel_version)
		else:
			self.msg.min("Kernel Version", "None")
		if( self.package_name != ''):
			self.msg.min("Package Name", self.package_name)
		else:
			self.msg.min("Package Name", "None")
		if( self.package_version != "0"):
			self.msg.min("Package Version", self.package_version)
		else:
			self.msg.min("Package Version", "None")
		if( self.service_name != "" ):
			self.msg.min("Service Name", self.service_name)
		else:
			self.msg.min("Service Name", "None")
		self.msg.min("Conditions", self.conditions)
		self.msg.min()

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


class DisplayMessages():
	"Display message string for a given log level"
	LOG_QUIET	= 0	# turns off messages
	LOG_MIN		= 1	# minimal messages
	LOG_NORMAL	= 2	# normal, but significant, messages
	LOG_VERBOSE	= 3	# detailed messages
	LOG_DEBUG	= 4	# debug-level messages
	LOG_LEVELS      = {0: "Quiet", 1: "Minimal", 2: "Normal", 3: "Verbose", 4: "Debug" }
	DISPLAY_PAIR    = "{0:30} = {1}"
	DISPLAY         = "{0:30}"

	def __init__(self, level=LOG_MIN):
		self.level = level

	def __str__ (self):
		return "class %s(level=%r)" % (self.__class__.__name__,self.level)

	def get_level(self):
		return self.level

	def get_level_str(self):
		return self.LOG_LEVELS[self.level]

	def set_level(self, level):
		if( level >= self.LOG_DEBUG ):
			self.level = self.LOG_DEBUG
		else:
			self.level = level

	def validate_level(self, level):
		validated_level = -1
		if( level.isdigit() ):
			validated_level = int(level)
		else:
			argstr = level.lower()
			if( argstr.startswith("qui") ):
				validated_level = self.LOG_QUIET
			elif( argstr.startswith("min") ):
				validated_level = self.LOG_MIN
			elif( argstr.startswith("norm") ):
				validated_level = self.LOG_NORMAL
			elif( argstr.startswith("verb") ):
				validated_level = self.LOG_VERBOSE
			elif( argstr.startswith("debug") ):
				validated_level = self.LOG_DEBUG
		return validated_level


	def __write_paired_msg(self, level, msgtag, msgstr):
		if( level <= self.level ):
			print(self.DISPLAY_PAIR.format(msgtag, msgstr))

	def __write_msg(self, level, msgtag):
		if( level <= self.level ):
			print(self.DISPLAY.format(msgtag))

	def quiet(self, msgtag = None, msgstr = None):
		"Write messages even if quiet is set"
		if msgtag:
			if msgstr:
				self.__write_paired_msg(self.LOG_QUIET, msgtag, msgstr)
			else:
				self.__write_msg(self.LOG_QUIET, msgtag)
		else:
			if( self.level >= self.LOG_QUIET ):
				print()

	def min(self, msgtag = None, msgstr = None):
		"Write the minium amount of messages"
		if msgtag:
			if msgstr:
				self.__write_paired_msg(self.LOG_MIN, msgtag, msgstr)
			else:
				self.__write_msg(self.LOG_MIN, msgtag)
		else:
			if( self.level >= self.LOG_MIN ):
				print()

	def normal(self, msgtag = None, msgstr = None):
		"Write normal, but significant, messages"
		if msgtag:
			if msgstr:
				self.__write_paired_msg(self.LOG_NORMAL, msgtag, msgstr)
			else:
				self.__write_msg(self.LOG_NORMAL, msgtag)
		else:
			if( self.level >= self.LOG_NORMAL ):
				print()

	def verbose(self, msgtag = None, msgstr = None):
		"Write more verbose informational messages"
		if msgtag:
			if msgstr:
				self.__write_paired_msg(self.LOG_VERBOSE, msgtag, msgstr)
			else:
				self.__write_msg(self.LOG_VERBOSE, msgtag)
		else:
			if( self.level >= self.LOG_VERBOSE ):
				print()

	def debug(self, msgtag = None, msgstr = None):
		"Write all messages, including debug level"
		if msgtag:
			if msgstr:
				self.__write_paired_msg(self.LOG_DEBUG, msgtag, msgstr)
			else:
				self.__write_msg(self.LOG_DEBUG, msgtag)
		else:
			if( self.level >= self.LOG_DEBUG ):
				print()

class SecurityAnnouncement():
	"Security announcement class"
	IDX_LAST = -1
	IDX_FIRST = 0

	def __init__(self, _msg, _config, url_date, _file, _version):
		self.msg = _msg
		self.pat_logs_dir = config_entry(_config.get("Security", "pat_logs"), '/')
		self.pat_dir = config_entry(_config.get("Security", "pat_dir"), '/')
		self.author = config_entry(_config.get("Common", "author"))
		self.bin_version = _version
		self.file = _file
		self.url_date = url_date
		self.safilepath = self.pat_logs_dir + self.file
		self.sauri = self.url_date + self.file
		self.loaded_file = []
		self.main_package = ''
		self.announcement_id = ''
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

class GitHubRepository():
	"""Creates an instance of a GitHub repository. _path must be a valid GitHub repository"""
	def __init__(self, _msg, _path):
		self.msg = _msg
		self.path = _path
		self.info = {'name': os.path.basename(self.path), 'valid': True, 'origin': '', 'branch': '', 'outdated': False, 'state': 'Current', 'content': '', 'spec_ver': 'Unknown', 'spec_ver_bumped': 'Unknown'}
		self.git_config_file = self.path + "/.git/config"
		self.spec_file = self.path + '/spec/' + self.info['name'] + ".spec"
		self.uncommitted_patterns = {}
		self.committed_patterns = {}
		self.local_sa_patterns = {}
		self.local_regular_patterns = {}
		self.__probe_repo_info()
		self.parse_local_patterns()

	def __str__ (self):
		return "class %s(level=%r)" % (self.__class__.__name__,self.msg,self.path)

	def __probe_repo_info(self):
		self.msg.normal("Probing repository information")
		self.msg.verbose("+ Repository Name", self.info['name'])
		# Remote origin
		git_config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
		git_config.read(self.git_config_file)
		self.info['origin'] = config_entry(git_config.get('remote "origin"', "url"))
		del git_config

		# Spec file version
		this_version = ""
		version = re.compile("^Version:\s.*[0-9]", re.IGNORECASE)
		fd = open(self.spec_file, "r")
		lines = fd.readlines()
		fd.close()
		for line in lines:
			if version.search(line):
				this_version = line.split()[-1]
				break

		self.info['spec_ver'] = this_version

		if( this_version ):
			parts = this_version.split('.')
			bumped = str(int(parts[-1]) + 1)
			parts[-1] = str(bumped)
			bumped_version = '.'.join(parts)
			self.info['spec_ver_bumped'] = bumped_version
			self.msg.verbose("+ Bumping package version", "{0} -> {1}".format(self.info['spec_ver'], self.info['spec_ver_bumped']))
		else:
			self.msg.verbose("+ Could not find package version in {0}".format(get_spec_file))

		# Git remote status
		os.chdir(self.path)
		try:
			p = sp.run(['/usr/bin/git', 'status'], universal_newlines=True, stdout=sp.PIPE, stderr=sp.PIPE)
		except Exception as e:
			self.msg.debug('  <> sp.run Exception')

			if( self.msg.get_level() >= self.msg.LOG_NORMAL ):
				self.msg.normal()
				print(str(e) + "\n")
				separator_line('-')
				print()
			return self.info

		if p.returncode > 0:
			self.msg.debug("  <> Non-Zero return code, p.returncode > 0")
		else:
			this_branch = re.compile("On branch", re.IGNORECASE)
			this_status = re.compile("is ahead of|Changes not staged for commit|Untracked files", re.IGNORECASE)
			data = p.stdout.splitlines()
			self.msg.debug("<> Command Output", "git status")
			for line in data:
				self.msg.debug("> " + line)
				if this_branch.search(line):
					self.info['branch'] = line.split()[-1]
				elif this_status.search(line):
					self.info['outdated'] = True
					self.info['state'] = "Push"
			self.info['content'] = data

		if( len(self.info['origin']) == 0 ):
			self.info['valid'] = False
		if( len(self.info['branch']) == 0 ):
			self.info['valid'] = False
		if( len(self.info['content']) == 0 ):
			self.info['valid'] = False

	def __get_committed_repo_range(self):
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
		
	def __get_committed_repo_uuid_list(self, _repo_range):
		prog = "git --no-pager log " + _repo_range
		commits_to_check = []

		p = sp.run(prog, shell=True, check=True, stdout=sp.PIPE, stderr=sp.PIPE, universal_newlines=True)

		for l in p.stdout.splitlines():
			line = l.lstrip()
			if( line.startswith("commit ") ):
				commits_to_check.append(line.split()[1])
		
		return commits_to_check

	def get_info(self):
		return self.info

	def get_uncommitted_list(self):
		self.msg.normal("Searching for local patterns", "uncommitted")
		prog = "git status"
		self.uncommitted_patterns = {}
		pat_file = re.compile("^patterns/.*")
		new_file = re.compile("^new file:.*patterns/", re.IGNORECASE)
		mod_file = re.compile("^modified:.*patterns/", re.IGNORECASE)
		del_file = re.compile("^deleted:.*patterns/", re.IGNORECASE)
		oldwd = os.getcwd()
		os.chdir(self.path)

		p = sp.run(prog, shell=True, check=True, stdout=sp.PIPE, stderr=sp.PIPE, universal_newlines=True)
		# There are two possible output formats from this command:
		# 	new file:   patterns/SLE/sle15sp4/xterm_SUSE-SU-2023_0221-1_sles_15.4.py
		#   patterns/SLE/sle15sp4/xterm_SUSE-SU-2023_0221-1_sles_15.4.py
		# This currently handles both formats
		os.chdir(oldwd)

		this_pattern = ''
		for l in p.stdout.splitlines():
			line = l.lstrip()
			if pat_file.search(line):
				pattern_path = line
				self.uncommitted_patterns[pattern_path] = 'add'
			elif new_file.search(line):
				pattern_path = line.split()[-1]
				self.uncommitted_patterns[pattern_path] = 'add'
			elif mod_file.search(line):
				pattern_path = line.split()[-1]
				self.uncommitted_patterns[pattern_path] = 'mod'
			elif del_file.search(line):
				pattern_path = line.split()[-1]
				self.uncommitted_patterns[pattern_path] = 'del'
		self.msg.verbose("+ Patterns Found", str(len(self.uncommitted_patterns.keys())))

	def get_committed_list(self):
		self.msg.normal("Searching for local patterns", "committed, not pushed")
		prog = "git diff-tree --no-commit-id --name-only -r "
		self.committed_patterns = {}
		pat_file = re.compile("^patterns/.*")
		new_file = re.compile("^new file:.*patterns/", re.IGNORECASE)
		mod_file = re.compile("^modified:.*patterns/", re.IGNORECASE)
		del_file = re.compile("^deleted:.*patterns/", re.IGNORECASE)

		oldwd = os.getcwd()
		os.chdir(self.path)
		repo_range = self.__get_committed_repo_range()
		commit_list = self.__get_committed_repo_uuid_list(repo_range)
		pattern = re.compile("patterns/.*")
		
		for _commit in commit_list:
			p = sp.run(prog + _commit, shell=True, check=True, stdout=sp.PIPE, stderr=sp.PIPE, universal_newlines=True)

			for l in p.stdout.splitlines():
				line = l.lstrip()
				if pat_file.search(line):
					pattern_path = line
					self.committed_patterns[pattern_path] = 'add'
				elif new_file.search(line):
					pattern_path = line.split()[-1]
					self.committed_patterns[pattern_path] = 'add'
				elif mod_file.search(line):
					pattern_path = line.split()[-1]
					self.committed_patterns[pattern_path] = 'mod'
				elif del_file.search(line):
					pattern_path = line.split()[-1]
					self.committed_patterns[pattern_path] = 'del'
		os.chdir(oldwd)
		self.msg.verbose("+ Patterns Found", str(len(self.committed_patterns)))

	def parse_local_patterns(self):
		pattern = re.compile("patterns/.*_SUSE-SU")
		self.local_sa_patterns = {}
		self.local_regular_patterns = {}
		self.get_uncommitted_list()
		self.get_committed_list()
		check_patterns = { **self.uncommitted_patterns, **self.committed_patterns } # Merge the two dictionaries
		self.msg.normal("Filtering local patterns")
		for key, value in check_patterns.items():
			if pattern.search(key):
				self.local_sa_patterns[key] = value
			else:
				self.local_regular_patterns[key] = value
		self.msg.verbose("+ Security Patterns", str(len(self.local_sa_patterns)))
		self.msg.verbose("+ Regular Patterns", str(len(self.local_regular_patterns)))

	def get_local_sa_patterns(self):
		return self.local_sa_patterns

	def get_local_regular_patterns(self):
		return self.local_regular_patterns


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


def show_config_file():
	"""Dump the current configuration file object"""
	print("Config File: {0}\n".format(_config_file))
	for section in _config.sections():
		print("[%s]" % section)
		for options in _config.options(section):
			print("%s = %s" % (options, _config.get(section, options)))
		print()

def validate_sa_patterns(_config, _msg):
	_msg.normal("Searching for Security Patterns to Validate")
	pat_dir = _config.get("Security", "pat_dir")
	pat_error_dir = _config.get("Security", "pat_error")
	pat_logs_dir = _config.get("Security", "pat_logs")
	pat_dups_dir = _config.get("Security", "pat_dups")
	patterns = []
	pattern_cache = []
	_msg.debug("Directory:", pat_dir)
	for file in glob(pat_dir + "/*.py"):
		patterns.append(file)
	for file in glob(pat_dir + "/*.pl"):
		patterns.append(file)
	_msg.debug("Number of Patterns", len(patterns))
	total = len(patterns)
	if( total < 1 ):
		print("+ Warning: No security patterns found, run sagen\n")
		return total
	else:
		_msg.normal("+ Patterns Found", total)
	size = len(str(total))

	_msg.normal("Building Pre-existing Pattern Cache")
	sca_repo_dir = _config.get("Common", "sca_repo_dir")
	for root, dirs, files in os.walk(sca_repo_dir):
		for name in files:
			pattern_cache.append(name)
	_msg.normal("+ Patterns Found", len(pattern_cache))

	count = 0
	fatal = []
	duplicates = []
	valid = 0
	if( _msg.get_level() == _msg.LOG_MIN ):
		bar = ProgressBar("Validating: ", total)
	_msg.normal("Checking Patterns")
	for pattern in patterns:
		count += 1
		pattern_file = os.path.basename(pattern)
		_msg.normal("+ Pattern [{}/{}]".format(count, total), pattern_file)
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
		if( _msg.get_level() == _msg.LOG_MIN ):
			bar.inc_count()
			bar.update()
	if( _msg.get_level() == _msg.LOG_MIN ):
		bar.finish()
	fatal_count = len(fatal)
	dup_count = len(duplicates)

	_msg.min()
	_msg.min("Summary")
	if( _msg.get_level() >= _msg.LOG_MIN ):
		separator_line('-')
	_msg.min(SUMMARY_FMT.format("Total", total))
	_msg.min(SUMMARY_FMT.format("Valid", valid))
	_msg.min(SUMMARY_FMT.format("Fatal", fatal_count))
	_msg.min(SUMMARY_FMT.format("Duplicates", dup_count))
	_msg.min()

	if( fatal_count > 0 ):
		_msg.min("Failed Patterns:")
		for failure in fatal:
			_msg.min(failure)
		_msg.min()

	if( dup_count > 0 ):
		_msg.min("Duplicate Patterns:")
		for dup in duplicates:
			_msg.min(dup)
		_msg.min()

	return total

def distribute_sa_patterns(_config):
	"""Distribute python patterns generated by sagen"""
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


def github_path_valid(msg, path):
	rc = True
	git_config_file = path + "/.git/config"
	spec_file = path + '/spec/' + os.path.basename(path) + ".spec"
	if not os.path.exists(git_config_file):
		msg.debug("  <github_path_valid> Error: File not found -" + git_config_file)
		rc = False
	elif not os.path.exists(spec_file):
		msg.debug("  <github_path_valid> Error: File not found -" + spec_file)
		rc = False

	return rc

def convert_log_date(given_str, use_prev_month=False):
	"Converts given string to valid format for change logs"
	converted_str = 'INVALID'
	today = datetime.datetime.today()
	MONTHS = {1: 'Jan', 2: 'Feb', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Jun', 
	7: 'Jul', 8: 'Aug', 9: 'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec', 
	'jan': 'Jan', 'feb': 'Feb', 'mar': 'Mar', 'apr': 'Apr', 'may': 'May', 'jun': 'Jun', 
	'jul': 'Jul', 'aug': 'Aug', 'sep': 'Sep', 'oct': 'Oct', 'nov': 'Nov', 'dec': 'Dec'}
	this_year = today.strftime("%Y")
	this_month = int(today.strftime("%m"))
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
							sys.exit(3)
			else:
				part = part[:3].lower()
				if( part in MONTHS.keys() ):
					use_month = MONTHS[part]
				else:
					sys.exit(3)
		if( len(use_year) == 0 ):
			use_year = this_year
		if( len(use_month) == 0 ):
			use_month = MONTHS[this_month]
		converted_str = str(use_month) + " " +str(use_year)
	else:
		if use_prev_month:
			if( this_month == 1 ):
				use_month = 12
				use_year = int(this_year) - 1
			else:
				use_month = this_month - 1
				use_year = this_year
		else:
			use_month = this_month
			use_year = this_year
		converted_str = str(MONTHS[use_month]) + " " + str(use_year)
	return converted_str

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
	_msg.debug("  <convert_sa_date> Date Conversion", "given_str=" + str(given_str) + ", converted_str=" + str(converted_str))
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

def validate_link_list(link_list, _c_, _msg):
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
			_msg.normal(vdisplay.format(status, link))
			continue
		except requests.exceptions.ConnectionError as errc:
			status = "- Invalid Connection"
			_c_['badconnection'] += 1
			bad_links[link] = "Invalid Connection"
			_msg.normal(vdisplay.format(status, link))
			continue
		except requests.exceptions.Timeout as errt:
			status = "- Server Timeout"
			_c_['ping'] += 1
			bad_links[link] = "Server Timeout"
			_msg.normal(vdisplay.format(status, link))
			continue
		except requests.exceptions.RequestException as err:
			status = "- Invalid URL"
			_c_['badurl'] += 1
			bad_links[link] = "Invalid URL"
			_msg.normal(vdisplay.format(status, link))
			continue
		except Exception as error:
			status = "- Unknown Error"
			_c_['ping'] += 1
			bad_links[link] = "Unknown Error"
			_msg.normal(vdisplay.format(status, link))
			continue


		urlhost = link.split('/')[2]
		if oldhosts.search(urlhost):
			status = "- Old Host"
			_c_['oldhosts'] += 1
			bad_links[link] = "Old Host"
			_msg.normal(vdisplay.format(status, link))
			continue

		if( x.status_code == 200 ):
			data = x.text.split('\n')
			badlink = re.compile('Invalid Bug ID|You must enter a valid bug number', re.IGNORECASE)
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
		_msg.verbose(vdisplay.format(status, link))
	return bad_links, _c_

def config_entry(_entry, trailer = ''):
	formatted_entry = _entry.strip('\"\'')
	if( len(trailer) > 0 ):
		if not formatted_entry.endswith(trailer):
			formatted_entry = formatted_entry + str(trailer)
	return formatted_entry

def update_git_repos(_config, _msg, _bar):
	sca_repo_dir = config_entry(_config.get("Common", "sca_repo_dir"))
	github_uri_base = config_entry(_config.get("GitHub", "uri_base"))
	patdev_repos = config_entry(_config.get("GitHub", "patdev_repos")).split(',')

	for repo in patdev_repos:
		repo_path = sca_repo_dir + repo
		if os.path.exists(repo_path):
			_msg.normal("+ Updating Local Repository", repo)
			prog = "git -C " + repo_path + " pull"
		else:
			_msg.normal("+ Cloning GitHub Repository", repo)
			prog = "git -C " + sca_repo_dir + " clone " + github_uri_base + "/" + repo + ".git"

		try:
			p = sp.run(prog.split(), universal_newlines=True, stdout=sp.PIPE, stderr=sp.PIPE)
		except Exception as e:
			_msg.normal("+ Exception: Command failed - " + prog)
			_msg.normal()
			_msg.normal(p.stdout)
			_msg.normal(p.stderr)

		if p.returncode != 0:
			_msg.normal("+ ERROR: Command failed - " + prog)
			_msg.normal()
			_msg.normal(p.stdout)
			_msg.normal(p.stderr)
		else:
			_msg.verbose(p.stdout)
			_msg.verbose()
		_bar.inc_count()
		if( _msg.get_level() == _msg.LOG_MIN ):
			_bar.update()		


