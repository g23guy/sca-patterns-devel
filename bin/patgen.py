#!/usr/bin/python3
SVER = '1.0.0'
##############################################################################
# patgen.py - SCA Tool Python3 Pattern Generator
# Copyright (C) 2022 SUSE LLC
#
# Description:  Creates a pattern template for TIDs based on commandline
#               conditions.
# Modified:     2022 Sep 27
#
##############################################################################
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#  Authors/Contributors:
#     Jason Record <jason.record@suse.com>
#
##############################################################################

import sys
import os
import stat
import re
import getopt
import datetime
import requests

# Global Options
script_name = "SCA Tool Python Pattern Generator"

# Class and Function Definitions

def title():
	print("\n##################################################")
	print(("# " + script_name + " v" + str(SVER)))
	print("##################################################")

def usage():
	print("Description:")
	print("  Ordering, Stacked: kernel > package > service > conditions")
	print("  Ordering, Flat:    kernel   package   service   conditions")
	print()
	print("Usage:")
	print("  " + str(os.path.basename(__file__)) + " [OPTIONS] <class,category,component,filename,tid#[,bug#]>")
	print()
	print("OPTIONS")
	print("  -c <0-3>, --conditions=<0-3>       Number of conditional functions to include, default=0")
	print("  -k <ver>, --kernel-version=<ver>   The kernel's version where the issue is fixed")
	print("  -r <name>, --rpm=<name>            The affected RPM package name")
	print("  -p <ver>, --package-version=<ver>  The package's version where the issue is fixed")
	print("  -s <name>, --service=<name>        The systemd service name affected")
	print("  -f, --flat                         All requested conditions are tested independently and not included in stacked order")
	print()
	print("METADATA")
	print("  class:        SLE,HAE,SUMA,Security,Custom")
	print("  category:     Category name string")
	print("  component:    Component name string")
	print("  filename:     Pattern filename (TID number will be added automatically)")
	print("  tid#:         TID number only")
	print("  bug#:         Bug number only (optional)")
	print()

class PatternTemplate():
	TID_BASE_URL = "https://www.suse.com/support/kb/doc/?id="
	BUG_BASE_URL = "https://bugzilla.suse.com/show_bug.cgi?id="
	author = 'Jason Record <jason.record@suse.com>'
	content = ''
	content_kernel = ''
	content_package = ''
	content_service = ''

	def __init__(self, script_name):
		self.meta_class = ''
		self.meta_category = ''
		self.meta_component = ''
		self.pattern_base = ''
		self.pattern_dir = os.getcwd()
		self.pattern_filename = ''
		self.tid_number = '0'
		self.bug_number = '0'
		self.conditions = 0
		self.flat = False
		self.basic = True
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
		self.links = ''

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

	def __validate_links(self):
		invalid = False
		link_list = self.links.split("|")
		for link in link_list:
			check_tag, check_url = link.split("=", 1)
			print("Validating " + check_tag + " " + check_url)
			try:
				x = requests.get(check_url)
			except Exception as error:
				print(" + Warning: Couldn't connect to the TID URL, manually enter the title.")

			if( x.status_code != 200 ):
				print("+ Invalid")
				invalid = True
		if( invalid ):
			print()
			print("Error: One of the links is not valid, please check the link and rerun")
			print()
			sys.exit(2)

	def __get_tid_title(self):
		print("Evaluating TID" + self.tid_number)
		this_title = "Manually enter the title"
		try:
			x = requests.get(self.tid_url)
		except Exception as error:
			print(" + Warning: Couldn't connect to the TID URL, manually enter the title.")

		if( x.status_code == 200 ):
			data = x.text.split('\n')
			urltitle = re.compile('\<title\>.*\</title\>', re.IGNORECASE)
			for line in data:
				if urltitle.search(line):
					this_title = line.split('<title>')[1].split('</title>')[0].replace(' | Support | SUSE', '')
		else:
			print(" + Warning: Couldn't get title from TID URL, enter in manually.")

		return this_title

	def __create_header(self):
		today = datetime.date.today()
		self.content = "#!/usr/bin/python3\n#\n"
		self.content += "# Title:       " + self.title + "\n"
		self.content += "# Description: Pattern for TID" + self.tid_number + "\n"
		self.content += "# Template:    " + self.script_name + " v" + str(SVER) + "\n"
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
		if( self.kernel_version != "0" ):
			self.content += "kernel_version_fixed = '" + self.kernel_version + "'\n"
		if( self.package_name != ''):
			self.content += "package = '" + self.package_name + "'\n"
		if( self.package_version != "0" ):
			self.content += "package_version_fixed = '" + self.package_version + "'\n"
		if( self.service_name != "" ):
			self.content += "service_name = '" + self.service_name + "'\n"
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
		indent_kernel = 0
		indent_package = 0
		indent_service = 0
		indent_conditions = 0

		self.content += "##############################################################################\n"
		self.content += "# Main\n"
		self.content += "##############################################################################\n\n"
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
				indent_kernel = 0
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
				indent_package = 0
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
		self.tid_url = self.TID_BASE_URL + self.tid_number
		self.pattern_filename = self.pattern_dir + "/" + self.pattern_base + "-" + self.tid_number + ".py"
		self.links = "META_LINK_TID=" + self.tid_url
		if( len(mdlist) > mdcount_min ):
			self.bug_number = str(mdlist[IDX_BUG])
			if( len(self.bug_number) > 1 ):
				self.bug_url = self.BUG_BASE_URL + self.bug_number
				self.links = self.links + "|META_LINK_BUG=" + self.bug_url
		if( len(self.other_url) > 0 ):
			self.links = self.links + "|" + self.other_url
		self.__validate_links()
		self.title = self.__get_tid_title()

	def set_conditions(self, conditions):
		self.conditions = conditions

	def set_flat(self, status):
		self.flat = status

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
		self.__save_pattern()
#		print(pat)
#		print(self.content)
		
	def show_summary(self):
		"Show a summary of the pattern created"
		DISPLAY = "{0:18} = {1}"
		
		print()
		print(DISPLAY.format("Title", self.title))
		print(DISPLAY.format("Pattern", self.pattern_filename))
		print(DISPLAY.format("Basic", self.basic))
		if( self.flat ):
			print(DISPLAY.format("Ordering", "Flat"))
		else:
			print(DISPLAY.format("Ordering", "Stacked"))
		if( self.kernel_version != "0" ):
			print(DISPLAY.format("Kernel Version", self.kernel_version))
		else:
			print(DISPLAY.format("Kernel Version", "None"))
		if( self.package_name != ''):
			print(DISPLAY.format("Package Name", self.package_name))
		else:
			print(DISPLAY.format("Package Name", "None"))
		if( self.package_version != "0"):
			print(DISPLAY.format("Package Version", self.package_version))
		else:
			print(DISPLAY.format("Package Version", "None"))
		if( self.service_name != "" ):
			print(DISPLAY.format("Service Name", self.service_name))
		else:
			print(DISPLAY.format("Service Name", "None"))
		print(DISPLAY.format("Conditions", self.conditions))
		print()

def option_error(msg):
	print(msg)
	print()
	usage()
	sys.exit(1)


##############################################################################
# Main
##############################################################################

def main(argv):
	"main entry point"
	global SVER, script_name

	given_conditions = 0
	conditions_min = 1
	conditions_max = 3
	metadata_min = 5
	metadata_max = 6
	package_name = ''
	package_version = '0'

	try:
		(optlist, args) = getopt.gnu_getopt(argv[1:], "hc:fk:r:p:s:u:", ["help", "conditions=", "flast", "kernel-version=", "rpm=", "package-version=", "service=", "url="])
	except getopt.GetoptError as exc:
		title()
		print("Error:", exc, file=sys.stderr)
		sys.exit(2)
	for option, arguement in optlist:
		if option in {"-h", "--help"}:
			title()
			usage()
			sys.exit(0)
		elif option in {"-c", "--conditions"}:
			if( arguement.isdigit() ):
				given_conditions = int(arguement)
				if( given_conditions > conditions_max ):
					title()
					option_error("Error: Invalid number of conditions, range is 0-3")
				else:
					pat.set_conditions(given_conditions)
			else:
				title()
				option_error("Error: Integer required for conditions, range is 0-3")
		elif option in {"-f", "--flat"}:
			pat.set_flat(True)
		elif option in {"-k", "--kernel-version"}:
			pat.set_kernel(arguement)
		elif option in {"-r", "--rpm"}:
			package_name = arguement
		elif option in {"-p", "--package-version"}:
			package_version = arguement
		elif option in {"-s", "--service"}:
			pat.set_service(arguement)
		elif option in {"-u", "--url"}:
			pat.set_other_url(arguement)

	title()

	if( len(package_name) > 0 ): # package_name without a package_version is ok
		pat.set_package(package_name, package_version)
	elif( len(package_version) > 1 ): # package_version without a package_name is not allowed
			option_error("Error: Missing affected RPM package name")

	if len(args) > 0:
		given_metadata = args[0].split(",")
		given_metadata_count = len(given_metadata)
		if( given_metadata_count < metadata_min ):
			option_error("Error: Insufficent metadata elements")
		elif( given_metadata_count > metadata_max ):
			option_error("Error: Too many metadata elements")
	else:
		option_error("Error: Missing pattern metadata")

	pat.set_metadata(given_metadata)
	pat.create_pattern()
	pat.show_summary()

# Entry point
if __name__ == "__main__":
	pat = PatternTemplate(script_name)
	main(sys.argv)


