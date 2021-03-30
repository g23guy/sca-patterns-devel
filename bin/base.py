#!/usr/bin/python3
SVER = '0.3.1'
##############################################################################
# base.py - Basic Python Pattern Template
# Copyright (C) 2021 SUSE LLC
#
# Description:  Creates a pattern template for TIDs where a specific package
#               and version contain a break and a fix.
# Modified:     2021 Mar 26
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
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

AUTHOR = 'Jason Record <jason.record@suse.com>'
MD = {
	'class': '',
	'category': '',
	'component': '',
	'title': '',
	'tid': '',
	'tidurl': '',
	'bug': '',
	'bugurl': '',
	'links': '',
	'patfile': '',
	'name': '',
	'conditions': 1,
	'package': 0,
	'service': 0
}
CONTENT = ''
CONTENT_CONDITIONS = ''
DISPLAY = "{0:15} = {1}"
VERBOSE = True
RCODE = 0
OPTIONS_REQ = 9

def title():
	print("\n##################################################")
	print("# Python Basic Pattern Template, v" + str(SVER))
	print("##################################################")

def createMetadata(IDENTITY_CODE):
	global MD
#	print(IDENTITY_CODE)
	(MD['class'], MD['category'], MD['component'], MD['name'], MD['tid'], MD['bug'], MD['conditions'], MD['package'], MD['service'] ) = IDENTITY_CODE.split(',')
	MD['tidurl'] = "https://www.suse.com/support/kb/doc/?id=" + str(MD['tid'])
	if( int(MD['bug']) > 0 ):
		MD['bugurl'] = "https://bugzilla.suse.com/show_bug.cgi?id=" + str(MD['bug'])
		MD['links'] = "META_LINK_TID=" + MD['tidurl'] + "|META_LINK_BUG=" + MD['bugurl']
	else:
		MD['bug'] = ''
		MD['links'] = "META_LINK_TID=" + MD['tidurl']
	MD['patfile'] = MD['name'] + "-" + MD['tid'] + ".py"

	if( int(MD['service']) > 0 ):
		MD['service'] = True
	else:
		MD['service'] = False
#	print(MD)

def patternHeader(OPT):
	global MD
	global CONTENT

	TODAY = datetime.date.today()
	# Build pattern file content
	CONTENT = "#!/usr/bin/python\n#\n"
	CONTENT += "# Title:       Pattern for TID" + MD['tid'] + "\n"
	CONTENT += "# Description: " + MD['title'] + "\n"
	CONTENT += "# Source:      Package Version Pattern Template v" + str(SVER) + "\n"
	CONTENT += "# Options:     " + str(OPT) + "\n"
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
	CONTENT += "#  Authors/Contributors:\n#   " + AUTHOR + "\n#\n"
	CONTENT += "##############################################################################\n\n"
	if( int(MD['conditions']) > 0 ):
		CONTENT += "import re\n"
	CONTENT += "import os\n"
	CONTENT += "import Core\n"
	if( int(MD['package']) > 0 or MD['service'] ):
		CONTENT += "import SUSE\n"
	CONTENT += "\nMETA_CLASS = \"" + MD['class'] + "\"\n"
	CONTENT += "META_CATEGORY = \"" + MD['category'] + "\"\n"
	CONTENT += "META_COMPONENT = \"" + MD['component'] + "\"\n"
	CONTENT += "PATTERN_ID = os.path.basename(__file__)\n"
	CONTENT += "PRIMARY_LINK = \"META_LINK_TID\"\n"
	CONTENT += "OVERALL = Core.TEMP\n"
	CONTENT += "OVERALL_INFO = \"NOT SET\"\n"
	CONTENT += "OTHER_LINKS = \"" + MD['links'] + "\"\n"
	CONTENT += "Core.init(META_CLASS, META_CATEGORY, META_COMPONENT, PATTERN_ID, PRIMARY_LINK, OVERALL, OVERALL_INFO, OTHER_LINKS)\n\n"

def patternConditions():
	global MD
	global CONTENT

	if( VERBOSE ):
		print(DISPLAY.format('Conditions', MD['conditions']))

	if( int(MD['conditions']) > 0 ):
		LIMIT = int(MD['conditions']) + 1
		CONTENT += "##############################################################################\n"
		CONTENT += "# Local Function Definitions\n"
		CONTENT += "##############################################################################\n\n"

		for CONDITION in range(1, LIMIT):
			CONTENT += "def condition" + str(CONDITION) + "():\n"
			CONTENT += "\tfileOpen = \"filename.txt\"\n"
			CONTENT += "\tsection = \"CommandToIdentifyFileSection\"\n"
			CONTENT += "\tcontent = []\n"
			CONTENT += "\tCONFIRMED = re.compile(\"\", re.IGNORECASE)\n"
			CONTENT += "\tif Core.isFileActive(fileOpen):\n"
			CONTENT += "\t\tif Core.getRegExSection(fileOpen, section, content):\n"
			CONTENT += "\t\t\tfor line in content:\n"
			CONTENT += "\t\t\t\tif CONFIRMED.search(line):\n"
			CONTENT += "\t\t\t\t\treturn True\n"
			CONTENT += "\treturn False\n\n"

def getConditions(START_LEVEL):
	global MD
	global CONTENT
	INDENT = ''

	for I in range(int(START_LEVEL)):
		INDENT += '\t'

	if( int(MD['conditions']) == 1 ):
		CONTENT += str(INDENT) + "if( condition1() ):\n"
		CONTENT += str(INDENT) + "\tCore.updateStatus(Core.CRIT, \"Condition1 Met\")\n"
		CONTENT += str(INDENT) + "else:\n"
		CONTENT += str(INDENT) + "\tCore.updateStatus(Core.WARN, \"Condition1 not found\")\n"
	elif( int(MD['conditions']) == 2 ):
		CONTENT += str(INDENT) + "if( condition1() ):\n"
		CONTENT += str(INDENT) + "\tif( condition2() ):\n"
		CONTENT += str(INDENT) + "\t\tCore.updateStatus(Core.CRIT, \"Condition2 Met\")\n"
		CONTENT += str(INDENT) + "\telse:\n"
		CONTENT += str(INDENT) + "\t\tCore.updateStatus(Core.WARN, \"Condition2 not found\")\n"
		CONTENT += str(INDENT) + "else:\n"
		CONTENT += str(INDENT) + "\tCore.updateStatus(Core.ERROR, \"Condition1 not found\")\n"
	elif( int(MD['conditions']) == 3 ):
		CONTENT += str(INDENT) + "if( condition1() ):\n"
		CONTENT += str(INDENT) + "\tif( condition2() ):\n"
		CONTENT += str(INDENT) + "\t\tif( condition3() ):\n"
		CONTENT += str(INDENT) + "\t\t\tCore.updateStatus(Core.CRIT, \"Condition3 Met\")\n"
		CONTENT += str(INDENT) + "\t\telse:\n"
		CONTENT += str(INDENT) + "\t\t\tCore.updateStatus(Core.WARN, \"Condition3 not found\")\n"
		CONTENT += str(INDENT) + "\telse:\n"
		CONTENT += str(INDENT) + "\t\tCore.updateStatus(Core.ERROR, \"Condition2 not found\")\n"
		CONTENT += str(INDENT) + "else:\n"
		CONTENT += str(INDENT) + "\tCore.updateStatus(Core.ERROR, \"Condition1 not found\")\n"
	else:
		CONTENT += str(INDENT) + "Core.updateStatus(Core.WARN, \"No conditions required\")\n"

def patternMain():
	global MD
	global CONTENT

	CONTENT += "##############################################################################\n"
	CONTENT += "# Main Program Execution\n"
	CONTENT += "##############################################################################\n\n"

	if( int(MD['package']) > 0 ):
		CONTENT += "PACKAGE = \"nameofpackage\"\n"
	if( MD['service'] ):
		CONTENT += "SERVICE_NAME = 'nameof.service'\n"
		CONTENT += "SERVICE_INFO = SUSE.getServiceDInfo(SERVICE_NAME)\n"

	if( int(MD['package']) == 1 ):
		if( VERBOSE ):
			print(DISPLAY.format('Package', "Affects Issue"))
		if( MD['service'] ):
			if( VERBOSE ):
				print(DISPLAY.format('Service', "Check"))
			# Checks if the affected package is installed and validates the systemd service
			CONTENT += "\nif( SUSE.packageInstalled(PACKAGE) ):\n"
			CONTENT += "\tif( SERVICE_INFO['UnitFileState'] == 'enabled' ):\n"
			CONTENT += "\t\tif( SERVICE_INFO['SubState'] == 'failed' ):\n"
			getConditions(3)
			CONTENT += "\t\telse:\n"
			CONTENT += "\t\t\tCore.updateStatus(Core.ERROR, \"Service did not fail: \" + str(SERVICE_NAME))\n"
			CONTENT += "\telse:\n"
			CONTENT += "\t\tCore.updateStatus(Core.ERROR, \"Service is disabled: \" + str(SERVICE_NAME))\n"
			CONTENT += "else:\n"
			CONTENT += "\tCore.updateStatus(Core.ERROR, \"ERROR: RPM package \" + PACKAGE + \" not installed\")\n"
		else:
			if( VERBOSE ):
				print(DISPLAY.format('Service', "Ignored"))
			# Checks if the affected package is installed and does not check any systemd services
			CONTENT += "\nif( SUSE.packageInstalled(PACKAGE) ):\n"
			getConditions(1)
			CONTENT += "else:\n"
			CONTENT += "\tCore.updateStatus(Core.ERROR, \"ERROR: RPM package \" + PACKAGE + \" not installed\")\n"
	elif( int(MD['package']) == 2 ):
		if( VERBOSE ):
			print(DISPLAY.format('Package', "Fixes Issue"))
		CONTENT += "\nif( SUSE.packageInstalled(PACKAGE) ):\n"
		CONTENT += "\tCore.updateStatus(Core.IGNORE, \"The \" + PACKAGE + \" package is installed\")\n"
		CONTENT += "else:\n"
		if( MD['service'] ):
			if( VERBOSE ):
				print(DISPLAY.format('Service', "Check"))
			# Checks for systemd service if the package is not installed
			CONTENT += "\tif( SERVICE_INFO['UnitFileState'] == 'enabled' ):\n"
			CONTENT += "\t\tif( SERVICE_INFO['SubState'] == 'failed' ):\n"
			getConditions(3)
			CONTENT += "\t\telse:\n"
			CONTENT += "\t\t\tCore.updateStatus(Core.ERROR, \"Service did not fail: \" + str(SERVICE_NAME))\n"
			CONTENT += "\telse:\n"
			CONTENT += "\t\tCore.updateStatus(Core.ERROR, \"Service is disabled: \" + str(SERVICE_NAME))\n"
		else:
			if( VERBOSE ):
				print(DISPLAY.format('Service', "Ignored"))
			# Checks if the package is not installed
			getConditions(1)
	else:
		if( VERBOSE ):
			print(DISPLAY.format('Package', "Ignored"))
		if( MD['service'] ):
			if( VERBOSE ):
				print(DISPLAY.format('Service', "Check"))
			# Only check if a systemd service has failed
			CONTENT += "if( SERVICE_INFO['UnitFileState'] == 'enabled' ):\n"
			CONTENT += "\tif( SERVICE_INFO['SubState'] == 'failed' ):\n"
			getConditions(2)
			CONTENT += "\telse:\n"
			CONTENT += "\t\tCore.updateStatus(Core.ERROR, \"Service did not fail: \" + str(SERVICE_NAME))\n"
			CONTENT += "else:\n"
			CONTENT += "\tCore.updateStatus(Core.ERROR, \"Service is disabled: \" + str(SERVICE_NAME))\n"
		else:
			if( VERBOSE ):
				print(DISPLAY.format('Service', "Ignored"))
			# Check for at least one condition
			getConditions(0)

	CONTENT += "\nCore.printPatternResults()\n\n"

def fetchTitle():
	global MD

	if( VERBOSE ):
		print(DISPLAY.format('Reading URL ', str(MD['tidurl'])))

	req = Request(MD['tidurl'])
	try:
		response = urlopen(req)
	except HTTPError as e:
		MD['title'] = 'Enter title manually'
	except URLError as e:
		MD['title'] = 'Enter title manually'
	else:
		html = response.read()	
		MD['title'] = str(html).split('<title>')[1].split('</title>')[0].replace(' | Support | SUSE', '')

	if( VERBOSE ):
		print(DISPLAY.format('Title', str(MD['title'])))

def savePattern():
	global MD
	global CONTENT

	# Write the content to disk
	try:
		PATFILE = MD['patfile']
		FILE_OPEN = open(PATFILE, "w")
		FILE_OPEN.write(CONTENT)
		FILE_OPEN.close()
#		os.chmod(PATFILE, 0755)
		os.chmod(PATFILE, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
	except OSError:
		print(" ERROR: Cannot create " + str(PATFILE) + ": " + str(error))

def usage():
	print("Usage:")
	print("base.py <class,category,component,name,tid#,bug#,conditions,package,service>")
	print()
	print("  class:      SLE,HAE,SUMA,Security,Custom")
	print("  category:   Category name")
	print("  component:  Component name")
	print("  name:       Pattern name")
	print("  tid#:       TID number only")
	print("  bug#:       Bug number only, 0=no bug")
	print("  conditions: Number of conditions to check, 0-3")
	print("  package:    Check if package is installed: 0 = No Package requirement, 1 = Affects issue, 2 = Fixes issue")
	print("  service:    Check if SystemD service is enabled and failed: 0 = Exclude service check, 1 = Include it")
	print()

def showSummary():
	global MD
	print("Pattern: ./" + MD['patfile'])

###########################################################################
# MAIN
###########################################################################
if( len(sys.argv[1:]) > 0 ):
	try:
		options, remainder = getopt.getopt(sys.argv[1:], "hqs", ["help", "quiet", "summary"])
#		print(options)
#		print(remainder)
	except getopt.GetoptError as err:
		# print help information and exit:
		title()
		usage()
		print("ERROR: " + str(err)) # will print something like "option -b not recognized"
		print()
		sys.exit(2)
else:
	title()
	usage()
	sys.exit(0)

for opt, arg in options:
#	print(opt)
#	print(arg)
	if opt in ("-h", "--help"):
		title()
		usage()
		sys.exit(0)
	elif opt in ("-q", "--quiet"):
		QUIET = True
		VERBOSE = False
	elif opt in ("-s", "--summary"):
		QUIET = False
		VERBOSE = False

if( remainder ):
	OPTIONS = remainder[0]
else:
	title()
	usage()
	sys.exit(0)

if VERBOSE:
    title()

ERRORS = False

OPTIONS_LIST = OPTIONS.split(',')
if( len(OPTIONS_LIST) < OPTIONS_REQ ):
	print("\nERROR: Invalid option list - missing value(s)\n")
	ERRORS = True
elif( len(OPTIONS_LIST) > OPTIONS_REQ ):
	print("\nERROR: Invalid option list - too many value(s)\n")
	ERRORS = True

createMetadata(OPTIONS)

if( int(MD['conditions']) > 3 ):
	print("ERROR: Invalid number of conditions, enter 0-3")
	ERRORS = True

if( int(MD['package']) > 2 ):
	print("ERROR: Invalid package selection, enter 0-2")
	ERRORS = True

if( ERRORS ):
	print()
	usage()
	sys.exit(1)

if( int(MD['package']) == 0 and int(MD['conditions']) == 0 and not MD['service']):
	if VERBOSE:
		print(DISPLAY.format('Override', 'Conditions'))
	MD['conditions'] = 1

fetchTitle()

if( VERBOSE ):
	print(DISPLAY.format('Pattern ', "./" +str(MD['patfile'])))

patternHeader(OPTIONS)
patternConditions()
patternMain()
savePattern()

if( not VERBOSE ):
	if( not QUIET ):
		showSummary()
else:
	print()

sys.exit(RCODE)

