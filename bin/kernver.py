#!/usr/bin/python3
SVER = '1.0.0'
##############################################################################
# kernver.py - Kernel Package Version Pattern Template
# Copyright (C) 2022 SUSE LLC
#
# Description:  Creates a pattern template for TIDs where a specific package
#               and version contain a break and a fix.
# Modified:     2022 Mar 30
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
	'kernvbroke': '',
	'kernvfixed': '',
	'confirmed': 1,
	'msgcrit': 'Critical Message',
	'msgwarn': 'Warning Message'
}
CONTENT = ''
DISPLAY = "{0:15} = {1}"
VERBOSE = True
RCODE = 0
OPTIONS_REQ = 9

def title():
	print("\n##################################################")
	print(("# Kernel Package Version Pattern Template, v" + str(SVER)))
	print("##################################################")

def createMetadata(IDENTITY_CODE):
	global MD
#	print(IDENTITY_CODE)
	(MD['class'], MD['category'], MD['component'], MD['name'], MD['tid'], MD['bug'], MD['kernvfixed'], MD['kernvbroke'], MD['confirmed'] ) = IDENTITY_CODE.split(',')
	MD['tidurl'] = "https://www.suse.com/support/kb/doc/?id=" + str(MD['tid'])
	if( int(MD['bug']) > 0 ):
		MD['bugurl'] = "https://bugzilla.suse.com/show_bug.cgi?id=" + str(MD['bug'])
		MD['links'] = "META_LINK_TID=" + MD['tidurl'] + "|META_LINK_BUG=" + MD['bugurl']
	else:
		MD['bug'] = ''
		MD['links'] = "META_LINK_TID=" + MD['tidurl']
	MD['patfile'] = MD['name'] + "-" + MD['tid'] + ".py"
	if( int(MD['confirmed']) > 0 ):
		MD['confirmed'] = True
	else:
		MD['confirmed'] = False
#	print(MD)

def patternHeader(OPT):
	global MD
	global CONTENT

	TODAY = datetime.date.today()
	# Build pattern file content
	CONTENT = "#!/usr/bin/python3\n#\n"
	CONTENT += "# Title:       Pattern for TID" + MD['tid'] + "\n"
	CONTENT += "# Description: " + MD['title'] + "\n"
	CONTENT += "# Source:      Kernel Package Version Pattern Template v" + str(SVER) + "\n"
	CONTENT += "# Options:     " + str(OPT) + "\n"
	CONTENT += "# Modified:    " + str(TODAY.strftime("%Y %b %d")) + "\n"
	CONTENT += "#\n##############################################################################\n"
	CONTENT += "# Copyright (C) " + str(TODAY.year) + ", SUSE LLC\n"
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
	if( MD['confirmed'] ):
		CONTENT += "import re\n"
	CONTENT += "import os\n"
	CONTENT += "import Core\n"
	CONTENT += "import SUSE\n\n"
	CONTENT += "META_CLASS = \"" + MD['class'] + "\"\n"
	CONTENT += "META_CATEGORY = \"" + MD['category'] + "\"\n"
	CONTENT += "META_COMPONENT = \"" + MD['component'] + "\"\n"
	CONTENT += "PATTERN_ID = os.path.basename(__file__)\n"
	CONTENT += "PRIMARY_LINK = \"META_LINK_TID\"\n"
	CONTENT += "OVERALL = Core.TEMP\n"
	CONTENT += "OVERALL_INFO = \"NOT SET\"\n"
	CONTENT += "OTHER_LINKS = \"" + MD['links'] + "\"\n"

	CONTENT += "\nCore.init(META_CLASS, META_CATEGORY, META_COMPONENT, PATTERN_ID, PRIMARY_LINK, OVERALL, OVERALL_INFO, OTHER_LINKS)\n\n"

def patternConfirmed():
	global MD
	global CONTENT

	if( VERBOSE ):
		print((DISPLAY.format('Confirmation', "True")))

	CONTENT += "##############################################################################\n"
	CONTENT += "# Local Function Definitions\n"
	CONTENT += "##############################################################################\n\n"
	CONTENT += "def conditionConfirmed():\n"
	CONTENT += "\tfileOpen = \"filename.txt\"\n"
	CONTENT += "\tsection = \"CommandToIdentifyFileSection\"\n"
	CONTENT += "\tcontent = []\n"
	CONTENT += "\tCONFIRMED = re.compile(\"\", re.IGNORECASE)\n"
	CONTENT += "\tif Core.getRegExSection(fileOpen, section, content):\n"
	CONTENT += "\t\tfor line in content:\n"
	CONTENT += "\t\t\tif CONFIRMED.search(line):\n"
	CONTENT += "\t\t\t\treturn True\n"
	CONTENT += "\treturn False\n\n"

	CONTENT += "##############################################################################\n"
	CONTENT += "# Main Program Execution\n"
	CONTENT += "##############################################################################\n\n"

	CONTENT += "KERNEL_VERSION_FIXED = '" + MD['kernvfixed'] + "'\n"

	if( str(MD['kernvbroke']) == "0" ):
		if( VERBOSE ):
			print((DISPLAY.format('RPM Depth', "Fixed Only")))
		CONTENT += "\nINSTALLED_VERSION = SUSE.compareKernel(KERNEL_VERSION_FIXED)\n"
		CONTENT += "if( INSTALLED_VERSION >= 0 ):\n"
		CONTENT += "\tCore.updateStatus(Core.IGNORE, \"Bug fixes applied in kernel version \" + KERNEL_VERSION_FIXED + \" or higher\")\n"
		CONTENT += "else:\n"
		CONTENT += "\tif( conditionConfirmed() ):\n"
		CONTENT += "\t\tCore.updateStatus(Core.CRIT, \"" + MD['msgcrit'] + "\")\n"
		CONTENT += "\telse:\n"
		CONTENT += "\t\tCore.updateStatus(Core.WARN, \"" + MD['msgwarn'] + "\")\n"
	else:
		if( VERBOSE ):
			print((DISPLAY.format('RPM Depth', "Broken and Fixed")))
		CONTENT += "KERNEL_VERSION_BROKE = '" + MD['kernvbroke'] + "'\n"
		CONTENT += "\nINSTALLED_VERSION = SUSE.compareKernel(KERNEL_VERSION_FIXED)\n"
		CONTENT += "if( INSTALLED_VERSION >= 0 ):\n"
		CONTENT += "\tCore.updateStatus(Core.IGNORE, \"Bug fixes applied in kernel version \" + KERNEL_VERSION_FIXED + \" or higher\")\n"
		CONTENT += "else:\n"
		CONTENT += "\tINSTALLED_VERSION = SUSE.compareKernel(KERNEL_VERSION_BROKE)\n"
		CONTENT += "\tif( INSTALLED_VERSION == 0 ):\n"
		CONTENT += "\t\tif( conditionConfirmed() ):\n"
		CONTENT += "\t\t\tCore.updateStatus(Core.CRIT, \"" + MD['msgcrit'] + "\")\n"
		CONTENT += "\t\telse:\n"
		CONTENT += "\t\t\tCore.updateStatus(Core.WARN, \"" + MD['msgwarn'] + "\")\n"
		CONTENT += "\telse:\n"
		CONTENT += "\t\tCore.updateStatus(Core.IGNORE, \"Previously unaffected version of the kernel installed\")\n"

	CONTENT += "\nCore.printPatternResults()\n\n"

def patternBasic():
	global MD
	global CONTENT

	if( VERBOSE ):
		print((DISPLAY.format('Confirmation', "False")))

	CONTENT += "##############################################################################\n"
	CONTENT += "# Main Program Execution\n"
	CONTENT += "##############################################################################\n\n"

	CONTENT += "KERNEL_VERSION_FIXED = '" + MD['kernvfixed'] + "'\n"
	if( str(MD['kernvbroke']) == "0" ):
		if( VERBOSE ):
			print((DISPLAY.format('RPM Depth', "Fixed Only")))
		CONTENT += "\nINSTALLED_VERSION = SUSE.compareKernel(KERNEL_VERSION_FIXED)\n"
		CONTENT += "if( INSTALLED_VERSION >= 0 ):\n"
		CONTENT += "\tCore.updateStatus(Core.IGNORE, \"Bug fixes applied in kernel version \" + KERNEL_VERSION_FIXED + \" or higher\")\n"
		CONTENT += "else:\n"
		CONTENT += "\tCore.updateStatus(Core.WARN, \"Warning Message\")\n"
	else:
		if( VERBOSE ):
			print((DISPLAY.format('RPM Depth', "Broken and Fixed")))
		CONTENT += "KERNEL_VERSION_BROKE = '" + MD['kernvbroke'] + "'\n"
		CONTENT += "\nINSTALLED_VERSION = SUSE.compareKernel(KERNEL_VERSION_FIXED)\n"
		CONTENT += "if( INSTALLED_VERSION >= 0 ):\n"
		CONTENT += "\tCore.updateStatus(Core.IGNORE, \"Bug fixes applied in kernel version \" + KERNEL_VERSION_FIXED + \" or higher\")\n"
		CONTENT += "else:\n"
		CONTENT += "\tINSTALLED_VERSION = SUSE.compareKernel(KERNEL_VERSION_BROKE)\n"
		CONTENT += "\tif( INSTALLED_VERSION == 0 ):\n"
		CONTENT += "\t\tCore.updateStatus(Core.WARN, \"Warning Message\")\n"
		CONTENT += "\telse:\n"
		CONTENT += "\t\tCore.updateStatus(Core.IGNORE, \"Previously unaffected version of the kernel installed\")\n"

	CONTENT += "\nCore.printPatternResults()\n\n"

def fetchTitle():
	global MD

	if( VERBOSE ):
		print((DISPLAY.format('Reading URL ', str(MD['tidurl']))))

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
		print((DISPLAY.format('Title', str(MD['title']))))

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
		print((" ERROR: Cannot create " + str(PATFILE) + ": " + str(error)))

def usage():
	print("Usage:")
	print("kernver.py <class,category,component,name,tid#,bug#,fixed,broke,confirm>")
	print()
	print("  class:      SLE,HAE,SUMA,Security,Custom")
	print("  category:   Category name")
	print("  component:  Component name")
	print("  name:       Pattern name")
	print("  tid#:       TID number only")
	print("  bug#:       Bug number only")
	print("  fixed:      Kernel version that fixes the issue")
	print("  broke:      Kernel version that is broke. 0 = Any version less than the fixed version")
	print("  confirm:    0 = no confirmation condition available, 1 = add confirmation condition code")
	print()

def showSummary():
	global MD
	print(("Pattern: ./" + MD['patfile']))

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
		print(("ERROR: " + str(err))) # will print something like "option -b not recognized"
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
OPTIONS_LIST = OPTIONS.split(',')
if( len(OPTIONS_LIST) < OPTIONS_REQ ):
	print("\nERROR: Invalid option list - missing value(s)\n")
	usage()
	sys.exit(1)
if( len(OPTIONS_LIST) > OPTIONS_REQ ):
	print("\nERROR: Invalid option list - too many value(s)\n")
	usage()
	sys.exit(1)

createMetadata(OPTIONS)
fetchTitle()

if( VERBOSE ):
	print((DISPLAY.format('Pattern ', "./" +str(MD['patfile']))))

patternHeader(OPTIONS)
if( MD['confirmed'] ):
	patternConfirmed()
else:
	patternBasic()

savePattern()

if( not VERBOSE ):
	if( not QUIET ):
		showSummary()
else:
	print()

sys.exit(RCODE)

