#!/usr/bin/python3
SVER = '1.0.1'
##############################################################################
# linkchk.py - SCA Pattern Link Verification Tool
# Copyright (C) 2022 SUSE LLC
#
# Description:  Validates META_LINK solution URLs to ensure they are valid.
#               Supports python and perl patterns with *.py and *.pl extensions.
# Modified:     2022 Oct 22
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
import re
import getopt
import requests
import signal
import subprocess
from datetime import timedelta
from timeit import default_timer as timer

##############################################################################
# Global Options
##############################################################################

recurse_directory = False
given_file = ''
pattern_list = []
c_ = {'current': 0, 'pat_total': 0, 'link_total': 0, 'badconnection': 0, "badurl": 0, "bugid": 0, "ping": 0, "active_pattern": '', "active_link": ''}
progress_bar_width = 57
invalid_links = {}
verbose = False
elapsed = -1
start = 0
end = 0

##############################################################################
# Functions
##############################################################################

def title():
	"Display the program title"
	print("#############################################################################")
	print("# SCA Pattern Link Verification Tool v" + str(SVER))
	print("# for the SCA Tool")
	print("#############################################################################")

def usage():
	"Displays usage information"
	print("Usage: linkchk.py [options] [filepath]")
	print()
	print("Options:")
	print("  -h, --help     Display this help")
	print("  -r, --recurse  Validate patterns recursively found in the directory structure")
	print("  -v, --verbose  Display verbose logging messages")
	print()

def signal_handler(sig, frame):
	print("\n\nAborting...\n")
	show_summary()
	sys.exit(1)

class ProgressBar():
	"Initialize and update progress bar class"
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

def get_pattern_list(this_path):
	this_list = []
	include_file = re.compile(".py$|.pl$")
	for dirpath, subdirs, files in os.walk(this_path, topdown = True):
		for file in files:
			if include_file.search(file):
				this_list.append(os.path.join(dirpath, file))
		if not recurse_directory:
			break
	return this_list

def get_url_list(this_pattern):
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
				find_links = re.compile('OTHER_LINKS = "', re.IGNORECASE)
			elif "#!/usr/bin/perl" in line:
				type_perl = True
				find_links = re.compile('"META_LINK_.*=', re.IGNORECASE)
	f.close()
#	print(these_urls)

	return these_urls

def validate(link_list):
	bad_links = {}
	for link in link_list:
		if verbose:
			print("  {0}".format(link))
		c_['link_total'] += 1
		status = "+ Confirmed"
		c_['active_link'] = link
		try:
			x = requests.get(link, timeout=10)
			x.raise_for_status()
		except requests.exceptions.HTTPError as errh:
			status = "- Invalid URL"
			c_['badurl'] += 1
			bad_links[link] = "Invalid URL"
			continue
		except requests.exceptions.ConnectionError as errc:
			status = "- Invalid Connection"
			c_['badconnection'] += 1
			bad_links[link] = "Invalid Connection"
			continue
		except requests.exceptions.Timeout as errt:
			status = "- Server Timeout"
			c_['ping'] += 1
			bad_links[link] = "Server Timeout"
			continue
		except requests.exceptions.RequestException as err:
			status = "- Invalid URL"
			c_['badurl'] += 1
			bad_links[link] = "Invalid URL"
			continue
		except Exception as error:
			status = "- Unknown Error"
			c_['ping'] += 1
			bad_links[link] = "Unknown Error"
			continue


		if( x.status_code == 200 ):
			data = x.text.split('\n')
			badlink = re.compile('Invalid Bug ID')
			for line in data:
				if badlink.search(line):
					status = "- Invalid BUG"
					c_['bugid'] += 1
					bad_links[link] = "Invalid BUG"
					break
		if verbose:
			print("    {0}".format(status))
	return bad_links

def show_summary():
	display = "{0:25} {1}"
	print("Summary")
	print("----------------------------------")
	print(display.format("Elsapsed Runtime", str(elapsed).split('.')[0]))
	print(display.format("Total Patterns Checked", c_['pat_total']))
	print(display.format("Total Links Evaluated", c_['link_total']))
	print(display.format("Invalid Connection Links", c_['badconnection']))
	print(display.format("Invalid URLs", c_['badurl']))
	print(display.format("Servers Down", c_['ping']))
	print(display.format("Invalid Bug Content", c_['bugid']))
	print(display.format("Active Pattern", c_['active_pattern']))
	print(display.format("Active Link", c_['active_link']))
	print()
	print("Invalid Links")
	print("----------------------------------")
	ldisplay = "  {0:24} {1}"
	if len(invalid_links) > 0:
		for pattern in invalid_links.keys():
			print(pattern)
			for key, value in invalid_links[pattern].items():
				print(ldisplay.format(value, key))
	else:
		print("None")
	print()

##############################################################################
# Main
##############################################################################

def main(argv):
	"main entry point"
	global SVER, pattern_list, recurse_directory, c_, invalid_links, verbose, elapsed, start, end
	start = timer()
	
	try:
		(optlist, args) = getopt.gnu_getopt(argv[1:], "hrv", ["help", "recurse", "verbose"])
	except getopt.GetoptError as exc:
		title()
		print("Error:", exc, file=sys.stderr)
		sys.exit(2)
	for opt in optlist:
		if opt[0] in {"-h", "--help"}:
			title()
			usage()
			sys.exit(0)
		elif opt[0] in {"-r", "--recurse"}:
			recurse_directory = True
		elif opt[0] in {"-v", "--verbose"}:
			verbose = True

	title()
	print("Loading patterns...")
	given_file = ''
	if len(args) > 0:
		# TODO: support multiple files given on the command line to validate
		given_file = args[0]
		if os.path.isdir(given_file):
			path = os.path.abspath(given_file)
			pattern_list = get_pattern_list(path)
			if recurse_directory:
				print("Recursively Processing " + path)
			else:
				print("Processing " + path)
		elif os.path.isfile(given_file):
			given_file = os.path.abspath(given_file)
			print("Processing file " + given_file)
			pattern_list.append(given_file)
		else:
			print("Error: Invalid file or path - " + given_file)
			sys.exit(5)
	else:
		path = os.getcwd()
		if recurse_directory:
			print("Recursively Processing " + path)
		else:
			print("Processing " + path)
		pattern_list = get_pattern_list(path)

	c_['pat_total'] = len(pattern_list)
	if not verbose:
		bar = ProgressBar(" Validating links: ", progress_bar_width, c_['pat_total'])
	for pattern in pattern_list:
		if verbose:
			print("{0}/{1} {2}".format(c_['current'], c_['pat_total'], pattern))
		c_['active_pattern'] = pattern
		bad_urls = []
		url_list = get_url_list(pattern)
		bad_urls = validate(url_list)
		if len(bad_urls) > 0:
			invalid_links[pattern] = bad_urls
		c_['current'] += 1
		if not verbose:
			bar.update(c_['current'])
	if not verbose:
		bar.finish()
	c_['active_pattern'] = "None"
	c_['active_link'] = "None"
	end = timer()
	elapsed = str(timedelta(seconds=end-start))
	show_summary()
		
# Entry point
if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	main(sys.argv)


