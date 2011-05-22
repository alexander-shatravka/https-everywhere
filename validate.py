#!/usr/bin/env python
# encoding: UTF-8
# ♥ 2011 katmagic
# This is free and unencumbered software released into the public domain. See
# http://unlicense.org/ for more information. ~katmagic

from __future__ import print_function, unicode_literals
from xml.etree import ElementTree
import re

HOST_RE = re.compile(r'^.*?://([^/]*)')
UNESCAPED_DOT_RE = re.compile(r'[^\\]\.[^*]')
DOT_IN_BRACKETS_RE = re.compile(r'\[[^\]]*\.[^\]]*\]')
MULTIPLE_WILDCARDS_RE = re.compile(r'\*.*\*')
NON_PROTOCOL_SLASH_RE = re.compile(r'(^|[^/])/')
def validate_rule(rule_file):
	"""Validate an HTTPS Everywhere rule. We return a tuple containing the ruleset
	name (a str) and a set of targets."""

	try:
		root = ElementTree.parse(rule_file).getroot()
	except ElementTree.ParseError:
		raise AssertionError("invalid xml")
	assert root.tag == 'ruleset', "not a ruleset"
	assert 'name' in root.attrib, "ruleset has no name"

	for rule in root.findall('rule'):
		if 'from' in rule.attrib:
			assert NON_PROTOCOL_SLASH_RE.search(rule.attrib['from']), \
				"no trailing slash in from pattern"

			try:
				host = HOST_RE.match(rule.attrib['from']).groups()[0]
			except IndexError:
				raise AssertionError('invalid host in from pattern')
			dibc = len(DOT_IN_BRACKETS_RE.findall(host))
			udc = len(UNESCAPED_DOT_RE.findall(host))
			assert dibc == udc, "unescaped dot in host portion of from pattern"

		if 'to' in rule.attrib:
			try:
				rule.attrib['to'].encode('ASCII')
			except UnicodeEncodeError:
				raise AssertionError("non-ASCII character in to rule")

			assert rule.attrib['to'].find('\\') == -1, "backslash in to pattern"
			assert not(rule.attrib['to'].startswith('http:')), "redirects to http"

	targets = root.findall('target')
	assert root.findall('target'), "no target target rule"
	for rule in targets:
		if 'host' in rule.attrib:
			assert not(MULTIPLE_WILDCARDS_RE.search(rule.attrib['host'])), \
				"multiple wildcards in target host"

	return (root.attrib['name'], {t.attrib['host'] for t in targets})

if __name__ == '__main__':
	import os, os.path
	import sys

	failure = False
	def err(error):
		print(error, file=sys.stderr)
		failure = True

	names, hosts = set(), set()
	for path, dirnames, files in os.walk(sys.argv[1]):
		for f in (os.path.join(path, f) for f in files):
			if f.endswith('.xml'):
				try:
					name, hosts_ = validate_rule(f)
				except AssertionError as e:
					err("error in file '%s': %s" % (f, e.args[0]))

	if failure:
		sys.exit(1)
	else:
		sys.exit(0)
