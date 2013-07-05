#!/usr/bin/env python2
#-*-encoding:utf-8-*-
import sys
from lib.do_HTTP_request import do_HTTP_request
from re import search, findall
from random import randint
from modules.USER_AGENTS import *

def searchHash (hashvalue):
	'''Google the hash value looking for any result which could give some clue...
	
	@param hashvalue The hash is been looking for.'''
	
	start = 0
	finished = False
	results = []
	
	sys.stdout.write("\nThe hash wasn't found in any database. Maybe Google has any idea...\nLooking for results...")
	sys.stdout.flush()
	
	while not finished:
		
		sys.stdout.write('.')
		sys.stdout.flush()
	
		# Build the URL
		url = "http://www.google.com.hk/search?hl=en&q=%s&filter=0" % (hashvalue)
		if start:
			url += "&start=%d" % (start)
			
		# Build the Headers with a random User-Agent
		headers = { "User-Agent" : USER_AGENTS[randint(0, len(USER_AGENTS))-1] }
		
		# Send the request
		response = do_HTTP_request ( url, httpheaders=headers )
		
		# Extract the results ...
		html = None
		if response:
			html = response.read()
		else:
			continue
			
		resultlist = findall (r'<a href="[^"]*?" class=l', html)
		
		# ... saving only new ones
		new = False
		for r in resultlist:
			url_r = r.split('"')[1]
			
			if not url_r in results:
				results.append (url_r)
				new = True
		
		start += len(resultlist)
		
		# If there is no a new result, finish
		if not new:
			finished = True
		
	
	# Show the results
	if results:
		print "\n\nGoogle has some results. Maybe you would like to check them manually:\n"
		
		results.sort()
		for r in results:
			print "  *> %s" % (r)
		print
	
	else:
		print "\n\nGoogle doesn't have any result. Sorry!\n"