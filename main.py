#! /usr/bin/env python
#coding=utf-8

########################################################################################################
### LICENSE
########################################################################################################
#
#   Thanks for JulGor's findmyhash.py - v 1.1.2
#   This code is an upgrade for findmyhash.py
#   Improved by haxsscker
#
print '''
    #######################################################
    #                                                     #
    #                  f4ckhash  v3.2                     #
    #             BY haxsscker#c0deplay.com               #
    #                  team.f4ck.net                      #
    #                                                     #
    #######################################################
'''
from lib.crackHash import crackHash
from lib.searchHash import searchHash
try:
	import sys, threading, Queue, os, time
	import urllib2
	import getopt
	from random import seed
	from cookielib import LWPCookieJar
except:
	print """
Execution error:

  You required some basic Python libraries. 
  
  This application use: sys, hashlib, urllib, urllib2, os, re, random, getopt, base64 and cookielib.

  Please, check if you have all of them installed in your system.

"""
	sys.exit(1)


########################################################################################################
### CONSTANTS
########################################################################################################

MD4	= "md4"
MD5 	= "md5"
SHA1 	= "sha1"
SHA224	= "sha224"
SHA256 	= "sha256"
SHA384	= "sha384"
SHA512 	= "sha512"
RIPEMD	= "rmd160"
LM 	= "lm"
NTLM	= "ntlm"
MYSQL	= "mysql"
CISCO7	= "cisco7"
JUNIPER = "juniper"
GOST	= "gost"
WHIRLPOOL = "whirlpool"
LDAP_MD5 = "ldap_md5"
LDAP_SHA1 = "ldap_sha1"



	


########################################################################################################
### GENERAL METHODS
########################################################################################################

def configureCookieProcessor (cookiefile='/tmp/searchmyhash.cookie'):
	'''Set a Cookie Handler to accept cookies from the different Web sites.
	
	@param cookiefile Path of the cookie store.'''
	
	cookieHandler = LWPCookieJar()
	if cookieHandler is not None:
		if os.path.isfile (cookiefile):
			cookieHandler.load (cookiefile)
			
		opener = urllib2.build_opener ( urllib2.HTTPCookieProcessor(cookieHandler) )
		urllib2.install_opener (opener)






def printSyntax ():
	"""Print application syntax."""
	
	print """
Usage: 
------

  python %s <algorithm> OPTIONS


Accepted algorithms are:
------------------------

  MD4	   - RFC 1320
  MD5	   - RFC 1321
  SHA1	  - RFC 3174 (FIPS 180-3)
  SHA224	- RFC 3874 (FIPS 180-3)
  SHA256	- FIPS 180-3
  SHA384	- FIPS 180-3
  SHA512	- FIPS 180-3
  RMD160	- RFC 2857
  GOST	  - RFC 5831
  WHIRLPOOL - ISO/IEC 10118-3:2004
  LM		- Microsoft Windows hash
  NTLM	  - Microsoft Windows hash
  MYSQL	 - MySQL 3, 4, 5 hash
  CISCO7	- Cisco IOS type 7 encrypted passwords
  JUNIPER   - Juniper Networks $9$ encrypted passwords
  LDAP_MD5  - MD5 Base64 encoded
  LDAP_SHA1 - SHA1 Base64 encoded
 
  NOTE: for LM / NTLM it is recommended to introduce both values with this format:
		 python %s LM   -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
		 python %s NTLM -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7


Valid OPTIONS are:
------------------

  -h <hash>		one hash.

  -f <file>		a file
				   
  -g			search in Google


Examples:
---------

  -> one hash.
	 python %s MD5 -h 098f6bcd4621d373cade4e832627b4f6
	 
  -> one hash.
	 python %s JUNIPER -h "\$9\$LbHX-wg4Z"
  
  -> one hash.
	 python %s LDAP_SHA1 -h "{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA=" -g
   
  -> a file.
	 python %s MYSQL -f hashs.txt
	 
	 
""" % ( (sys.argv[0],) * 7 )


########################################################################################################
### MAIN CODE
########################################################################################################

def main():
	"""Main method."""


	###################################################
	# Syntax check
	if len (sys.argv) < 4:
		printSyntax()
		sys.exit(1)
	
	else:
		try:
			opts, args = getopt.getopt (sys.argv[2:], "gh:f:")
		except:
			printSyntax()
			sys.exit(1)
	
	
	###################################################
	# Load input parameters
	algorithm = sys.argv[1].lower()
	hashvalue = None
	hashfile  = None
	googlesearch = False
	global savepath
	savepath = None
	cracked = None
	
	for opt, arg in opts:
		if opt == '-h':
			hashvalue = arg
		elif opt == '-f':
			hashfile = arg
		else:
			googlesearch = True

	if hashfile:
		savepath = os.path.dirname(hashfile) + "/hashsave.txt"
		
	###################################################
	# Configure the Cookie Handler
	configureCookieProcessor()
	
	# Initialize PRNG seed
	seed()
	
	###################################################
	# Crack the hash/es
	cracked = crackHash (algorithm, hashvalue, hashfile, savepath)
	
	
	###################################################
	# Look for the hash in Google if it was not cracked
	if not cracked and googlesearch and not hashfile:
		try:
			searchHash (hashvalue)
		except:
			print "google error!"
			pass

if __name__ == "__main__":
	main()


