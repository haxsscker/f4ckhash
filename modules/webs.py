#! /usr/bin/env python
#coding=utf-8

import urllib2, os
from re import search, findall
from lib.do_HTTP_request import do_HTTP_request
from modules.hashf import *
from modules.USER_AGENTS import *
from base64 import decodestring, encodestring
from random import randint
try:
	from libxml2 import parseDoc
except:
	print """
	libxml2 is not installed. Some plugins aren't going to work correctly.
"""

class XMD5:
	
	name = 		"xmd5"
	url = 		"http://www.xmd5.org/"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):		
		if alg in self.supported_algorithm:
			return True
		else:
			return False

	def crack (self, hashvalue, alg):
		if not self.isSupported (alg):
			return None

		header = { "Referer" : "http://www.xmd5.org/" }	
		# Build the URL
		url = "http://www.xmd5.org/md5/search.asp?hash=%s&xmd5=MD5+%%BD%%E2%%C3%%DC" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url, httpheaders=header )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None

		match = search (r'<font color="#ffffff" size="3">[^<]*>>>Good', html)
		match2 = search (r'/user/pay\.asp', html)
		if match2:
			print "need money! ---> www.xmd5.com"
			return "www.xmd5.com----->"+hashvalue
		elif match:
			return match.group().split('>')[1][2:-14]
		else:
			return None


class SCHWETT:
	
	name = 		"schwett"
	url = 		"http://schwett.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://schwett.com/md5/index.php?md5value=%s&md5c=Hash+Match" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r"<h3><font color='red'>No Match Found</font></h3><br />", html)
		if match:
			return None
		else:
			return "The hash is broken, please contact with La X marca el lugar and send it the hash value to add the correct regexp."



class NETMD5CRACK:

	name = 		"netmd5crack"
	url = 		"http://www.netmd5crack.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://www.netmd5crack.com/cgi-bin/Crack.py?InputHash=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		regexp = r'<tr><td class="border">%s</td><td class="border">[^<]*</td></tr></table>' % (hashvalue)
		match = search (regexp, html)
		
		if match:
			match2 = search ( "Sorry, we don't have that hash in our database", match.group() )
			if match2:
				return None
			else:
				return match.group().split('border')[2].split('<')[0][2:]



class MD5_CRACKER:
	
	name = 		"md5-cracker"
	url = 		"http://www.md5-cracker.tk"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		return None # the web is error
		# Build the URL
		url = "http://www.md5-cracker.tk/xml.php?md5=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		if response:
			try:
				doc = parseDoc ( response.read() )
			except:
				#print "INFO: You need libxml2 to use this plugin."
				return None
		else:
			return None
		
		result = doc.xpathEval("//data")
		if len(result):
			return result[0].content
		else:
			return None


class BENRAMSEY:
	
	name = 		"benramsey"
	url = 		"http://tools.benramsey.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://tools.benramsey.com/md5/md5.php?hash=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
			
		match = search (r'<string><!\[CDATA\[[^\]]*\]\]></string>', html)
		
		if match:
			return match.group().split(']')[0][17:]
		else:
			return None



class GROMWEB: 
	
	name = 		"gromweb"
	url = 		"http://md5.gromweb.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.gromweb.com/query/%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		if response:
			return response.read()
			
		return response
		
		


class HASHCRACKING:
	
	name = 		"hashcracking"
	url = 		"http://md5.hashcracking.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.hashcracking.com/search.php?md5=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'\sis.*', html)
		
		if match:
			return match.group()[4:]
			
		return None



class VICTOROV:
	
	name = 		"hashcracking"
	url = 		"http://victorov.su"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://victorov.su/md5/?md5e=&md5d=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r': <b>[^<]*</b><br><form action="">', html)
		
		if match:
			return match.group().split('b>')[1][:-2]
			
		return None


class THEKAINE: 
	
	name = 		"thekaine"
	url = 		"http://md5.thekaine.de"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.thekaine.de/?hash=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<td colspan="2"><br><br><b>[^<]*</b></td><td></td>', html)
		
		if match:
			
			match2 = search (r'not found', match.group() )
			
			if match2:
				return None
			else:
				return match.group().split('b>')[1][:-2]
			


class TMTO:
	
	name = 		"tmto"
	url = 		"http://www.tmto.org"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://www.tmto.org/api/latest/?hash=%s&auth=true" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'text="[^"]+"', html)
		
		if match:
			return decodestring(match.group().split('"')[1])
		else:
			return None


class MD5_DB:
	
	name = 		"md5-db"
	url = 		"http://md5-db.de"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5-db.de/%s.html" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		if not response:
			return None
			
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<strong>Es wurden 1 m.gliche Begriffe gefunden, die den Hash \w* verwenden:</strong><ul><li>[^<]*</li>', html)
		
		if match:
			return match.group().split('li>')[1][:-2]
		else:
			return None




class MY_ADDR:
	
	name = 		"my-addr"
	url = 		"http://md5.my-addr.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php"
		
		# Build the parameters
		params = { "md5" : hashvalue,
			   "x" : 21,
			   "y" : 8 }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", html)
		
		if match:
			return match.group().split('span')[2][3:-6]
		else:
			return None




class MD5PASS:
	
	name = 		"md5pass"
	url = 		"http://md5pass.info"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = self.url
		
		# Build the parameters
		params = { "hash" : hashvalue,
			   "get_pass" : "Get Pass" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r"Password - <b>[^<]*</b>", html)
		
		if match:
			return match.group().split('b>')[1][:-2]
		else:
			return None



class MD5DECRYPTION:
	
	name = 		"md5decryption"
	url = 		"http://md5decryption.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = self.url
		
		# Build the parameters
		params = { "hash" : hashvalue,
			   "submit" : "Decrypt It!" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r"Decrypted Text: </b>[^<]*</font>", html)
		
		if match:
			return match.group().split('b>')[1][:-7]
		else:
			return None



class MD5CRACK:
	
	name = 		"md5crack"
	url = 		"http://md5crack.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5crack.com/crackmd5.php"
		
		# Build the parameters
		params = { "term" : hashvalue,
			   "crackbtn" : "Crack that hash baby!" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'Found: md5\("[^"]+"\)', html)
		
		if match:
			return match.group().split('"')[1]
		else:
			return None


class MD5ONLINE:
	
	name = 		"md5online"
	url = 		"http://md5online.net"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = self.url
		
		# Build the parameters
		params = { "pass" : hashvalue,
			   "option" : "hash2text",
			   "send" : "Submit" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<center><p>md5 :<b>\w*</b> <br>pass : <b>[^<]*</b></p></table>', html)
		
		if match:
			return match.group().split('b>')[3][:-2]
		else:
			return None




class MD5_DECRYPTER:
	
	name = 		"md5-decrypter"
	url = 		"http://md5-decrypter.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = self.url
		
		# Build the parameters
		params = { "data[Row][cripted]" : hashvalue }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = findall (r'<b class="res">[^<]*</b>', html)
		
		if match:
			return match[1].split('>')[1][:-3]
		else:
			return None



class AUTHSECUMD5:
	
	name = 		"authsecu"
	url = 		"http://www.authsecu.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://www.authsecu.com/decrypter-dechiffrer-cracker-hash-md5/script-hash-md5.php"
		
		# Build the parameters
		params = { "valeur_bouton" : "dechiffrage",
			   "champ1" : "",
			   "champ2" : hashvalue,
			   "dechiffrer.x" : "78",
			   "dechiffrer.y" : "7" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = findall (r'<td><p class="chapitre---texte-du-tableau-de-niveau-1">[^<]*</p></td>', html)
		
		if len(match) > 2:
			return match[1].split('>')[2][:-3]
		else:
			return None



class HASHCRACK:
	
	name = 		"hashcrack"
	url = 		"http://hashcrack.com"
	supported_algorithm = [MD5, SHA1, MYSQL, LM, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://hashcrack.com/indx.php"
		
		hash2 = None
		if alg in [LM, NTLM] and ':' in hashvalue:
			if alg == LM:
				hash2 = hashvalue.split(':')[0]
			else:
				hash2 = hashvalue.split(':')[1]
		else:
			hash2 = hashvalue
		
		# Delete the possible starting '*'
		if alg == MYSQL and hash2[0] == '*':
			hash2 = hash2[1:]
		
		# Build the parameters
		params = { "auth" : "8272hgt",
			   "hash" : hash2,
			   "string" : "",
			   "Submit" : "Submit" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<div align=center>"[^"]*" resolves to</div><br><div align=center> <span class=hervorheb2>[^<]*</span></div></TD>', html)
		
		if match:
			return match.group().split('hervorheb2>')[1][:-18]
		else:
			return None



class OPHCRACK:
	
	name = 		"ophcrack"
	url = 		"http://www.objectif-securite.ch"
	supported_algorithm = [LM, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Check if hashvalue has the character ':'
		if ':' not in hashvalue:
			return None
			
		# Ophcrack doesn't crack NTLM hashes. It needs a valid LM hash and this one is an empty hash.
		if hashvalue.split(':')[0] == "aad3b435b51404eeaad3b435b51404ee":
			return None
		
		# Build the URL and the headers
		url = "http://www.objectif-securite.ch/en/products.php?hash=%s" % (hashvalue.replace(':', '%3A'))
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<table><tr><td>Hash:</td><td>[^<]*</td></tr><tr><td><b>Password:</b></td><td><b>[^<]*</b></td>', html)
		
		if match:
			return match.group().split('b>')[3][:-2]
		else:
			return None
	


class C0LLISION:
	
	name = 		"c0llision"
	url = 		"http://www.c0llision.net"
	supported_algorithm = [MD5, LM, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Check if hashvalue has the character ':'
		if alg in [LM, NTLM] and ':' not in hashvalue:
			return None
			
		# Look for "hash[_csrf_token]" parameter
		response = do_HTTP_request ( "http://www.c0llision.net/webcrack.php" )
		html = None
		if response:
			html = response.read()
		else:
			return None
		match = search (r'<input type="hidden" name="hash._csrf_token." value="[^"]*" id="hash__csrf_token" />', html)
		token = None
		if match:
			token = match.group().split('"')[5]
		
		# Build the URL
		url = "http://www.c0llision.net/webcrack/request"
		
		# Build the parameters
		params = { "hash[_input_]" : hashvalue,
			   "hash[_csrf_token]" : token }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = None
		if alg in [LM, NTLM]:
			html = html.replace('\n', '')
			result = ""
			
			match = search (r'<table class="pre">.*?</table>', html)
			if match:
				try:
					doc = parseDoc ( match.group() )
				except:
					#print "INFO: You need libxml2 to use this plugin."
					return None
				lines = doc.xpathEval("//tr")
				for l in lines:
					doc = parseDoc ( str(l) )
					cols = doc.xpathEval("//td")
					
					if len(cols) < 4:
						return None
					
					if cols[2].content:
						result = " > %s (%s) = %s\n" % ( cols[1].content, cols[2].content, cols[3].content )
				
				#return ( result and "\n" + result or None )
				return ( result and result.split()[-1] or None )
			
		else:
			match = search (r'<td class="plaintext">[^<]*</td>', html)
		
			if match:
				return match.group().split('>')[1][:-4]
		
		return None



class REDNOIZE:
	
	name = 		"rednoize"
	url = 		"http://md5.rednoize.com"
	supported_algorithm = [MD5, SHA1]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = ""
		if alg == MD5:
			url = "http://md5.rednoize.com/?p&s=md5&q=%s&_=" % (hashvalue)
		else:
			url = "http://md5.rednoize.com/?p&s=sha1&q=%s&_=" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		return html
			
			


class CMD5:
	
	name = 		"cmd5"
	url = 		"http://www.cmd5.com"
	supported_algorithm = [MD5, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Look for hidden parameters
		response = do_HTTP_request ( "http://www.cmd5.com/" )
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="[^"]*" />', html)
		viewstate = None
		if match:
			viewstate = match.group().split('"')[7]
		
		match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField1" id="ctl00_ContentPlaceHolder1_HiddenField1" value="[^"]*" />', html)
		ContentPlaceHolder1 = ""
		if match:
			ContentPlaceHolder1 = match.group().split('"')[7]
		
		match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField2" id="ctl00_ContentPlaceHolder1_HiddenField2" value="[^"]*" />', html)
		ContentPlaceHolder2 = ""
		if match:
			ContentPlaceHolder2 = match.group().split('"')[7]
		
		# Build the URL
		url = "http://www.cmd5.com/"
		
		hash2 = ""
		if alg == MD5:
			hash2 = hashvalue
		else:
			if ':' in hashvalue:
				hash2 = hashvalue.split(':')[1]
		
		# Build the parameters
		params = { "__EVENTTARGET" : "",
			   "__EVENTARGUMENT" : "",
			   "__VIEWSTATE" : viewstate,
			   "ctl00$ContentPlaceHolder1$TextBoxInput" : hash2,
			   "ctl00$ContentPlaceHolder1$InputHashType" : alg,
			   "ctl00$ContentPlaceHolder1$Button1" : "decrypt",
			   "ctl00$ContentPlaceHolder1$HiddenField1" : ContentPlaceHolder1,
			   "ctl00$ContentPlaceHolder1$HiddenField2" : ContentPlaceHolder2 }
			  
		header = { "Referer" : "http://www.cmd5.com/" }
		
		# Make the request
		response = do_HTTP_request ( url, params, header )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<span id="ctl00_ContentPlaceHolder1_LabelAnswer">[^<]*</span>', html)
		match2 = search (r'buy\.aspx', html)
		if match2:
			print "need money! ---> www.cmd5.com"
			return "www.cmd5.com----->"+hashvalue
		elif match:
			return match.group().split('>')[1][:-6]
		else:
			return None

class CMD5ORG:
	
	name = 		"cmd5org"
	url = 		"http://www.cmd5.org"
	supported_algorithm = [MD5, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Look for hidden parameters
		response = do_HTTP_request ( "http://www.cmd5.org/" )
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="[^"]*" />', html)
		viewstate = None
		if match:
			viewstate = match.group().split('"')[7]
		
		match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField1" id="ctl00_ContentPlaceHolder1_HiddenField1" value="[^"]*" />', html)
		ContentPlaceHolder1 = ""
		if match:
			ContentPlaceHolder1 = match.group().split('"')[7]
		
		match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField2" id="ctl00_ContentPlaceHolder1_HiddenField2" value="[^"]*" />', html)
		ContentPlaceHolder2 = ""
		if match:
			ContentPlaceHolder2 = match.group().split('"')[7]
		
		# Build the URL
		
		hash2 = ""
		if alg == MD5:
			hash2 = hashvalue
		else:
			if ':' in hashvalue:
				hash2 = hashvalue.split(':')[1]
		
		# Build the parameters
		params = { "__EVENTTARGET" : "",
			   "__EVENTARGUMENT" : "",
			   "__VIEWSTATE" : viewstate,
			   "ctl00$ContentPlaceHolder1$TextBoxInput" : hash2,
			   "ctl00$ContentPlaceHolder1$InputHashType" : alg,
			   "ctl00$ContentPlaceHolder1$Button1" : "decrypt",
			   "ctl00$ContentPlaceHolder1$HiddenField1" : ContentPlaceHolder1,
			   "ctl00$ContentPlaceHolder1$HiddenField2" : ContentPlaceHolder2 }
			  
		header = { "Referer" : "http://www.cmd5.org/" }
		url = "http://www.cmd5.org/"
		# Make the request
		response = do_HTTP_request ( url, params, header )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<span id="ctl00_ContentPlaceHolder1_LabelAnswer">[^<]*</span>', html)
		match2 = search (r'buy\.aspx', html)
		if match2:
			print "need money! ---> www.cmd5.org"
			return "www.xmd5.org----->"+hashvalue
		elif match:
			return match.group().split('>')[1][:-6]
		else:
			return None



class AUTHSECUCISCO7:
	
	name = 		"authsecu"
	url = 		"http://www.authsecu.com"
	supported_algorithm = [CISCO7]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL and the headers
		url = "http://www.authsecu.com/decrypter-dechiffrer-cracker-password-cisco-7/script-password-cisco-7-launcher.php"
		
		# Build the parameters
		params = { "valeur_bouton" : "dechiffrage",
			   "champ1" : hashvalue,
			   "dechiffrer.x" : 43,
			   "dechiffrer.y" : 16 }
			   
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = findall (r'<td><p class="chapitre---texte-du-tableau-de-niveau-1">[^<]*</p></td>', html)
		
		if match:
			return match[1].split('>')[2][:-3]
		else:
			return None




class CACIN:
	
	name = 		"cacin"
	url = 		"http://cacin.net"
	supported_algorithm = [CISCO7]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL and the headers
		url = "http://cacin.net/cgi-bin/decrypt-cisco.pl?cisco_hash=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<tr>Cisco password 7: [^<]*</tr><br><tr><th><br>Decrypted password: .*', html)
		
		if match:
			return match.group().split(':')[2][1:]
		else:
			return None


class IBEAST:
	
	name = 		"ibeast"
	url = 		"http://www.ibeast.com"
	supported_algorithm = [CISCO7]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL and the headers
		url = "http://www.ibeast.com/content/tools/CiscoPassword/decrypt.php?txtPassword=%s&submit1=Enviar+consulta" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<font size="\+2">Your Password is [^<]*<br>', html)
		
		if match:
			return match.group().split('is ')[1][:-4]
		else:
			return None



class PASSWORD_DECRYPT:
	
	name = 		"password-decrypt"
	url = 		"http://password-decrypt.com"
	supported_algorithm = [CISCO7, JUNIPER]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL and the parameters
		url = ""
		params = None
		if alg == CISCO7:
			url = "http://password-decrypt.com/cisco.cgi"
			params = { "submit" : "Submit",
				"cisco_password" : hashvalue,
				"submit" : "Submit" }
		else:
			url = "http://password-decrypt.com/juniper.cgi"
			params = { "submit" : "Submit",
				"juniper_password" : hashvalue,
				"submit" : "Submit" }
		
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'Decrypted Password:&nbsp;<B>[^<]*</B> </p>', html)
		
		if match:
			return match.group().split('B>')[1][:-2]
		else:
			return None




class BIGTRAPEZE:
	
	name = 		"bigtrapeze"
	url = 		"http://www.bigtrapeze.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL and the headers
		url = "http://www.bigtrapeze.com/md5/index.php"
		
		# Build the parameters
		params = { "query" : hashvalue,
			   " Crack " : "Enviar consulta" }
			   
		# Build the Headers with a random User-Agent
		headers = { "User-Agent" : USER_AGENTS[randint(0, len(USER_AGENTS))-1] }

		# Make the request
		response = do_HTTP_request ( url, params, headers )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
			
		match = search (r'Congratulations!<li>The hash <strong>[^<]*</strong> has been deciphered to: <strong>[^<]*</strong></li>', html)
		
		if match:
			return match.group().split('strong>')[3][:-2]
		else:
			return None


class HASHCHECKER:
	
	name = 		"hashchecker"
	url = 		"http://www.hashchecker.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL and the headers
		url = "http://www.hashchecker.com/index.php"
		
		# Build the parameters
		params = { "search_field" : hashvalue,
			   "Submit" : "search" }
			   
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
			
		match = search (r'<td><li>Your md5 hash is :<br><li>[^\s]* is <b>[^<]*</b> used charlist :2</td>', html)
		
		if match:
			return match.group().split('b>')[1][:-2]
		else:
			return None



class MD5HASHCRACKER:
	
	name = 		"md5hashcracker"
	url = 		"http://md5hashcracker.appspot.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5hashcracker.appspot.com/crack"
		
		# Build the parameters
		params = { "query" : hashvalue,
			   "submit" : "Crack" }
		
		# Make the firt request
		response = do_HTTP_request ( url, params )
		
		# Build the second URL
		url = "http://md5hashcracker.appspot.com/status"
		
		# Make the second request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		if response:
			html = response.read()
		else:
			return None
		match = search (r'<td id="cra[^"]*">not cracked</td>', html)
		
		if not match:
			match = search (r'<td id="cra[^"]*">cracked</td>', html)
			regexp = r'<td id="pla_' + match.group().split('"')[1][4:] + '">[^<]*</td>'
			match2 = search (regexp, html)
			if match2:
				return match2.group().split('>')[1][:-4]
			
		else:
			return None



class PASSCRACKING:
	
	name = 		"passcracking"
	url = 		"http://passcracking.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL 
		url = "http://passcracking.com/index.php"
		
		# Build the parameters
		boundary = "-----------------------------" + str(randint(1000000000000000000000000000,9999999999999999999999999999))
		params = [ '--' + boundary, 
			   'Content-Disposition: form-data; name="admin"', 
			   '', 
			   'false', 
			   
			   '--' + boundary, 
			   'Content-Disposition: form-data; name="admin2"', 
			   '', 
			   '77.php', 
			   
			   '--' + boundary, 
			   'Content-Disposition: form-data; name="datafromuser"', 
			   '', 
			   '%s' % (hashvalue) , 
			   
			   '--' + boundary + '--', '' ]
		body = '\r\n'.join(params)

		# Build the headers
		headers = { "Content-Type" : "multipart/form-data; boundary=%s" % (boundary),
					"Content-length" : len(body) }
		
			   
		# Make the request
		request = urllib2.Request ( url )
		request.add_header ( "Content-Type", "multipart/form-data; boundary=%s" % (boundary) )
		request.add_header ( "Content-length", str(len(body)) )
		request.add_data(body)
		try:
			response = urllib2.urlopen(request)
		except e:
			return None
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
			
		match = search (r'<td>md5 Database</td><td>[^<]*</td><td bgcolor=.FF0000>[^<]*</td>', html)
		
		if match:
			return match.group().split('>')[5][:-4]
		else:
			return None


class ASKCHECK:
	
	name = 		"askcheck"
	url = 		"http://askcheck.com"
	supported_algorithm = [MD4, MD5, SHA1, SHA256]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://askcheck.com/reverse?reverse=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
			
		match = search (r'Reverse value of [^\s]* hash <a[^<]*</a> is <a[^>]*>[^<]*</a>', html)
		
		if match:
			return match.group().split('>')[3][:-3]
		else:
			return None



class FOX21:
	
	name = 		"fox21"
	url = 		"http://cracker.fox21.at"
	supported_algorithm = [MD5, LM, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		hash2 = None
		if alg in [LM, NTLM] and ':' in hashvalue:
			if alg == LM:
				hash2 = hashvalue.split(':')[0]
			else:
				hash2 = hashvalue.split(':')[1]
		else:
			hash2 = hashvalue
		
		
		# Build the URL
		url = "http://cracker.fox21.at/api.php?a=check&h=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		xml = None
		if response:
			try:
				doc = parseDoc ( response.read() )
			except:
				#print "INFO: You need libxml2 to use this plugin."
				return None
		else:
			return None
		
		result = doc.xpathEval("//hash/@plaintext")
		
		if result:
			return result[0].content
		else:
			return None


class NICENAMECREW:
	
	name = 		"nicenamecrew"
	url = 		"http://crackfoo.nicenamecrew.com"
	supported_algorithm = [MD5, SHA1, LM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		hash2 = None
		if alg in [LM] and ':' in hashvalue:
			hash2 = hashvalue.split(':')[0]
		else:
			hash2 = hashvalue
			
		# Build the URL
		url = "http://crackfoo.nicenamecrew.com/?t=%s" % (alg)
		
		# Build the parameters
		params = { "q" : hash2,
			   "sa" : "Crack" }
			   
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'The decrypted version of [^\s]* is:<br><strong>[^<]*</strong>', html)
		
		if match:
			return match.group().split('strong>')[1][:-2].strip()
		else:
			return None



class JOOMLAAA:
	
	name = 		"joomlaaa"
	url = 		"http://joomlaaa.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://joomlaaa.com/component/option,com_md5/Itemid,31/"
		
		# Build the parameters
		params = { "md5" : hashvalue,
			   "decode" : "Submit" }
			   
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r"<td class='title1'>not available</td>", html)
		
		if not match:
			match2 = findall (r"<td class='title1'>[^<]*</td>", html)
			return match2[1].split('>')[1][:-4]
		else:
			return None



class MD5_LOOKUP:
	
	name = 		"md5-lookup"
	url = 		"http://md5-lookup.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5-lookup.com/livesearch.php?q=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<td width="250">[^<]*</td>', html)
		
		if match:
			return match.group().split('>')[1][:-4]
		else:
			return None


class SHA1_LOOKUP:
	
	name = 		"sha1-lookup"
	url = 		"http://sha1-lookup.com"
	supported_algorithm = [SHA1]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://sha1-lookup.com/livesearch.php?q=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<td width="250">[^<]*</td>', html)
		
		if match:
			return match.group().split('>')[1][:-4]
		else:
			return None


class SHA256_LOOKUP:
	
	name = 		"sha256-lookup"
	url = 		"http://sha-256.sha1-lookup.com"
	supported_algorithm = [SHA256]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://sha-256.sha1-lookup.com/livesearch.php?q=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<td width="250">[^<]*</td>', html)
		
		if match:
			return match.group().split('>')[1][:-4]
		else:
			return None



class RIPEMD160_LOOKUP:
	
	name = 		"ripemd-lookup"
	url = 		"http://www.ripemd-lookup.com"
	supported_algorithm = [RIPEMD]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://www.ripemd-lookup.com/livesearch.php?q=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<td width="250">[^<]*</td>', html)
		
		if match:
			return match.group().split('>')[1][:-4]
		else:
			return None



class MD5_COM_CN:
	
	name = 		"md5.com.cn"
	url = 		"http://md5.com.cn"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.com.cn/md5reverse"
		headers={"Host": "www.md5.com.cn",\
			"Referer": "http://www.md5.com.cn/",\
			"Content-Type": "application/x-www-form-urlencoded"}
		# Build the parameters
		params = { "md" : hashvalue,
			   "submit" : "MD5 Crack" }
		# Make the request
		response = do_HTTP_request ( url, params, httpheaders=headers )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<b style="color:red;">[^<]*</b><br/><span', html)
		
		if match:
			return match.group().split('>')[1][:-3]
		else:
			return None



class DIGITALSUN:
	
	name = 		"digitalsun.pl"
	url = 		"http://md5.digitalsun.pl"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.digitalsun.pl/"
		
		# Build the parameters
		params = { "hash" : hashvalue }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<b>[^<]*</b> == [^<]*<br>\s*<br>', html)
		
		if match:
			return match.group().split('b>')[1][:-2]
		else:
			return None



class DRASEN:
	
	name = 		"drasen.net"
	url = 		"http://md5.drasen.net"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.drasen.net/search.php?query=%s" % (hashvalue)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'Hash: [^<]*<br />Plain: [^<]*<br />', html)
		
		if match:
			return match.group().split('<br />')[1][7:]
		else:
			return None




class MYINFOSEC:
	
	name = 		"myinfosec"
	url = 		"http://md5.myinfosec.net"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.myinfosec.net/md5.php"
		
		# Build the parameters
		params = { "md5hash" : hashvalue }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<center></center>[^<]*<font color=green>[^<]*</font><br></center>', html)
		
		if match:
			return match.group().split('>')[3][:-6]
		else:
			return None



class MD5_NET:
	
	name = 		"md5.net"
	url = 		"http://md5.net"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://www.md5.net/cracker.php"
		
		# Build the parameters
		params = { "hash" : hashvalue }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<input type="text" id="hash" size="32" value="[^"]*"/>', html)
		
		if match:
			return match.group().split('"')[7]
		else:
			return None




class NOISETTE:
	
	name = 		"noisette.ch"
	url = 		"http://md5.noisette.ch"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5.noisette.ch/index.php"
		
		# Build the parameters
		params = { "hash" : hashvalue }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<p>String to hash : <input name="text" value="[^"]+"/>', html)
		
		if match:
			return match.group().split('"')[3]
		else:
			return None




class MD5HOOD:
	
	name = 		"md5hood"
	url = 		"http://md5hood.com"
	supported_algorithm = [MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://md5hood.com/index.php/cracker/crack"
		
		# Build the parameters
		params = { "md5" : hashvalue,
			   "submit" : "Go" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<div class="result_true">[^<]*</div>', html)
		
		if match:
			return match.group().split('>')[1][:-5]
		else:
			return None



class STRINGFUNCTION:
	
	name = 		"stringfunction"
	url = 		"http://www.stringfunction.com"
	supported_algorithm = [MD5, SHA1]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = ""
		if alg == MD5:
			url = "http://www.stringfunction.com/md5-decrypter.html"
		else:
			url = "http://www.stringfunction.com/sha1-decrypter.html"
		
		# Build the parameters
		params = { "string" : hashvalue,
			   "submit" : "Decrypt",
			   "result" : "" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<textarea class="textarea-input-tool-b" rows="10" cols="50" name="result"[^>]*>[^<]+</textarea>', html)
		
		if match:
			return match.group().split('>')[1][:-10]
		else:
			return None





class XANADREL:
	
	name = 		"99k.org"
	url = 		"http://xanadrel.99k.org"
	supported_algorithm = [MD4, MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://xanadrel.99k.org/hashes/index.php?k=search"
		
		# Build the parameters
		params = { "hash" : hashvalue,
			   "search" : "ok" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<p>Hash : [^<]*<br />Type : [^<]*<br />Plain : "[^"]*"<br />', html)
		
		if match:
			return match.group().split('"')[1]
		else:
			return None




class SANS:
	
	name = 		"sans"
	url = 		"http://isc.sans.edu"
	supported_algorithm = [MD5, SHA1]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://isc.sans.edu/tools/reversehash.html"
		
		# Build the Headers with a random User-Agent
		headers = { "User-Agent" : USER_AGENTS[randint(0, len(USER_AGENTS))-1] }
		
		# Build the parameters
		response = do_HTTP_request ( url, httpheaders=headers )
		html = None
		if response:
			html = response.read()
		else:
			return None
		match = search (r'<input type="hidden" name="token" value="[^"]*" />', html)
		token = ""
		if match:
			token = match.group().split('"')[5]
		else:
			return None
		
		params = { "token" : token,
			   "text" : hashvalue,
			   "word" : "",
			   "submit" : "Submit" }
		
		# Build the Headers with the Referer header
		headers["Referer"] = "http://isc.sans.edu/tools/reversehash.html"
		
		# Make the request
		response = do_HTTP_request ( url, params, headers )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'... hash [^\s]* = [^\s]*\s*</p><br />', html)
		
		if match:
			#print "hola mundo"
			return match.group().split('=')[1][:-10].strip()
		else:
			return None



class BOKEHMAN:
	
	name = 		"bokehman"
	url = 		"http://bokehman.com"
	supported_algorithm = [MD4, MD5]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False



	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Build the URL
		url = "http://bokehman.com/cracker/"
		
		# Build the parameters from the main page
		response = do_HTTP_request ( url )
		html = None
		if response:
			html = response.read()
		else:
			return None
		match = search (r'<input type="hidden" name="PHPSESSID" id="PHPSESSID" value="[^"]*" />', html)
		phpsessnid = ""
		if match:
			phpsessnid = match.group().split('"')[7]
		else:
			return None
		match = search (r'<input type="hidden" name="key" id="key" value="[^"]*" />', html)
		key = ""
		if match:
			key = match.group().split('"')[7]
		else:
			return None
		
		params = { "md5" : hashvalue,
			   "PHPSESSID" : phpsessnid,
			   "key" : key,
			   "crack" : "Try to crack it" }
		
		# Make the request
		response = do_HTTP_request ( url, params )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<tr><td>[^<]*</td><td>[^<]*</td><td>[^s]*seconds</td></tr>', html)
		
		if match:
			return match.group().split('td>')[1][:-2]
		else:
			return None



class GOOG_LI:

	name = 		"goog.li"
	url = 		"http://goog.li"
	supported_algorithm = [MD5, MYSQL, SHA1, SHA224, SHA384, SHA256, SHA512, RIPEMD, NTLM, GOST, WHIRLPOOL, LDAP_MD5, LDAP_SHA1]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
			
		hash2 = None
		if alg in [NTLM] and ':' in hashvalue:
			hash2 = hashvalue.split(':')[1]
		else:
			hash2 = hashvalue
		
		# Confirm the initial '*' character
		if alg == MYSQL and hash2[0] != '*':
			hash2 = '*' + hash2
		
		# Build the URL
		url = "http://goog.li/?q=%s" % (hash2)
		
		# Make the request
		response = do_HTTP_request ( url )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<br />cleartext[^:]*: [^<]*<br />', html)
		
		if match:
			return match.group().split(':')[1].strip()[:-6]
		else:
			return None



class WHREPORITORY:

	name = 		"Windows Hashes Repository"
	url = 		"http://nediam.com.mx"
	supported_algorithm = [LM, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
			
		hash2 = None
		if ':' in hashvalue:
			if alg == LM:
				hash2 = hashvalue.split(':')[0]
			else:
				hash2 = hashvalue.split(':')[1]
		else:
			hash2 = hashvalue
		
		# Build the URL, parameters and headers
		url = ""
		params = None
		headers = None
		if alg == LM:
			url = "http://nediam.com.mx/winhashes/search_lm_hash.php"
			params = { "lm" : hash2,
				"btn_go" : "Search" }
			headers = { "Referer" : "http://nediam.com.mx/winhashes/search_lm_hash.php" }
		else:
			url = "http://nediam.com.mx/winhashes/search_nt_hash.php"
			params = { "nt" : hash2,
				"btn_go" : "Search" }
			headers = { "Referer" : "http://nediam.com.mx/winhashes/search_nt_hash.php" }
		
		# Make the request
		response = do_HTTP_request ( url, params, headers )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<tr><td align="right">PASSWORD</td><td>[^<]*</td></tr>', html)
		
		if match:
			return match.group().split(':')[1]
		else:
			return None