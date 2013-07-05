#!/usr/bin/env python2
#-*-encoding:utf-8-*-

import Queue, os, threading, hashlib
from random import randint
from modules.hashf import *
from modules.CRAKERS import CRAKERS
try:
	ismsvcrt = 0
	from lib.ThreadGetKey import ThreadGetKey
	ismsvcrt = 1
except:
	print """
	msvcrt is not installed. You may not stop the program by press Q!
"""


def crackHash (algorithm, hashvalue=None, hashfile=None, savepath=None):
	global CRAKERS
	global queue
	global threads
	global hashresults
	global ishashcracked
	global nowcracking
	
	# Cracked hashes will be stored here
	crackedhashes = []
	
	# Is the hash cracked?
	cracked = False
	
	# Only one of the two possible inputs can be setted.
	if (not hashvalue and not hashfile) or (hashvalue and hashfile):
		return False
	
	# hashestocrack depends on the input value
	hashestocrack = None
	if hashvalue:
		hashestocrack = [ hashvalue ]
	else:
		try:
			hashestocrack = open (hashfile, "r")
		except:
			print "\nIt is not possible to read input file (%s)\n" % (hashfile)
			return cracked
	
	
	# Try to crack all the hashes...
	for activehash in hashestocrack:
		hashresults = []
		threads = []
		ishashcracked = "0"
		# Standarize the hash
		activehash = activehash.strip()
		nowcracking = activehash
		if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
			activehash = activehash.lower()
		
		# Initial message
		print "\nCracking hash-------------> %s\n" % (activehash)

		# Each loop starts for a different start point to try to avoid IP filtered
		begin = randint(0, len(CRAKERS)-1)
		queue = Queue.Queue()
		queue.queue.clear()
		for i in range(len(CRAKERS)):
			queue.put(i)
		# maxloading = queue.qsize()
		# view_loading = Loading(maxloading)
		# view_loading.start()

		line = len(CRAKERS)
		if ismsvcrt == 1 :
			shouhu = ThreadGetKey()
			shouhu.setDaemon(True)
			shouhu.start()
		
		for i in range(line):
			a = START_CRACKER(begin,algorithm,activehash,savepath)
			a.start()
			threads.append(a)
		for j in threads:
			j.join()
		# Store the result/s for later...
		if hashresults:
			# With some hash types, it is possible to have more than one result,
			# Repited results are deleted and a single string is constructed.
			resultlist = []
			for r in hashresults:
				#if r.split()[-1] not in resultlist:
					#resultlist.append (r.split()[-1])
				if r not in resultlist:
					resultlist.append (r)
					
			finalresult = ""
			if len(resultlist) > 1:
				finalresult = ', '.join (resultlist)
			else:
				finalresult = resultlist[0]
			
			# Valid results are stored
			crackedhashes.append ( (activehash, finalresult) )
	
	
	# Loop is finished. File can need to be closed
	if hashfile:
		try:
			hashestocrack.close ()
		except:
			pass
		
	# Show a resume of all the cracked hashes
	print "\nThe following hashes were cracked:\n----------------------------------\n"
	print crackedhashes and "\n".join ("%s -> %s" % (hashvalue, result.strip()) for hashvalue, result in crackedhashes) or "NO HASH WAS CRACKED."
	return cracked


class START_CRACKER(threading.Thread):
	def __init__(self,begin,algorithm,activehash,savepath):
		threading.Thread.__init__(self)
		self.begin = begin
		self.algorithm = algorithm
		self.activehash = activehash
		self.savepath = savepath

	def run(self):
		while 1:
			if queue.empty()== True:
				break
			# Select the cracker
			self.i = queue.get()
			global ishashcracked
			if ishashcracked == "1":
				return
			self.cr = CRAKERS[ (self.i+self.begin)%len(CRAKERS) ]()
			# Check if the cracker support the algorithm
			if not self.cr.isSupported ( self.algorithm ):
				return
			# Analyze the hash
			#print "Analyzing %s with %s..." % (self.activehash, self.cr.name)
				
			# Crack the hash
			self.result = None
			try:
				self.result = self.cr.crack ( self.activehash, self.algorithm )
				# If it was some trouble, exit
			except Exception,e:
				print e
				return False
				
				# If there is any result...
			self.cracked = 0
			if self.result and self.activehash == nowcracking :
				# If it is a hashlib supported algorithm...
				if self.algorithm in [MD4, MD5, SHA1,  SHA224, SHA384, SHA256, SHA512, RIPEMD]:
					# Hash value is calculated to compare with cracker result
					self.h = hashlib.new (self.algorithm)
					self.h.update (self.result)
						
					# If the calculated hash is the same to cracker result, the result is correct (finish!)
					if self.h.hexdigest() == self.activehash.lower() or self.h.hexdigest()[8:24] == self.activehash.lower():
						hashresults.append (self.result)
						self.cracked = 2
					
				# If it is a half-supported hashlib algorithm
				elif self.algorithm in [LDAP_MD5, LDAP_SHA1]:
					self.alg = algorithm.split('_')[1]
					self.ahash =  decodestring ( activehash.split('}')[1] )
						
					# Hash value is calculated to compare with cracker result
					self.h = hashlib.new (self.alg)
					self.h.update (self.result)
						
					# If the calculated hash is the same to cracker result, the result is correct (finish!)
					if self.h.digest() == self.ahash:
						hashresults.append (self.result)
						self.cracked = 2
					
				# If it is a NTLM hash
				elif self.algorithm == NTLM or (self.algorithm == LM and ':' in self.activehash):
					# NTLM Hash value is calculated to compare with cracker result
					self.candidate = hashlib.new('md4', result.split()[-1].encode('utf-16le')).hexdigest()
					
					# It's a LM:NTLM combination or a single NTLM hash
					if (':' in self.activehash and self.candidate == self.activehash.split(':')[1]) or (':' not in self.activehash and self.candidate == self.activehash):
						hashresults.append (self.result)
						self.cracked = 2
					
				# If it is another algorithm, we search in all the crackers
				else:
					hashresults.append (self.result)
					self.cracked = 1
			
			# elif self.result:
			# 	self.panding = 0
			# 	if self.algorithm in [MD4, MD5, SHA1,  SHA224, SHA384, SHA256, SHA512, RIPEMD]:
			# 		self.h = hashlib.new (self.algorithm)
			# 		self.h.update (self.result)
			# 		if self.h.hexdigest() == self.activehash.lower() or self.h.hexdigest()[8:24] == self.activehash.lower():
			# 			self.panding = 1
			# 	elif self.algorithm in [LDAP_MD5, LDAP_SHA1]:
			# 		self.alg = algorithm.split('_')[1]
			# 		self.ahash =  decodestring ( activehash.split('}')[1] )
			# 		self.h = hashlib.new (self.alg)
			# 		self.h.update (self.result)
			# 		if self.h.digest() == self.ahash:
			# 			self.panding = 1
			# 	elif self.algorithm == NTLM or (self.algorithm == LM and ':' in self.activehash):
			# 		self.candidate = hashlib.new('md4', result.split()[-1].encode('utf-16le')).hexdigest()
			# 		if (':' in self.activehash and self.candidate == self.activehash.split(':')[1]) or (':' not in self.activehash and self.candidate == self.activehash):
			# 			self.panding = 1
			# 	else:
			# 		self.panding = 1
			# 	if self.panding == 1:
			# 		self.hashwrite = self.activehash+"----->"+self.result+"\n"
			# 		print "\n***** OLDER HASH CRACKED!! *****\n %s \n" % (self.hashwrite)
			# 		if self.savepath:
			# 			self.savepath = os.path.dirname(self.savepath)+"/exhashsave.txt"
			# 			self.hashf = open(self.savepath,'a')
			# 			self.hashf.write(self.hashwrite)
			# 			self.hashf.close
			# 	return

			# Had the hash cracked?
			if self.cracked and ishashcracked == "0":
				print "\n***** HASH CRACKED!! *****\nThe unhashed pass is: %s\n" % (self.result)
				ishashcracked = "1"
				queue.queue.clear()
				if self.savepath:
					self.hashwrite = self.activehash+"----->"+self.result+"\n"
					print "save to --> "+self.savepath
					self.hashf = open(self.savepath,'a')
					self.hashf.write(self.hashwrite)
					self.hashf.close
				return
			elif ishashcracked == "1":
				return

			if self.result and ishashcracked == "0":
				if self.result.find("----->") != -1:
					try:
						print "pay list ---> "+os.path.dirname(self.savepath)+"/hash_pay.txt"
						self.sf = open(os.path.dirname(self.savepath)+"/hash_pay.txt",'a')
						self.sf.write("\n"+self.result)
						self.sf.close()
					except:
						pass
					return