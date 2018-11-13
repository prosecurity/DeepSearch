#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
# --------------------------------------
# DeepSearch - Advanced Web Dir Scanner
# by Momo (m4ll0k) Outaadi
# --------------------------------------

import os
import re
import sys
import time
import random
import requests
import urllib3
import socket
import getopt
import requests
import concurrent.futures
from urllib.parse import urlparse

# -- colors --
R = "\033[%s;31m"; G = "\033[%s;32m"
Y = "\033[%s;33m"; B = "\033[%s;34m"
M = "\033[%s;35m"; C = "\033[%s;36m"
W = "\033[%s;37m"; E = "\033[0m"

# -- time format --
strftime = "%H:%M:%S"

# -- banner -- 
banner= r'''
{l}
 DeepSearch - Advanced Web Dir Scanner
       Momo (m4ll0k) Outaadi
     {y}https://github.com/m4ll0k{r}
{e}
'''.format(l='-'*40,e='-'*40,y=Y%0,r=E)

# -- kwargs var -- 
kwargs = {
	'cookie':None,'ragent':False,
	'delay':None,'timeout':None,
	'hostname':False,'redirect':False,
	'proxy':None,'threads':5,
	'dict':None,'tolower':False,
	'toupper':False,'force' :False,
	'maxretries' :2,'headers':None,
	'exclude': None,'only': None,
	'extension': None,'wordlist':None
}

def warn(string,exit=False):
	print('{red}[!] {string}{end}'.format(
		red=R%0,string=string,end=E))
	if exit: sys.exit(0)

# -- random user-agent 
def randomAgent():
	path = os.path.join(os.path.abspath('.'),'agents.txt')
	agents = [x.strip() for x in open(path,'rb')]
	return agents[random.randint(0,len(agents)-1)]

# -- request class --
class Request(object):
	def __init__(self,kwargs):
		self.host = None
		self.ip = None
		self.port = None
		self.headers = {}
		self.protocol = None
		self.basePath = None
		self.agent = randomAgent()
		self.cookie = kwargs['cookie']
		self.ragent = kwargs['ragent']
		self.proxy = kwargs['proxy']
		self.delay = kwargs['delay']
		self.timeout = kwargs['timeout']
		self.redirect = kwargs['redirect']
		self.maxRetries = kwargs['maxretries']
		self.byhostname = kwargs['hostname']
		self.set_headers = kwargs['headers']
		self.session = requests.Session()

	def path(self,_path,_word):
		# check path
		if _word.endswith('/'): _word = _word[:-1]
		if not _path.startswith('/'): _path = '/'+_path

		if r'%%' in _path:
			return _path.replace(r'%%',_word)
		
		elif re.search(r'\%(\S*)\%',_path,re.I):
			return re.sub(r'\%(\S*)\%',_word,_path)
		
		else:
			if _path.endswith('/') and  _word.startswith('/'):
				try:
					if _word.split('.')[1]:
						# end with ext
						return _path + _word[1:]
				except IndexError:
					# dir 
					return _path + _word[1:] + '/'
			elif not _path.endswith('/') and not _word.startswith('/'):
				try:
					if _word.split('.')[1]:
						return _path + '/' + _word
				except IndexError:
					return _path + '/' + _word + '/'
			else:
				try:
					if _word.split('.')[1]:
						return _path + _word
				except IndexError:
					return _path + _word + '/'
		return _word

	def req(self,url,word):
		len_max = 0
		proxies = None 
		response = None 
		# urlparse
		parsed = urlparse(url)
		if parsed.scheme not in ['http','https']:
			parsed = urlparse('http://'+url)
		# parts
		self.protocol = parsed.scheme
		if ':' in parsed.netloc:
			self.host,self.port = parsed.netloc.split(':')
		else:
			self.host = parsed.netloc
		self.basePath = parsed.path +'?'+ parsed.query if parsed.query != '' else parsed.path
		# headers 
		self.headers['Host'] = self.host
		self.headers['User-Agent'] = self.agent 
		if self.ragent is True:
			self.headers['User-Agent'] = randomAgent()
		self.headers['Accept-Language'] = 'en-US,en;q=0.8,en-US;q=0.5,en;q=0.3'
		self.headers['Accept-Encoding'] = 'gzip, deflate'
		self.headers['Keep-Alive'] = '300'
		self.headers['Connection'] = 'keep-alive'
		self.headers['Cache-Control'] = 'max-age=0'
		if self.cookie is not None:
			self.headers['Cookie'] = self.cookie 
		# headers
		if self.set_headers != None:
			if '\\n' in self.set_headers:
				for header in self.set_headers.split('\\n'):
					key,value = header.split(':')
					self.headers[key] = value
			else:
				key,value = self.set_headers.split(':')
				self.headers[key] = value
		# by hostname
		if self.byhostname is True:
			try:
				if self.ip == None:
					self.ip = socket.gethostbyname(self.host)
				else:
					pass
			except socket.gaierror as e:
				print('Couldn\'t resolve DNS')
		# make base path
		self.basePath = self.path(self.basePath,word)
		# make url 
		try:
			if self.ip != None:
				url = '{protocol}://{netloc}{path}'.format(
					protocol = self.protocol,
					netloc = self.ip+':'+self.port if self.port != None else self.ip,
					path = self.basePath
					)
			else:
				url = '{protocol}://{netloc}{path}'.format(
					protocol = self.protocol,
					netloc = parsed.netloc,
					path = self.basePath
					)
		except Exception as e:
			print(e)
		# make proxy
		if self.proxy != None:
			proxies = {
			'http'  : self.proxy,
			'https' : self.proxy
			}
		# urljoin 
		while len_max < self.maxRetries:
			try:
				resp = requests.packages.urllib3.disable_warnings(
					urllib3.exceptions.InsecureRequestWarning
					)
				resp = self.session.get(
					url = url,
					verify = False,
					proxies = proxies,
					headers = self.headers,
					timeout = self.timeout,
					allow_redirects = self.redirect
					)
				response = resp 
				# delay
				if self.delay is not None:
					time.sleep(self.delay)
				try:
					if response != None or response != "":
						break
				except NameError:
					pass
			except requests.exceptions.TooManyRedirects as e:
				warn('Too many redirects: %s'%(e),1)
			except requests.exceptions.SSLError as e:
				warn('SSL Error connecting to server. Try the -b/--host flag to connect by hostname',1)
			except requests.ConnectionError as e:
				if self.proxy is not None:
					warn('Error with proxy: %s'%(e))
				len_max += 1
				if len_max > self.maxRetries:
					warn(e,1)
				continue
			except (requests.exceptions.ConnectTimeout,
				requests.exceptions.ReadTimeout,
				requests.exceptions.Timeout,
				socket.timeout) as e:
				len_max += 1
				if len_max > self.maxRetries:
					warn(e,1)
				continue

		if len_max > self.maxRetries:
			warn('Connection Timeout: There was a problem in the request to: %s'%url,1)
		return response

def Test(url):
	try:
		resp = requests.packages.urllib3.disable_warnings(
			urllib3.exceptions.InsecureRequestWarning
			)
		resp = requests.get(url,
			verify=False,
			headers={'User-Agent':'Mozilla/5.0'},
			allow_redirects=False
			)
	except Exception as e:
		warn('Failed to establish a connection.',1)

def LenHtml(content):
	f_len = len(content)
	if f_len <= 1023:
		return "%sB"%(f_len)
	else:
		return "%sKB"%(int(f_len/1000))

def ProcessPrint(resp,exclude,only,word):
	url = resp.url
	content = resp.content
	code = resp.status_code
	word = '/'+word if not word.startswith('/') else word
	if exclude != None:
		if str(code) not in exclude:
			pprint(url,code,content,word)
	elif only != None:
		if str(code) in only:
			pprint(url,code,content,word)
	else:
		pprint(url,code,content,word)

def pprint(url,code,content,word):
	if code == 200:
		print('{g}[{t}] {code} - {len_}\t- {url}{e}'.format(
			g=G%0,t=time.strftime(strftime),e=E,
			code=code,len_=LenHtml(content),url=word))
	elif code in [301,302]:
		print('{m}[{t}] {code} - {len_}\t- {word} -> {url}{e}'.format(
			m=M%0,t=time.strftime(strftime),e=E,
			code=code,len_=LenHtml(content),word=word,url=url))
	elif code == 401:
		print('{y}[{t}] {code} - {len_}\t- {url}{e}'.format(
			y=Y%0,t=time.strftime(strftime),e=E,
			code=code,len_=LenHtml(content),url=word))
	else:
		if code != 404:
			print('{w}[{t}] {code} - {len_}\t- {url}{e}'.format(
				w=W%0,t=time.strftime(strftime),e=E,
				code=code,len_=LenHtml(content),url=word)
			)

def usage(exit=False,ban=False):
	if ban != False:
		print(banner)
	print('''Usage: deepsearch.py [OPTIONS]\n
	-u  --url\t\tTarget URL (e.g: http://site.com)
	-U  --url-list\t\tScan multiple targets given in a text file
	-b  --host\t\tMake request by hostname
	-e  --extension\t\tExtensions list separated by comma (e.g: php,asp)
	-w  --wordlist\t\tSet wordlist, (e.g: wl.txt)
	-r  --random-agent\tUse random User-Agent
	-c  --cookies\t\tSet HTTP Cookie header value
	-H  --headers\t\tSet HTTP Headers (e.g: "Accept: ..\\nTag: 123")
	-f  --force\t\tForce extension for every wordlist entry
	-x  --exclude\t\tExclude status code separated by comma (e.g: 400,500)
	-l  --lowercase\t\tForce lowercase for every wordlist entry
	-p  --uppercase\t\tForce uppercase for every wordlist entry
	-R  --redirect\t\tIgnore redirection attemps
	-d  --delay\t\tDelay in seconds between each HTTP request
	-P  --proxy\t\tUse a proxy to connect to the target URL
	-o  --only\t\tShow only status code separated by comma (e.g: 200,302)
	-t  --threads\t\tMax number of concurrent HTTP requests
	-T  --timeout\t\tSeconds to wait before timeout connection
	-h  --help\t\tShow this banner and exit
	''')
	if exit: sys.exit(0)

def ProcessWord(word,toupper=False,tolower=False,force=False,extension=None):
	word = word.decode('utf-8')
	word_2 = word
	if word != None:
		if toupper: word_2 = str(word).upper()
		if tolower: word_2 = str(word).lower()
		if force:
			if type(extension) is list:
				for ext in extension:
					if ext.startswith('.'):
						return word_2+ext
					return word_2 +'.'+ext
			elif type(extension) is str:
				if extension.startswith('.'):
					return word_2+extension
				return word_2+'.'+extension
			else:
				return word_2
		return word
	return None

class Fuzzer(Request):
	def __init__(self,kwargs):
		Request.__init__(self,kwargs)
		self.kwargs = kwargs
		self.threads = kwargs['threads']
		self.exclude = kwargs['exclude']
		self.only = kwargs['only']

	def fuzzer(self,url,word):
		word = ProcessWord(
			word,self.kwargs['toupper'],
			self.kwargs['tolower'],self.kwargs['force'],self.kwargs['extension'])
		if word != None:
			resp = self.req(url,word)
			ProcessPrint(resp,self.exclude,self.only,word)

def ExtInToList(exts):
	if len(exts.split(',')) == 1:
		return exts
	elif len(exts.split(',')) > 1:
		return exts.split(',')

def CheckWordlist(wl):
	if os.path.exists(wl):
		if os.path.isdir(wl):
			print('"%s" is a directory...'%(wl))
		return wl
	else:
		print('"%s" not found path...'%(wl))

def ExcInToList(exc):
	if len(exc.split(',')) == 1:
		return [exc] 
	elif len(exc.split(',')) > 1:
		return exc.split(',')

def OnlyInToList(only):
	if len(only.split(',')) == 1:
		return [only]
	elif len(only.split(',')) > 1:
		return only.split(',')

def ReadFile(path):
	return [x.strip() for x in open(path,'rb')]

def CheckURL(url):
	parsed = urlparse(url)
	if parsed.scheme not in ['http','https','ftp','']:
		warn('The scheme "%s" not supported. Please check your URL'%(parsed.scheme),1)
	if parsed.netloc == '':
		warn('Please check your URL and try...',1)
	return url

def main():
	url = None
	urls = None
	is_multiple = False
	word_cmd = [
				'url=','url_list=','host','extension=','wordlist=',
				'random-agent','cookies=','headers=','force',
				'exclude=','uppercase','lowercase','redirect','delay=',
				'proxy=','only=','threads=','timeout=','help'
			]
	single_cmd = 'u:U:e:w:c:H:x:d:P:o:t:T:brflpRh'
	try:
		opts,args = getopt.getopt(sys.argv[1:],single_cmd,word_cmd)
	except getopt.GetoptError as e:
		usage(True,False)
	for i in range(len(opts)):
		if(opts[i][0] in('-u','--url')): url = opts[i][1]
		if(opts[i][0] in('-U','--url-list')): urls = CheckWordlist(opts[i][1])
		if(opts[i][0] in('-b','--host')): kwargs['hostname'] = True
		if(opts[i][0] in('-e','--extension')): kwargs['extension'] = ExtInToList(opts[i][1])
		if(opts[i][0] in('-w','--wordlist')): kwargs['wordlist'] = CheckWordlist(opts[i][1])
		if(opts[i][0] in('-r','--random-agent')): kwargs['ragent'] = True
		if(opts[i][0] in('-c','--cookies')): kwargs['cookie'] = opts[i][1]
		if(opts[i][0] in('-H','--headers')): kwargs['headers'] = opts[i][1]
		if(opts[i][0] in('-f','--force')): kwargs['force'] = True
		if(opts[i][0] in('-x','--exclude')): kwargs['exclude'] = ExcInToList(opts[i][1])
		if(opts[i][0] in('-l','--lowercase')): kwargs['tolower'] = True
		if(opts[i][0] in('-p','--uppercase')): kwargs['toupper'] = True
		if(opts[i][0] in('-R','--redirect')): kwargs['redirect'] = True
		if(opts[i][0] in('-d','--delay')): kwargs['delay'] = float(opts[i][1])
		if(opts[i][0] in('-P','--proxy')): kwargs['proxy'] = opts[i][1]
		if(opts[i][0] in('-t','--threads')): kwargs['threads'] = int(opts[i][1])
		if(opts[i][0] in('-o','--only')): kwargs['only'] = OnlyInToList(opts[i][1])
		if(opts[i][0] in('-t','--threads')): kwargs['threads'] = 2 if opts[i][1] == 1 else int(opts[i][1])
		if(opts[i][0] in('-T','--timeout')): kwargs['timeout'] = float(opts[i][1])
		if(opts[i][0] in('-h','--help')):usage(True,True)
	print(banner)
	if len(sys.argv) <= 2:
		usage(True,False)
	if kwargs['extension'] == None:
		sys.exit(print('No extension specified. You must specify at least one extension with -e/--extension'))
	if kwargs['wordlist'] == None:
		sys.exit(print('No wordlist specified. Please specify the wordlist with -w/--wordlist'))
	words = ReadFile(kwargs['wordlist'])
	header  = '%sExtension: %s%s%s'%(Y%1,M%1,kwargs['extension'],E)
	header += ' | '
	header += '%sThreads: %s%s%s'%(Y%1,M%1,kwargs['threads'],E)
	header += ' | '
	header += '%sWords: %s%s%s\n'%(Y%1,M%1,len(words),E)
	print(header)
	if urls != None:
		is_multiple = True
		print('%sScanning multiple targets...%s'%(Y%1,E))
		urls = ReadFile(urls)
	else:
		print('%sTarget: %s%s%s'%(Y%1,M%1,url,E))
		urls = [url]
	print('\n%s[%s] Starting...%s'%(Y%1,time.strftime(strftime),E))
	for u in urls:
		CheckURL(u)
		Test(u)
		if is_multiple:u=u.decode('utf-8')
		if is_multiple:
			CheckURL(u)
			print('\n%sTarget: %s%s%s'%(Y%1,M%1,u,E))
		try:
			ThreadPool = concurrent.futures.ThreadPoolExecutor(int(kwargs['threads']))
			thread = (ThreadPool.submit(Fuzzer(kwargs).fuzzer,u,w) for w in words)
			for i,_ in enumerate(concurrent.futures.as_completed(thread)):
				print('%s'%(words[i].decode('utf-8')),end='\r')
				print('%s'%(' '*len(words[i].decode('utf-8'))),end='\r')
				_.result()
		except KeyboardInterrupt as e:
			sys.exit(0)
# -- main --
try:
	main()
except KeyboardInterrupt as e:
	warn(e,1)