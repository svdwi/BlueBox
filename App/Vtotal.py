import os 
import re 
import magic 
import json
import urllib
import urllib2
from _config import GetConfig 
from _config import GetHTTPResponse 


class VTotalAPI(): 


	def __init__(self, hash):

		self.VirusTotal_url = GetConfig().__api__("Virustotal")["URL"]
		self.VirusTotal_API_key =  GetConfig().__api__("Virustotal")["KEY"]
		self.hash = hash 
		self.param  = {'apikey': self.VirusTotal_API_key, 'resource': self.hash}


	def SendRequest(self):
		return GetHTTPResponse().__send__(self.param , self.VirusTotal_url) 


	def run(self):
		#self.SendRequest()
		return self.SendRequest()

 
