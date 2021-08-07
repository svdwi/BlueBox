import os 
import re 
import magic 
import json
import urllib
import urllib2
from _config import GetConfig 
from _config import GetHTTPResponse 

"""
 Fonction you can found it on _config.py 
 Send a request to API for  get some response to show  
 GetHTTPResponse().__send__( parametre  ,  Url )  


That Fonction get config API KEY & URL  ( _config.py )
GetConfig().__api__("Virustotal")["URL"]


Execute that Class : 
put code in end of file 
print(VTotalAPI("829dde7015c32d7d77d8128665390dab").run())


"""


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

 

#829dde7015c32d7d77d8128665390dab = Cryptolocker_Ransomeware_hash_md5_file 
#print(VTotalAPI("b2aa1bd534746649b754c8175086c714").run())
