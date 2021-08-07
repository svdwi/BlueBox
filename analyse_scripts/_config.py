import os 
#import urllib
#import urllib2
from analyse_scripts.secrets import * 
import json 
"""
api Fonction To get API KEY from Secret File <secret.py>
Exemple For use : 

------- GetConfig().__api__("Virustotal")["KEY"] -------
------- GetConfig().__api__("Virustotal")["URL"] -------
"""





"""

# Fonction TO send request with specifc param
class GetHTTPResponse():
	def __send__(self, param , url ):
		encodedParm = urllib.urlencode(param)
		request = urllib2.Request(url , encodedParm)
		response = urllib2.urlopen(request)
		json_response = json.loads(response.read())
		if json_response : 
			return json_response
		else: 
			return "{}"
"""

#get value from dictionary  (key:value) ("URL": "www.svdwi.com")
class GetConfig(): 
	def __api__(self,api_name): 
		return config.get(api_name)
 
    




