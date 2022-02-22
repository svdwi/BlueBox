import os 
#import urllib
#import urllib2
from App.secrets import * 
import json 

#get value from dictionary  (key:value) ("URL": "www.svdwi.com")
class GetConfig(): 
	def __api__(self,api_name): 
		return config.get(api_name)
 
    




