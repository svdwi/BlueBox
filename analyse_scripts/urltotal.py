import json
from analyse_scripts._config import GetConfig 
from virustotal_python import Virustotal
from pprint import pprint
from base64 import urlsafe_b64encode

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


	def __init__(self,url):
		self.VirusTotal_API_key =  GetConfig().__api__("Virustotal")["KEY"]
		self.url  = url
	 

	

	def run(self):
		try:
			vtotal = Virustotal(API_KEY=self.VirusTotal_API_key)
			resp = vtotal.request("url/scan", params={"url": self.url}, method="POST")
			url_resp = resp.json()
			scan_id = url_resp["scan_id"]
			analysis_resp = vtotal.request("url/report", params={"resource": scan_id})
			b = analysis_resp.json()
			return b["scans"]
		except:
			return {"error check connection please !!"}


