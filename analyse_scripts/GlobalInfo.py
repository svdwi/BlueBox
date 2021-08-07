import os
import re
import sys
import json

#Import From FI_GetInfo, FileInfo Classe
from FI_GetInfo import FileInfo  

#Import From Pe_GetInfo , PEInfo Classe
from Pe_GetInfo import PEInfo   
#from Vtotal import VTotalAPI 
#Calls_API
from Calls_Strings import calls_nd_strings 
from signaturecheck import signateur



class GlobalInfo(): 

	def __init__(self, file_name = None ):
		self.__file_path__ = file_name
		self.__FileInfo__ = FileInfo(self.__file_path__).run()
		self.__PEInfo__ = PEInfo(self.__file_path__).run()
		self.__Calls_Strings__ = calls_nd_strings(self.__file_path__).run()
		self.__signaturecheck__ = signateur(self.__file_path__).check_signateur()

	#print(self.__FileInfo )

	def run(self):
		return self.Static_File_Info() 



	##-------------------------------------------------------- ##
	# some problem happen on this fonction Vtotal_runner 	    #
	# for search a way to return a pure json (Not list return )#
	##-------------------------------------------------------- ##
	"""def Vtotal_runner(self , hash): 
	dump = VTotalAPI(hash).run()
	fJson = dump["scans"]
	extract = []	
	total = 0 
	for a , b in fJson.items():
	#print(str(b["detected"]).strip()) 
	if not "False" in str(b["detected"]).strip():
	total =+ 1 
	extract.append({
	"name" : a , 
	"result":  str(b["result"]),
	"detected" : str(b["detected"])  
	})
	return(json.dumps(extract))"""



	#return a json data (FI_Getinfo & Pe_GetInfo)	
	def Static_File_Info(self):
		results ={}
		results ={

		"FileInfo_Data": self.__FileInfo__ ,
		"PEInfo_Data": self.__PEInfo__ ,
		"Calls_API":self.__Calls_Strings__,
		"signature": self.__signaturecheck__,
		}
		return json.dumps(results)
 



print(GlobalInfo("WannaCry_Ransomware.exe").Static_File_Info())
