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


	def run(self):
		return self.Static_File_Info() 



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
 
