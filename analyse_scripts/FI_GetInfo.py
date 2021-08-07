import magic 
import json
import pefile
import pyexifinfo 
import hashlib
import ssdeep

class FileInfo():


	def __init__(self, file_name):
		self.filepath = file_name
		self.pe = pefile.PE(self.filepath)
		if not self.pe:
			raise pefile.PEFormatError('__EmptyFile__')


	def run(self):	
		results = {}
		content = open(self.filepath, 'rb').read()  
		results = {
		'MD5'  : hashlib.md5(content).hexdigest(),
		'SHA1'  : hashlib.sha1(content).hexdigest(),
		'SHA251' : hashlib.sha256(content).hexdigest(),
		'sha512'  : hashlib.sha512(content).hexdigest(),	
		'Magic': self.F_Magic(),
		'SSDeep': self.PE_ssdeep(),
		'Type': self.F_Mimetype(),
		'File TYpe': self.F_FileType(),
		#'exiftool_Report': self.F_Exif(),
											}
		return results 

	def PE_ssdeep(self):
		try:
			return ssdeep.hash_from_file(self.filepath)
		except ImportError:
			pass
		return ''

	def F_Magic(self):
		return magic.from_file(self.filepath)	


	def F_Mimetype(self):
		return magic.from_file(self.filepath, mime=True) 

	def F_FileType(self): 		
		return pyexifinfo.fileType(self.filepath).encode()



	def F_Exif(self):

		exif_report = pyexifinfo.get_json(self.filepath)
		if exif_report:
			exif_report_cleaned = {
				key: value
				for key, value in exif_report[0].items()
				if not (key.startswith("File") or key.startswith("SourceFile"))
			}
			
		return  json.dumps(exif_report_cleaned) 

	def F_Hash(self):
		hashes = {}
		content = open(self.filepath, 'rb').read()  
		#hashlib.md5(open(f, 'rb').read()).hexdigest()
		hashes["Hash_md5"]  = hashlib.md5(content).hexdigest()
		hashes["Hash_sha1"]  = hashlib.sha1(content).hexdigest()
		hashes["Hash_sha251"]  = hashlib.sha256(content).hexdigest()
		hashes["Hash_sha512"]  = hashlib.sha512(content).hexdigest()
		return hashes


 
		
