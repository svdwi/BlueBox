import os.path
import re
 
class calls_nd_strings():


	def __init__(self,file_name):
		self.filepath =file_name
		self.MAX_FILESIZE = 16*1024*1024
		self.MAX_STRINGCNT = 2048
		self.MAX_STRINGLEN = 1024


	def run(self):	
		return self.check_MalciousCalls()


	def ext_strings(self): 

		data = open(self.filepath, "rb").read(self.MAX_FILESIZE)
		strings =[]
		for _str in re.findall(b"[\x1f-\x7e]{6,}", data):
			strings.append(_str.decode("utf-8"))
		for _str in re.findall(b"(?:[\x1f-\x7e][\x00]){6,}", data):
			strings.append(_str.decode("utf-16le"))

		# Now limit the amount & length of the strings.
		strings = strings[:self.MAX_STRINGCNT]
		for idx, s in enumerate(strings):
			strings[idx] = s[:self.MAX_STRINGLEN]
		#print(strings)
		return strings
		#print(strings)




	def check_MalciousCalls(self):
		
		""" Over the last quarter, we ve seen an increase in malware using packers, 
			crypters, and protectors all methods used to obfuscate malicious code from 
			systems or programs attempting to identify it. 
	        Detect shit with Calls Babe   - svdwi **  """ 
	        
		suspicious_apis = ['accept','AddCredentials','bind','CertDeleteCertificateFromStore',
		'CheckRemoteDebuggerPresent','CloseHandle','closesocket','connect','ConnectNamedPipe',
		'CopyFile','CreateFile','CreateProcess','CreateToolhelp32Snapshot','CreateFileMapping',
		'CreateRemoteThread','CreateDirectory','CreateService','CreateThread','CryptEncrypt',
		'DeleteFile','DeviceIoControl','DisconnectNamedPipe','DNSQuery','EnumProcesses',
		'ExitProcess','ExitThread','FindWindow','FindResource','FindFirstFile','FindNextFile',
		'FltRegisterFilter','FtpGetFile','FtpOpenFile','GetCommandLine','GetComputerName',
		'GetCurrentProcess','GetThreadContext','GetDriveType','GetFileSize','GetFileAttributes',
		'GetHostByAddr','GetHostByName','GetHostName','GetModuleHandle','GetModuleFileName',
		'GetProcAddress','GetStartupInfo','GetSystemDirectory','GetTempFileName','GetTempPath',
		'GetTickCount','GetUpdateRect','GetUpdateRgn','GetUserNameA','GetUrlCacheEntryInfo',
		'GetVersionEx','GetWindowsDirectory','GetWindowThreadProcessId','HttpSendRequest',
		'HttpQueryInfo','IcmpSendEcho','IsBadReadPtr','IsBadWritePtr','IsDebuggerPresent',
		'InternetCloseHandle','InternetConnect','InternetCrackUrl','InternetQueryDataAvailable',
		'InternetGetConnectedState','InternetOpen','InternetQueryDataAvailable','InternetQueryOption',
		'InternetReadFile','InternetWriteFile','LdrLoadDll','LoadLibrary','LoadLibraryA','LockResource',
		'listen','MapViewOfFile','OutputDebugString','OpenFileMapping','OpenProcess','Process32First',
		'Process32Next','recv','ReadFile','RegCloseKey','RegCreateKey','RegDeleteKey','RegDeleteValue',
		'RegEnumKey','RegOpenKey','ReadProcessMemory','send','sendto','SetFilePointer','SetKeyboardState',
		'SetWindowsHook','ShellExecute','Sleep','socket','StartService','TerminateProcess','UnhandledExceptionFilter',
		'URLDownload','VirtualAlloc','VirtualFree','VirtualProtect','VirtualAllocEx','WinExec','WriteProcessMemory',
		'WriteFile','WSASend','WSASocket','WSAStartup','ZwQueryInformation,taskdl.exe','cmd.exe'
		]
		# find calls if existe in strings 
		x = self.ext_strings() 
		api_calls = list()
		for api_call in suspicious_apis:
			for i in x: 
				if api_call == i :
					api_calls.append(api_call)
					
		return api_calls

