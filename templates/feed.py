import requests
import json

#curl -X POST https://threatfox-api.abuse.ch/api/v1/ -d '{ "query": "search_ioc", "search_term": "139.180.203.104" }'     
#post_data = f'{{ "query": "get_iocs", "days": 1 }}'
#post_data2 = f'{{ "query": "search_ioc", "search_term": "139.180.203.104" }}'
#{ "query": "malwareinfo", "malware": "Cobalt Strike", "limit": 10 }

"""


"ioc": "gaga.com",
"threat_type": "botnet_cc",
"threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
"ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
"malware": "win.dridex",
"malware_printable": "Dridex",
"malware_alias": null,
"confidence_level": 50,
"first_seen": "2020-12-08 13:36:27 UTC",
"tags": [
"exe",
"test"


"""

class ThreatFoxFeeds():

    def __init__(self):
        self.url = "https://threatfox-api.abuse.ch/api/v1/"



    def fetch_threatfox(self, time: int):
        """
            Query current IOC set from ThreatFox API
        """
        post_data = f'{{ "query": "get_iocs", "days": {time} }}'
        data = requests.post(self.url,post_data).content.decode('utf-8')
        tf_data = json.loads(data)['data']
        return tf_data
        
    def fetch_Malware(self, malware: str):
        """
        You can search for an IOC on ThreatFox API
        """
        post_data = f'{{ "query": "malwareinfo", "malware": "{malware}" , "limit": 10 }}'
        data = requests.post(self.url,post_data).content.decode('utf-8')
        tf_data = json.loads(data)['data']
        return tf_data
        
       
    def fetch_search(self, term :str):
        """
        IOC you want to search for	exemple : 94.103.84.81
        """
        post_data = f'{{ "query": "search_ioc", "search_term": "{term}" }}'
        print(post_data)
        data = requests.post(self.url,post_data).content.decode('utf-8')
        tf_data = json.loads(data)['data']
        return tf_data
                



 
"""
feed = ThreatFoxFeeds().fetch_Malware(1)
for i in range(len(feed)):
    print(feed[i]["id"]) 
    print(feed[i]["ioc"])
    print(feed[i]["malware"])

"""

#print(ThreatFoxFeeds().fetch_Malware("wannacry"))

