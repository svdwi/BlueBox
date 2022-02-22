import requests
import json
 

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
                

 