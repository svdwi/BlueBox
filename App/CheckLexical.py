import re
import whois
#import urllib.request
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup


class extract_data():

    def __init__(self, url):
        self.url = url


    def results(self):
        results ={}
        results ={
		"AbnormalURL": self.AbnormalURL(), 
        "RedirectURL": self.RedirectURL(), 
        "onmouseover": self.onmouseover(), 
        "Rightclick": self.Rightclick(), 
        "PopUpWindow": self.PopUpWindow(),
        "symboles": self.symboles(), 
        "prefixURL": self.prefixURL(), 
        "subdomain": self.subdomain(), 
        "portCheck": self.portCheck(),  
        "Iframe": self.Iframe(), 
        "urlTOhttp": self.urlTOhttp(), 
        "returnDomain": self.returnDomain(), 
        "whois": self.whois(), 
        "length": self.length(), 
        "ShortingSearch": self.ShortingSearch(), 
        "HttpsToken": self.HttpsToken(), 
        "SFH": self.SFH(), 
        }
        return results
		
    def urlTOhttp(self):
        if not re.match(r"^https?", self.url):
            self.url = "http://" + self.url
        return self.url

    def returnDomain(self):
        parsed = urlparse(self.url)
        domain = parsed.netloc.split(".")
        return ".".join(domain)

    # check the library fo Requests all the information
    # https://pypi.org/project/whois/

    def whois(self):
        domain = self.returnDomain()
        print(domain)
        whois_response = whois.whois(domain)
        return whois_response.__dict__

    def length(self):
        if len(self.url) < 54:
            return "True"
        elif len(self.url) >= 54 and len(self.url) <= 75:
            return "False"
        else:
            return Count(self.url)

    def ShortingSearch(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
		'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
		'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
		'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
		'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
		'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
		'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        result = 'False' if match else 'True'
        return result

    def symboles(self):
        result = 'False' if re.findall("@", self.url) else 'True'
        return result

    def prefixURL(self):
        result = "False" if re.findall(
            r'https?://[^\-]+-[^\-]+/', self.url) else "True"
        return result

    def subdomain(self):
        result = "True" if len(re.findall("\.", self.url)) == 1 else "False" if len(
            re.findall("\.", self.url)) == 2 else "False"
        return result

    def portCheck(self):
        dom = self.returnDomain()
        if ":" in dom:
            return 'False'
        else:
            return 'True'

    def HttpsToken(self):
        result = "True" if re.findall(r"^https://", self.url) else "False"
        return result

    def GetResponse(self):
        try:
            response = requests.get(self.url)
            print("------------------")
            print(response)
        except:
            response = ""
        return response

    def GetSoup(self):
        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
        except:
            response = ""
            soup = -999
        return soup

    def SFH(self):
        _soup_ = self.GetSoup()
        _domain_ = self.returnDomain()

        # print(_soup_)
        for form in _soup_.find_all('form', action=True):
            if form['action'] == "" or form['action'] == "about:blank":
                return 'False'
                break
            elif self.url not in form['action'] and _domain_ not in form['action']:
                return '0'
                break
            else:
                return 'True'
                break

    def AbnormalURL(self):
        # idk but there some error when i test : response<200> & return False
        _response_ = self.GetResponse()
        print(_response_)
        if _response_ == "":
            return "False"
        else:
            if _response_.text == "":
                return "True"
            else:
                return "False"

    def RedirectURL(self):
        _response_ = self.GetResponse()
        # print(_response_)
        if _response_ == "":
            return "False"
        else:
            if len(_response_.history) <= 1:
                return "False"
            elif len(_response_.history) <= 4:
                return "False"
            else:
                return "True"

    def onmouseover(self):
        _response_ = self.GetResponse()
        if _response_ == "":
            return "False"
        else:
            if re.findall("<script>.+onmouseover.+</script>", _response_.text) or re.findall("onmouseover", _response_.text):
                return "True"
            else:
                return "False"

    def Rightclick(self):
        _response_ = self.GetResponse()
        if re.findall(r"event.button ", _response_.text):
            return "True"
        else:
            return "False"

    def PopUpWindow(self):
        _response_ = self.GetResponse()
        if re.findall(r"alert\(", _response_.text):
            return "True"
        else:
            return "False"

    def Iframe(self):
        _response_ = self.GetResponse()
        if re.findall(r"[<iframe>|<frameBorder>]", _response_.text):
            return "True"
        else:
            return "False"


 