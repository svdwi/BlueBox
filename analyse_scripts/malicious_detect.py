""" extracting the features from the URL """ 

import re 
import whois 
#import urllib.request
from urlparse import urlparse
import requests
from bs4 import BeautifulSoup

class extract_data(): 
    
    def __init__(self, url):
        self.url = url


    # add Http to Url if ! Https 
    def urlTOhttp(self): 
        if not re.match(r"^https?", self.url):   
            self.url = "http://" + self.url
        return self.url 


    def returnDomain(self): 
       # parsed => scheme='http', netloc='hostname.com', path='/somethings/',
        parsed = urlparse(self.url)
        domain = parsed.netloc.split(".")
        #print (domain)
        return ".".join(domain)


    # check the library fo Requests all the information 
    # https://pypi.org/project/whois/
    def whois(self): 
        domain = self.returnDomain()
        print(domain)
        whois_response = domain = whois.query(domain)
        return whois_response.__dict__


    def length(self):
        if len(self.url) < 54:
          return "1"
        elif len(self.url) >= 54 and len(self.url) <= 75:
          return "0"
        else:
          return "-1"



    def ShortingSearch(self): 
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',self.url)
        result = '-1' if match  else '1'
        return result



    def symboles(self):
        result = '-1' if re.findall("@", self.url)   else '1'
        return result

    def prefixURL(self):
        result = "-1" if re.findall(r'https?://[^\-]+-[^\-]+/', self.url) else "1"
        return result

    #a = "neg" if b<0 else "pos" if b>0 else "zero"
    def subdomain(self):
        result = "1" if  len(re.findall("\.", self.url)) == 1 else "0" if len(re.findall("\.", self.url)) == 2 else "-1"
        return result

    # 9.Domain_registeration_length
    # 10.Favicon


    def portCheck(self):
        dom = self.returnDomain()
        if ":" in dom: 
            return '-1'
        else:
            return '1'

    def HttpsToken(self):
        result = "1" if re.findall(r"^https://", self.url) else "-1" 
        return result


    def GetResponse(self): 
        try:
            response = requests.get(self.url)
        except:
            response = ""
        return response



    def GetSoup(self):
        try:
            response = requests.get(self.url)
            print(response)
            soup = BeautifulSoup(response.text, 'html.parser')
        except:
            response = ""
            soup = -999
        return soup



    def SFH(self): 
        _soup_ = self.GetSoup()
        _domain_= self.returnDomain()

        #print(_soup_)
        for form in _soup_.find_all('form', action= True):
           if form['action'] =="" or form['action'] == "about:blank" :
              return '-1'
              break
           elif self.url  not in form['action'] and _domain_ not in form['action']:
               return '0'
               break
           else:
                return '1'
                break


    def AbnormalURL(self): 
        #idk but there some error when i test : response<200> & return -1 
        _response_ = self.GetResponse() 
        print(_response_)
        if _response_ == "":
            return "-1"
        else:
            if _response_.text == "":
                return "1"
            else:
                return "-1"

    def RedirectURL(self): 
        _response_ = self.GetResponse() 
        #print(_response_)
        if _response_ == "":
              return "-1"
        else:
            if len(_response_.history) <= 1:
                return "-1"
            elif len(_response_.history) <= 4:
                return "0"
            else:
                return "1"  

    def onmouseover(self):
        _response_ = self.GetResponse() 
        if _response_ == "" :
              return "-1"
        else:
            if re.findall("<script>.+onmouseover.+</script>", _response_.text) or re.findall("onmouseover", _response_.text) :
              return "1"
            else:
              return "-1"

    def Rightclick(self): 
        _response_ = self.GetResponse()
        #print(_response_.text) 
        if re.findall(r"event.button ?== ?2", _response_.text):
             return "1"
        else:
             return "-1"   
             
    def PopUpWindow(self): 
        _response_ = self.GetResponse()
        #print(_response_.text) 
        if re.findall(r"alert\(", _response_.text):
            return "1"
        else:
            return "-1"

    def Iframe(self): 
        _response_ = self.GetResponse()
        #print(_response_.text) 
        if re.findall(r"[<iframe>|<frameBorder>]", _response_.text):
            return "1"
        else:
            return "-1"


    #def AgeDomain(self):
        #_whois_ = self.whois()
        #print(_whois_)
       # date ="datetime.datetime(1997, 3, 29, 5, 0)"
      #  print re.findall(r"\D(\d{4})\D" , date)   '''

    
  #  def trafficRank(self): 
       # try:
       #     rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
        #    rank= int(rank)
       #     if (rank<100000):
       #          return "1"
       #     else:
       #          return "0"
      #  except TypeError:
        #    return "-1"

    def indexGoogle(self):
        site = search(self.url, 5)
        result = "1" if site else "-1"
        return result

