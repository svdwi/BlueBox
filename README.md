
# BlueBox Malware analysis Box and Cyber threat Hunting



<img src="images/logo_bluebox.png"  width=547 height=250 alt="BlueBox"/>


[![GitHub Repo stars](https://img.shields.io/github/stars/svdwi?style=social)](https://twitter.com/aziz_saadaoui)
[![Twitter Follow](https://img.shields.io/twitter/follow/aziz_saadaoui?style=social)](https://twitter.com/intel_owl)
[![Official Site](https://img.shields.io/badge/official-site-blue)](https://github.com/svdwi)


[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/svdwi)


# Description
 **threat intelligence data** about a malware, an IP or a domain , URL ? a Quick Analysis suspicious File or Malware ! 



# What is it?

BlueBox is an Open Source Intelligence, or OSINT solution to get threat intelligence data about a specific file, an IP or a domain ,Url and analyze them.


# How To Run !! 
First Change the `conf.py`  to receive authentication keys : 

    vim conf.py
    pip3 -r requements.txt
    pip3 -r req.txt #if there a issues in ssdeep
    python3 app.py 

## VIDEO USAGE

<a href="https://drive.google.com/file/d/1FxDkz2h4jldsEU8QTL0uFaJSZFSI8XZ-/preview" title="BlueBox Usage"><img src="images/bluebox.png" alt="Cyber threat Hunting & Malware Analysis" /></a>



## BlueBox Architecture
Blue
<img src="images/architecture.png"  alt="BlueBox"/>


### what is included ?? /Features

- Provides enrichment of threat intel for malware as well as observables (IP, Domain, URL and hash).
- This application is built to **scale out** and to **speed up the retrieval of threat info**.

-  built with Python3, Flask , js ,Bootstrap , SQLAlchemy ,Scikit-learn ,Json ,YARA Rules
-  Get threat intelligence data about a specific file, an IP or a domain,URL and Get latest Malware Ioc feeds from a single API at scale .
- Static Analysis File ( Hashes , suspicious Strings , import/Export Functions , Suspicious DLL used ).
- retrieve data from external sources (like VirusTotal).
- Detection Using YARA Rules ( crypto , packed , malware IOc )
- Detection URL,Phishing Website using Machine Learning Logistic regression .
- Checking URL,Domain External sources( Like VirusTotal).
- Extract Some Features (Lexical Features) to help detection malicious website .
- Real-time Latest ioc malware trending feeds .





