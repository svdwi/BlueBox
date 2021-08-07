import os 
import json



''' that script ,  just testing for filtring json response  from virustotal API :)) Don't touch it please  '''


#response = {u'scan_id': u'5291232b297dfcb56f88b020ec7b896728f139b98cef7ab33d4f84c85a06d553-1612533648', u'sha1': u'a4185032072a2ee7629c53bda54067e0022600f8', u'resource': u'829dde7015c32d7d77d8128665390dab', u'response_code': 1, u'scan_date': u'2021-02-05 14:00:48', u'permalink': u'https://www.virustotal.com/gui/file/5291232b297dfcb56f88b020ec7b896728f139b98cef7ab33d4f84c85a06d553/detection/f-5291232b297dfcb56f88b020ec7b896728f139b98cef7ab33d4f84c85a06d553-1612533648', u'verbose_msg': u'Scan finished, information embedded', u'sha256': u'5291232b297dfcb56f88b020ec7b896728f139b98cef7ab33d4f84c85a06d553', u'positives': 59, u'total': 70, u'md5': u'829dde7015c32d7d77d8128665390dab', u'scans': {u'Bkav': {u'detected': False, u'version': u'1.3.0.9899', u'result': None, u'update': u'20210205'}, u'Elastic': {u'detected': False, u'version': u'4.0.16', u'result': None, u'update': u'20210121'}, u'DrWeb': {u'detected': True, u'version': u'7.0.49.9080', u'result': u'Trojan.Encoder.304', u'update': u'20210205'}, u'ClamAV': {u'detected': False, u'version': u'0.103.1.0', u'result': None, u'update': u'20210205'}, u'CMC': {u'detected': False, u'version': u'2.10.2019.1', u'result': None, u'update': u'20210130'}, u'CAT-QuickHeal': {u'detected': False, u'version': u'14.00', u'result': None, u'update': u'20210205'}, u'Qihoo-360': {u'detected': True, u'version': u'1.0.0.1120', u'result': u'HEUR/Malware.QVM03.Gen', u'update': u'20210205'}, u'ALYac': {u'detected': True, u'version': u'1.1.3.1', u'result': u'Trojan.Ransom.CryptoLocker.C', u'update': u'20210205'}, u'Cylance': {u'detected': True, u'version': u'2.3.1.101', u'result': u'Unsafe', u'update': u'20210205'}, u'Zillya': {u'detected': True, u'version': u'2.0.0.4287', u'result': u'Trojan.Blocker.Win32.13918', u'update': u'20210205'}, u'AegisLab': {u'detected': True, u'version': u'4.2', u'result': u'Trojan.Win32.Blocker.j!c', u'update': u'20210205'}, u'Sangfor': {u'detected': True, u'version': u'1.0', u'result': u'Malware', u'update': u'20210204'}, u'CrowdStrike': {u'detected': True, u'version': u'1.0', u'result': u'win/malicious_confidence_100% (W)', u'update': u'20190702'}, u'BitDefender': {u'detected': True, u'version': u'7.2', u'result': u'Gen:Variant.Ransom.Blocker.3', u'update': u'20210205'}, u'K7GW': {u'detected': True, u'version': u'11.164.36368', u'result': u'Trojan ( 004ced761 )', u'update': u'20210205'}, u'K7AntiVirus': {u'detected': True, u'version': u'11.164.36370', u'result': u'Trojan ( 004ced761 )', u'update': u'20210205'}, u'Arcabit': {u'detected': True, u'version': u'1.0.0.881', u'result': u'Trojan.Ransom.Blocker.3', u'update': u'20210205'}, u'BitDefenderTheta': {u'detected': True, u'version': u'7.2.37796.0', u'result': u'Gen:NN.ZemsilF.34804.pm0@aSi5kfo', u'update': u'20210201'}, u'Cyren': {u'detected': True, u'version': u'6.3.0.2', u'result': u'W32/Ransom.JXIW-5701', u'update': u'20210205'}, u'Symantec': {u'detected': True, u'version': u'1.13.0.0', u'result': u'ML.Attribute.HighConfidence', u'update': u'20210205'}, u'ESET-NOD32': {u'detected': True, u'version': u'22763', u'result': u'MSIL/Filecoder.G', u'update': u'20210205'}, u'Zoner': {u'detected': False, u'version': u'0.0.0.0', u'result': None, u'update': u'20210205'}, u'TrendMicro-HouseCall': {u'detected': True, u'version': u'10.0.0.1040', u'result': u'TROJ_CRILOCK.CB', u'update': u'20210205'}, u'Paloalto': {u'detected': True, u'version': u'1.0', u'result': u'generic.ml', u'update': u'20210205'}, u'Cynet': {u'detected': True, u'version': u'4.0.0.25', u'result': u'Malicious (score: 100)', u'update': u'20210205'}, u'Kaspersky': {u'detected': True, u'version': u'15.0.1.13', u'result': u'Trojan-Ransom.Win32.Blocker.dmbt', u'update': u'20210205'}, u'Alibaba': {u'detected': True, u'version': u'0.3.0.5', u'result': u'Ransom:Win32/Blocker.93b5def2', u'update': u'20190527'}, u'NANO-Antivirus': {u'detected': True, u'version': u'1.0.146.25261', u'result': u'Trojan.Win32.Blocker.dvtmqg', u'update': u'20210205'}, u'ViRobot': {u'detected': False, u'version': u'2014.3.20.0', u'result': None, u'update': u'20210205'}, u'MicroWorld-eScan': {u'detected': True, u'version': u'14.0.409.0', u'result': u'Gen:Variant.Ransom.Blocker.3', u'update': u'20210205'}, u'Rising': {u'detected': True, u'version': u'25.0.0.26', u'result': u'Ransom.Blocker!8.12A (CLOUD)', u'update': u'20210205'}, u'Ad-Aware': {u'detected': True, u'version': u'3.0.16.117', u'result': u'Gen:Variant.Ransom.Blocker.3', u'update': u'20210205'}, u'Sophos': {u'detected': True, u'version': u'1.0.2.0', u'result': u'Mal/Generic-S + Troj/CRILOCK-D', u'update': u'20210205'}, u'Comodo': {u'detected': True, u'version': u'33237', u'result': u'Malware@#3fuy0p8uuoubu', u'update': u'20210205'}, u'F-Secure': {u'detected': True, u'version': u'12.0.86.52', u'result': u'Heuristic.HEUR/AGEN.1112933', u'update': u'20210205'}, u'Baidu': {u'detected': False, u'version': u'1.0.0.2', u'result': None, u'update': u'20190318'}, u'VIPRE': {u'detected': True, u'version': u'90190', u'result': u'Trojan.Win32.Generic!BT', u'update': u'20210205'}, u'TrendMicro': {u'detected': True, u'version': u'11.0.0.1006', u'result': u'TROJ_CRILOCK.CB', u'update': u'20210205'}, u'McAfee-GW-Edition': {u'detected': True, u'version': u'v2019.1.2+3728', u'result': u'Ransom-FHB!829DDE7015C3', u'update': u'20210204'}, u'FireEye': {u'detected': True, u'version': u'32.44.1.0', u'result': u'Generic.mg.829dde7015c32d7d', u'update': u'20210205'}, u'Emsisoft': {u'detected': True, u'version': u'2018.12.0.1641', u'result': u'Gen:Variant.Ransom.Blocker.3 (B)', u'update': u'20210205'}, u'Ikarus': {u'detected': True, u'version': u'0.1.5.2', u'result': u'Trojan-Ransom.Blocker', u'update': u'20210205'}, u'Jiangmin': {u'detected': True, u'version': u'16.0.100', u'result': u'Trojan/Blocker.jyk', u'update': u'20210204'}, u'Webroot': {u'detected': True, u'version': u'1.0.0.403', u'result': u'W32.Ransom.Blocker', u'update': u'20210205'}, u'Avira': {u'detected': True, u'version': u'8.3.3.10', u'result': u'HEUR/AGEN.1112933', u'update': u'20210205'}, u'Antiy-AVL': {u'detected': True, u'version': u'3.0.0.1', u'result': u'Trojan/MSIL.Packed.Confuser.P', u'update': u'20210205'}, u'Kingsoft': {u'detected': True, u'version': u'2017.9.26.565', u'result': u'Win32.Troj.Undef.(kcloud)', u'update': u'20210205'}, u'Gridinsoft': {u'detected': True, u'version': u'1.0.28.119', u'result': u'Ransom.Win32.Blocker.vb!s1', u'update': u'20210205'}, u'Microsoft': {u'detected': True, u'version': u'1.1.17800.5', u'result': u'Backdoor:Win32/Bladabindi!ml', u'update': u'20210205'}, u'SUPERAntiSpyware': {u'detected': True, u'version': u'5.6.0.1032', u'result': u'Trojan.Agent/Gen-Ransom', u'update': u'20210205'}, u'ZoneAlarm': {u'detected': True, u'version': u'1.0', u'result': u'Trojan-Ransom.Win32.Blocker.dmbt', u'update': u'20210205'}, u'GData': {u'detected': True, u'version': u'A:25.28543B:27.21851', u'result': u'Gen:Variant.Ransom.Blocker.3', u'update': u'20210205'}, u'TACHYON': {u'detected': False, u'version': u'2021-02-05.02', u'result': None, u'update': u'20210205'}, u'AhnLab-V3': {u'detected': True, u'version': u'3.19.4.10106', u'result': u'Trojan/Win32.Blocker.R185819', u'update': u'20210205'}, u'Acronis': {u'detected': False, u'version': u'1.1.1.80', u'result': None, u'update': u'20201023'}, u'McAfee': {u'detected': True, u'version': u'6.0.6.653', u'result': u'Ransom-FHB!829DDE7015C3', u'update': u'20210205'}, u'MAX': {u'detected': True, u'version': u'2019.9.16.1', u'result': u'malware (ai score=100)', u'update': u'20210205'}, u'VBA32': {u'detected': True, u'version': u'4.4.1', u'result': u'Hoax.Blocker', u'update': u'20210205'}, u'Malwarebytes': {u'detected': True, u'version': u'4.2.1.18', u'result': u'Trojan.CryptoLocker', u'update': u'20210205'}, u'Panda': {u'detected': True, u'version': u'4.6.4.2', u'result': u'Trj/CI.A', u'update': u'20210205'}, u'APEX': {u'detected': True, u'version': u'6.128', u'result': u'Malicious', u'update': u'20210204'}, u'Tencent': {u'detected': True, u'version': u'1.0.0.1', u'result': u'Malware.Win32.Gencirc.11498c8e', u'update': u'20210205'}, u'Yandex': {u'detected': True, u'version': u'5.5.2.24', u'result': u'Trojan.Blocker!6OL9shngGUw', u'update': u'20210205'}, u'SentinelOne': {u'detected': True, u'version': u'5.0.0.9', u'result': u'Static AI - Suspicious PE', u'update': u'20210131'}, u'eGambit': {u'detected': True, u'version': None, u'result': u'Generic.Malware', u'update': u'20210205'}, u'Fortinet': {u'detected': True, u'version': u'6.2.142.0', u'result': u'MSIL/Generic.DN.494FBF!tr', u'update': u'20210205'}, u'AVG': {u'detected': True, u'version': u'21.1.5827.0', u'result': u'Win32:Trojan-gen', u'update': u'20210205'}, u'Cybereason': {u'detected': True, u'version': u'1.2.449', u'result': u'malicious.015c32', u'update': u'20210106'}, u'Avast': {u'detected': True, u'version': u'21.1.5827.0', u'result': u'Win32:Trojan-gen', u'update': u'20210205'}, u'MaxSecure': {u'detected': False, u'version': u'1.0.0.1', u'result': None, u'update': u'20201212'}}}
response = {'ADMINUSLabs': {'detected': False, 'result': 'clean site'},
 'AICC (MONITORAPP)': {'detected': False, 'result': 'clean site'},
 'AegisLab WebGuard': {'detected': False, 'result': 'clean site'},
 'AlienVault': {'detected': False, 'result': 'clean site'},
 'Antiy-AVL': {'detected': False, 'result': 'clean site'},
 'Armis': {'detected': False, 'result': 'clean site'},
 'Artists Against 419': {'detected': False, 'result': 'clean site'},
 'AutoShun': {'detected': False, 'result': 'unrated site'},
 'Avira': {'detected': False, 'result': 'clean site'},
 'BADWARE.INFO': {'detected': False, 'result': 'clean site'},
 'Baidu-International': {'detected': False, 'result': 'clean site'},
 'Bfore.Ai PreCrime': {'detected': False, 'result': 'clean site'},
 'BitDefender': {'detected': False, 'result': 'clean site'},
 'BlockList': {'detected': False, 'result': 'clean site'},
 'Blueliv': {'detected': False, 'result': 'clean site'},
 'CINS Army': {'detected': False, 'result': 'clean site'},
 'CLEAN MX': {'detected': False, 'result': 'clean site'},
 'CMC Threat Intelligence': {'detected': False, 'result': 'clean site'},
 'CRDF': {'detected': False, 'result': 'clean site'},
 'Certego': {'detected': False, 'result': 'clean site'},
 'Cisco Talos IP Blacklist': {'detected': False, 'result': 'clean site'},
 'Comodo Valkyrie Verdict': {'detected': False, 'result': 'clean site'},
 'CyRadar': {'detected': False, 'result': 'clean site'},
 'Cyan': {'detected': False, 'result': 'unrated site'},
 'CyberCrime': {'detected': False, 'result': 'clean site'},
 'Cyren': {'detected': False, 'result': 'clean site'},
 'DNS8': {'detected': False, 'result': 'clean site'},
 'Dr.Web': {'detected': False, 'result': 'clean site'},
 'ESET': {'detected': False, 'result': 'clean site'},
 'EmergingThreats': {'detected': False, 'result': 'clean site'},
 'Emsisoft': {'detected': False, 'result': 'clean site'},
 'EonScope': {'detected': False, 'result': 'clean site'},
 'Feodo Tracker': {'detected': False, 'result': 'clean site'},
 'Forcepoint ThreatSeeker': {'detected': False, 'result': 'clean site'},
 'Fortinet': {'detected': False, 'result': 'clean site'},
 'FraudScore': {'detected': False, 'result': 'clean site'},
 'G-Data': {'detected': False, 'result': 'clean site'},
 'Google Safebrowsing': {'detected': False, 'result': 'clean site'},
 'GreenSnow': {'detected': False, 'result': 'clean site'},
 'Hoplite Industries': {'detected': False, 'result': 'clean site'},
 'IPsum': {'detected': False, 'result': 'clean site'},
 'K7AntiVirus': {'detected': False, 'result': 'clean site'},
 'Kaspersky': {'detected': False, 'result': 'clean site'},
 'Lumu': {'detected': False, 'result': 'unrated site'},
 'MalBeacon': {'detected': False, 'result': 'clean site'},
 'MalSilo': {'detected': False, 'result': 'clean site'},
 'Malware Domain Blocklist': {'detected': False, 'result': 'clean site'},
 'MalwareDomainList': {'detail': 'http://www.malwaredomainlist.com/mdl.php?search=facebook.com',
                       'detected': False,
                       'result': 'clean site'},
 'MalwarePatrol': {'detected': False, 'result': 'clean site'},
 'Malwared': {'detected': False, 'result': 'clean site'},
 'Netcraft': {'detected': False, 'result': 'unrated site'},
 'NotMining': {'detected': False, 'result': 'unrated site'},
 'Nucleon': {'detected': False, 'result': 'clean site'},
 'OpenPhish': {'detected': False, 'result': 'clean site'},
 'PREBYTES': {'detected': False, 'result': 'clean site'},
 'PhishLabs': {'detected': False, 'result': 'clean site'},
 'Phishing Database': {'detected': False, 'result': 'clean site'},
 'Phishtank': {'detected': False, 'result': 'clean site'},
 'Quick Heal': {'detected': False, 'result': 'clean site'},
 'Quttera': {'detected': False, 'result': 'clean site'},
 'Rising': {'detected': False, 'result': 'clean site'},
 'SCUMWARE.org': {'detected': False, 'result': 'clean site'},
 'Sangfor': {'detected': False, 'result': 'clean site'},
 'Scantitan': {'detected': False, 'result': 'clean site'},
 'SecureBrain': {'detected': False, 'result': 'clean site'},
 'Sophos': {'detected': False, 'result': 'clean site'},
 'Spam404': {'detected': False, 'result': 'clean site'},
 'Spamhaus': {'detected': False, 'result': 'clean site'},
 'StopBadware': {'detected': False, 'result': 'unrated site'},
 'StopForumSpam': {'detected': False, 'result': 'clean site'},
 'Sucuri SiteCheck': {'detected': False, 'result': 'clean site'},
 'Tencent': {'detected': False, 'result': 'clean site'},
 'ThreatHive': {'detected': False, 'result': 'clean site'},
 'Threatsourcing': {'detected': False, 'result': 'clean site'},
 'Trustwave': {'detected': False, 'result': 'clean site'},
 'URLhaus': {'detected': False, 'result': 'clean site'},
 'VX Vault': {'detected': False, 'result': 'clean site'},
 'Virusdie External Site Scan': {'detected': False, 'result': 'clean site'},
 'Web Security Guard': {'detected': False, 'result': 'clean site'},
 'Webroot': {'detected': False, 'result': 'clean site'},
 'Yandex Safebrowsing': {'detail': 'http://yandex.com/infected?l10n=en&url=http://facebook.com/',
                         'detected': False,
                         'result': 'clean site'},
 'ZeroCERT': {'detected': False, 'result': 'clean site'},
 'alphaMountain.ai': {'detected': False, 'result': 'clean site'},
 'benkow.cc': {'detected': False, 'result': 'clean site'},
 'desenmascara.me': {'detected': False, 'result': 'clean site'},
 'malwares.com URL checker': {'detected': False, 'result': 'clean site'},
 'securolytics': {'detected': False, 'result': 'clean site'},
 'zvelo': {'detected': False, 'result': 'clean site'}
}


#print(response["scans"])
for a , b in response.items():
	k = a , b["result"], b["detected"]
	print(k)


 

#print(json.dumps(imp))
