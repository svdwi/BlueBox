# -*- coding: utf-8 -*-
import sys
from requests import session
from _config import GetConfig 

if sys.version_info.major < 3:
    from urlparse import urljoin
else:
    from urllib.parse import urljoin



#from hybridAnalysis import HybridAnalysis
#ha = HybridAnalysis('keyHYbrid')
#print(ha.search_hash('HashMalware'))

class HybridAnalysis(object):
    environments = {
    100: 'Windows 7 32 bit',
    110: 'Windows 7 32 bit (HWP Support)',
    120: 'Windows 7 64 bit',
    200: 'Android Static Analysis',
    300: 'Linux (Ubuntu 16.04, 64 bit)', }



    def __init__(self):
        self.__API__ = GetConfig().__api__("hybridanalysis")["URL"]
        self.api_key =  GetConfig().__api__("hybridanalysis")["KEY"]
        self.session = session()
        self.session.headers = {
        'api-key': self.api_key,
        'user-agent': "Falcon Sandbox"
        }




    def __sendRequest(self, method, uri_path_api, **kwargs):
        __response = self.session.request(method, urljoin(self.__API__, uri_path_api), **kwargs)
        __response.raise_for_status()
        if __response.headers['Content-Type'] == 'application/json':
            return __response.json()
        return __response.content




    #summary for given hash
    def search_hash(self, file_hash):
        return self.__sendRequest('POST', 'search/hash', data={'hash': file_hash})



    #summary for given hash
    def search_hashes(self, file_hashes):
        return self.__sendRequest('POST', 'search/hashes', data={'hashes[]': file_hashes})

    #search the database using the search terms
    def search_terms(self, terms):
        return self.__sendRequest('POST', 'search/terms', data=terms)

    """
        POST /submit​/url
        submit a websites url or url with file for analysis

        POST ​/submit​/url-to-file
        submit a file by url for analysis

        POST /submit​/url-for-analysis
        submit a url for analysis

        POST /submit​/hash-for-url
        determine a SHA256 that an online file or URL submission will have when being processed by the system. Note: this is useful when looking up URL analysis

        POST ​/submit​/dropped-file
        submit dropped file for analysis
    """

    def submit_file(self, environment_id, file_name, file_path, options=dict()):
        options.update({'environment_id': environment_id})
        return self.__sendRequest('POST', 'submit/file', data=options, files={'file': (file_name, open(file_path, 'rb'))})

    def submit_url_to_file(self, environment_id, url, options=dict()):
        options.update({'environment_id': environment_id, 'url': url})
        return self.__sendRequest('POST', 'submit/url-to-file', data=options)

    def submit_url_for_analysis(self, environment_id, url, options=dict()):
        options.update({'environment_id': environment_id, 'url': url})
        return self.__sendRequest('POST', 'submit/url-for-analysis', data=options)

    def submit_hash_for_url(self, url):
        return self.__sendRequest('POST', 'submit/hash-for-url', data={'url': url})

    def submit_dropped_file(self, report_id, file_hash, options=dict()):
        options.update({'id': report_id, 'file_hash': file_hash})
        return self.__sendRequest('POST', 'submit/dropped-file', data=options)





    """
        GET /quick-scan​/state
        return list of available scanners

        POST /quick-scan​/file
        submit a file for quick scan, you can check results in overview endpoint

        POST /quick-scan​/url
        submit a website's url or url with file for analysis


        GET /quick-scan​/{id}
        some scanners need time to process file, if in response `finished` is set to false, then you need use this endpoint to get final results

        POST /quick-scan​/{id}​/convert-to-full
        convert quick scan to sandbox report

    """

    def quick_scan_file(self, scan_type, file_name, file_path, options=dict()):
        options.update({'scan_type': scan_type})
        return self.__sendRequest('POST', 'quick-scan/file', data=options,
                                files={'file': (file_name, open(file_path, 'rb'))})

    def quick_scan_url_to_file(self, scan_type, url, options=dict()):
        options.update({'scan_type': scan_type, 'url': url})
        return self.__sendRequest('POST', 'quick-scan/url-to-file', data=options)

    def quick_scan_url_for_analysis(self, scan_type, url, options=dict()):
        options.update({'scan_type': scan_type, 'url': url})
        return self.__sendRequest('POST', 'quick-scan/url-for-analysis', data=options)


    def quick_scan_id_convert_to_full(self, environment_id, scan_id, options=dict()):
        options.update({'environment_id': environment_id})
        return self.__sendRequest('POST', 'quick-scan/{}/convert-to-full'.format(scan_id), data=options)

    def quick_scan_state(self):
        return self.__sendRequest('GET', 'quick-scan/state')

  
    def quick_scan_id(self, scan_id):
        return self.__sendRequest('GET', 'quick-scan/{}'.format(scan_id))




    """
    GET ​/overview​/{sha256}
    return overview for hash

    GET /overview​/{sha256}​/refresh
    refresh overview and download fresh data from external services

    GET /overview​/{sha256}​/summary
    return overview for hash

    GET /overview​/{sha256}​/sample
    downloading sample file

    """

    def overview_sha256(self, sha256):
        return self.__sendRequest('GET', 'overview/{}'.format(sha256))

    def overview_sha256_refresh(self, sha256):
        return self.__sendRequest('GET', 'overview/{}/refresh'.format(sha256))

    def overview_sha256_summary(self, sha256):
        return self.__sendRequest('GET', 'overview/{}/summary'.format(sha256))

    def overview_sha256_sample(self, sha256):
        return self.__sendRequest('GET', 'overview/{}/sample'.format(sha256))




    """

    GET​/report​/{id}​/certificate
    downloading certificate file from report (if available)

    GET/report​/{id}​/children
    returns children reports ids, once given id indicated archive or container file

    GET /report​/{id}​/memory-strings
    downloading all memory strings from report (if available)

    GET /report​/{id}​/pcap
    downloading network PCAP file from report (if available)

    GET /report​/{id}​/report​/{type}
    downloading report file (e.g. JSON, XML, HTML)

    GET /report​/{id}​/sample
    downloading sample file

    GET /report​/{id}​/state
    return state of a submission

    GET /report​/{id}​/summary
    return summary of a submission

    """



    def report_id_state(self, report_id):
        return self.__sendRequest('GET', 'report/{}/state'.format(report_id))

    def report_id_summary(self, report_id):
        return self.__sendRequest('GET', 'report/{}/summary'.format(report_id))

    def report_summary(self, report_ids):
        return self.__sendRequest('POST', 'report/summary', data={'hashes[]': report_ids})

    def report_id_file_type(self, report_id, file_type):
        return self.__sendRequest('GET', 'report/{}/file/{}'.format(report_id, file_type))

    def report_id_screenshots(self, report_id):
        return self.__sendRequest('GET', 'report/{}/screenshots'.format(report_id))

    def report_id_dropped_file_raw_hash(self, report_id, hash_file):
        return self.__sendRequest('GET', 'report/{}/dropped-file-raw/{}'.format(report_id, hash_file))

    def report_id_dropped_files(self, report_id):
        return self.__sendRequest('GET', 'report/{}/dropped-files'.format(report_id))


    """


    GET ​/system​/version
    return system elements versions

    GET /system​/environments
    return information about available execution environments

    GET /system​/action-scripts
    return information about available action scripts

    GET ​/system​/stats
    contains a variety of webservice statistics, e.g. the total number of submissions, unique submissions, signature ID distribution, user comments, etc.

    GET /system​/configuration
    a partial information about instance configuration

    GET /system​/queue-size
    return information about queue size

    GET /system​/total-submissions
    return total number of submission




    """



    def system_version(self):
        return self.__sendRequest('GET', 'system/version')

    def system_environments(self):
        return self.__sendRequest('GET', 'system/environments')

    def system_stats(self):
        return self.__sendRequest('GET', 'system/stats')

    def system_state(self):
        return self.__sendRequest('GET', 'system/state')

    def system_configuration(self):
        return self.__sendRequest('GET', 'system/configuration')

    def system_backend(self):
        return self.__sendRequest('GET', 'system/backend')

    def system_queue_size(self):
        return self.__sendRequest('GET', 'system/queue-size')

    def system_in_progress(self):
        return self.__sendRequest('GET', 'system/in-progress')

    def system_total_submissions(self):
        return self.__sendRequest('GET', 'system/total-submissions')

    def system_heartbeat(self):
        return self.__sendRequest('GET', 'system/heartbeat')





    def key_current(self):
        return self.__sendRequest('GET', 'key/current')

    def feed_latest(self):
        return self.__sendRequest('GET', 'feed/latest')



