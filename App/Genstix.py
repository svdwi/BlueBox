from stix.core import STIXPackage
from stix.indicator import Indicator
from cybox.objects.uri_object import URI


#unifinished Class


class StixUrllMalicious():

    def __init__(self,is_dll):
        self.pkg = STIXPackage()
        self.indicator = Indicator()
        self.indicator.id_ = id  
        self.indicator.title = "Malicious site hosting downloader"
        self.indicator.add_indicator_type("URL Watchlist")

        self.url = URI()
        self.url.value = "http://x4z9arb.cn/4712"
        self.url.type_ = URI.TYPE_URL
        self.url.value.condition = "Equals"

        self.indicator.add_observable(self.url)

        self.pkg.add_indicator(self.indicator)

        print(self.pkg.to_xml(encoding=None))


