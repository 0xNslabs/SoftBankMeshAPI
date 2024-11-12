# tr69.py
# @package   SoftBank Mesh API
# @author    Samy Younsi - NeroTeam Security Labs <samy@neroteam.com>
# @license   Proprietary License - All Rights Reserved
# @docs      https://neroteam.com/blog/softbank-wi-fi-mesh-rp562b

from zeep import Client
from zeep.transports import Transport
import requests
import socket
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


original_getaddrinfo = socket.getaddrinfo


def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host == "dl_meta_8080":
        host = "fota.sercomm.com"
    return original_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = custom_getaddrinfo

session = requests.Session()


class CustomHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        self.poolmanager = PoolManager(*args, **kwargs)


session.mount("http://", CustomHTTPAdapter())
session.mount("https://", CustomHTTPAdapter())

transport = Transport(session=session)

wsdl = "http://http-fota.softbank.smartgaiacloud.com/bms_iface?wsdl"

client = Client(wsdl=wsdl, transport=transport)

response = client.service.getDeviceModelList(beginId=0, maxCount=100)
# response = client.service.getAllKit(accountId=1)
print(response)

socket.getaddrinfo = original_getaddrinfo
