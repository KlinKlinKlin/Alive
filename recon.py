# from prefect.run_configs import LocalRun
# from prefect import Flow , task 
# from prefect.engine.executors import LocalDaskExecutor

import subprocess , shlex , json , os  , random , string , tld
from datetime import datetime
from colorslogging import *
from functools import wraps
from pprint import pprint
from io import StringIO
from IPy import IP

from collections import Counter
NUM_COUNT = 4

from ipaddress import IPv4Address, ip_address
from socket import gethostbyname
from urllib.parse import urlparse
from dns.resolver import Resolver
from tldextract import extract
from sys import argv
import sys , time, re  ,json , ipaddress , ctypes
import sqlite3,logging,io,socket,struct ,threading,random , requests ,ssl,json,time,random,urllib3,copy
from pprint import pprint
from requests.adapters import HTTPAdapter
from multiprocessing.dummy import Pool

from pymongo import MongoClient
from pymongo import errors as PymongoErrors
from urllib.parse import quote


def import_env(Key):
    if not os.path.exists('.env'):
        logger.error('no .env ')
        sys.exit()
    for line in open('.env'):
        var = line.strip().split('=')
        if len(var) == 2:
            key, value = var[0].strip(), var[1].strip()
            os.environ[key] = value
    return os.environ.get(Key , '')
    # return col

def init_mongo():
    """ @return mongodb col
    """
    client = MongoClient(f'mongodb://{import_env("mongo_username")}:{quote(import_env("mongo_password"))}@{import_env("mongo_ip")}:{import_env("mongo_port")}/?authSource=admin')
    db = client[import_env("mongo_db")]
    col = db[import_env("db_col")]
    return col

def insert_mongo(data , col):
    """ @input:data
        @input:col : mongodb col
    """
    if isinstance(data , list):
        col.insert_many(data)
        logger.info(f'mongo insert num:{str(len(data))}')
    elif isinstance(data , dict):
        col.insert_one(data)
        logger.info(f'mongo insert num:{str(len(data))}')

class AttribDict(dict):
    """
    This class defines the dictionary with added capability to access members as attributes
    """

    def __init__(self, indict=None, attribute=None):
        if indict is None:
            indict = {}

        # Set any attributes here - before initialisation
        # these remain as normal attributes
        self.attribute = attribute
        dict.__init__(self, indict)
        self.__initialised = True

        # After initialisation, setting attributes
        # is the same as setting an item

    def __getattr__(self, item):
        """
        Maps values to attributes
        Only called if there *is NOT* an attribute with this name
        """

        try:
            return self.__getitem__(item)
        except KeyError:
            raise AttributeError("unable to access item '%s'" % item)

    def __setattr__(self, item, value):
        """
        Maps attributes to values
        Only if we are initialised
        """

        # This test allows attributes to be set in the __init__ method
        if "_AttribDict__initialised" not in self.__dict__:
            return dict.__setattr__(self, item, value)

        # Any normal attributes are handled normally
        elif item in self.__dict__:
            dict.__setattr__(self, item, value)

        else:
            self.__setitem__(item, value)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __deepcopy__(self, memo):
        retVal = self.__class__()
        memo[id(self)] = retVal

        for attr in dir(self):
            if not attr.startswith('_'):
                value = getattr(self, attr)
                if not isinstance(value, (types.BuiltinFunctionType, types.FunctionType, types.MethodType)):
                    setattr(retVal, attr, copy.deepcopy(value, memo))

        for key, value in self.items():
            retVal.__setitem__(key, copy.deepcopy(value, memo))

        return retVal

class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                            maxsize=maxsize,
                            block=block,
                            ssl_version=ssl.PROTOCOL_TLSv1_2)

class webInfo(threading.Thread):
    __slots__ = ('headers' , 'WebInfos' , '_ssl_error' , 'url','rex' , 'WebInfos' , 'OutInfos' )
    """ 
    run with cms
    modify with Glass  
    """
    def __init__(self, url):
        # glass.py 规则
        self.ruleDatas = [['Shiro', 'headers', '(=deleteMe|rememberMe=)'],['Portainer(Docker管理)', 'code', '(portainer.updatePassword|portainer.init.admin)'],['Gogs简易Git服务', 'cookie', '(i_like_gogs)'],['Gitea简易Git服务', 'cookie', '(i_like_gitea)'],['宝塔-BT.cn', 'code', '(app.bt.cn/static/app.png|安全入口校验失败)'],['Nexus', 'code', '(Nexus Repository Manager)'],['Nexus', 'cookie', '(NX-ANTI-CSRF-TOKEN)'],['Harbor', 'code', '(<title>Harbor</title>)'],['Harbor', 'cookie', '(harbor-lang)'],['禅道', 'code', '(/theme/default/images/main/zt-logo.png)'],['禅道', 'cookie', '(zentaosid)'],['协众OA', 'code', '(Powered by 协众OA)'],['协众OA', 'cookie', '(CNOAOASESSID)'],['xxl-job', 'code', '(分布式任务调度平台XXL-JOB)'],['atmail-WebMail', 'cookie', '(atmail6)'],['atmail-WebMail', 'code', '(Powered by Atmail)'],['atmail-WebMail', 'code', '(/index.php/mail/auth/processlogin)'],['weblogic', 'code',    '(/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png|Welcome to Weblogic Application Server|<i>Hypertext Transfer Protocol -- HTTP/1.1</i>)'],['用友致远oa', 'code', '(/seeyon/USER-DATA/IMAGES/LOGIN/login.gif)'],['Typecho', 'code', '(Typecho</a>)'],['金蝶EAS', 'code', '(easSessionId)'],['phpMyAdmin', 'cookie', '(pma_lang|phpMyAdmin)'],['phpMyAdmin', 'code', '(/themes/pmahomme/img/logo_right.png)'],['H3C-AM8000', 'code', '(AM8000)'],['360企业版', 'code', '(360EntWebAdminMD5Secret)'],['H3C公司产品', 'code', '(service@h3c.com)'],['H3C ICG 1000', 'code', '(ICG 1000系统管理)'],['Citrix-Metaframe', 'code', '(window.location=\\"/Citrix/MetaFrame)'],['H3C ER5100', 'code', '(ER5100系统管理)'],['阿里云CDN', 'code', '(cdn.aliyuncs.com)'],['CISCO_EPC3925', 'code', '(Docsis_system)'],['CISCO ASR', 'code', '(CISCO ASR)'],['H3C ER3200', 'code', '(ER3200系统管理)'],['万户ezOFFICE', 'headers', '(LocLan)'],['万户网络', 'code', '(css/css_whir.css)'],['Spark_Master', 'code', '(Spark Master at)'],['华为_HUAWEI_SRG2220', 'code', '(HUAWEI SRG2220)'],['蓝凌EIS智慧协同平台', 'code', '(/scripts/jquery.landray.common.js)'],['深信服ssl-vpn', 'code', '(login_psw.csp)'],['华为 NetOpen', 'code', '(/netopen/theme/css/inFrame.css)'],['Citrix-Web-PN-Server', 'code', '(Citrix Web PN Server)'],['juniper_vpn', 'code',    '(welcome.cgi\\?p=logo|/images/logo_juniper_reversed.gif)'],['360主机卫士', 'headers', '(zhuji.360.cn)'],['Nagios', 'headers', '(Nagios Access)'],['H3C ER8300', 'code', '(ER8300系统管理)'],['Citrix-Access-Gateway', 'code', '(Citrix Access Gateway)'],['华为 MCU', 'code', '(McuR5-min.js)'],['TP-LINK Wireless WDR3600', 'code', '(TP-LINK Wireless WDR3600)'],['泛微协同办公OA', 'headers', '(ecology_JSessionid)'],['华为_HUAWEI_ASG2050', 'code', '(HUAWEI ASG2050)'],['360网站卫士', 'code', '(360wzb)'],['Citrix-XenServer', 'code', '(Citrix Systems, Inc. XenServer)'],['H3C ER2100V2', 'code', '(ER2100V2系统管理)'],['zabbix', 'cookie', '(zbx_sessionid)'],['zabbix', 'code', '(images/general/zabbix.ico|Zabbix SIA)'],['CISCO_VPN', 'headers', '(webvpn)'],['360站长平台', 'code', '(360-site-verification)'],['H3C ER3108GW', 'code', '(ER3108GW系统管理)'],['o2security_vpn', 'headers', '(client_param=install_active)'],['H3C ER3260G2', 'code', '(ER3260G2系统管理)'],['H3C ICG1000', 'code', '(ICG1000系统管理)'],['CISCO-CX20', 'code', '(CISCO-CX20)'],['H3C ER5200', 'code', '(ER5200系统管理)'],['linksys-vpn-bragap14-parintins', 'code',    '(linksys-vpn-bragap14-parintins)'],['360网站卫士常用前端公共库', 'code', '(libs.useso.com)'],['H3C ER3100', 'code', '(ER3100系统管理)'],['H3C-SecBlade-FireWall', 'code', '(js/MulPlatAPI.js)'],['360webfacil_360WebManager', 'code', '(publico/template/)'],['Citrix_Netscaler', 'code', '(ns_af)'],['H3C ER6300G2', 'code', '(ER6300G2系统管理)'],['H3C ER3260', 'code', '(ER3260系统管理)'],['华为_HUAWEI_SRG3250', 'code', '(HUAWEI SRG3250)'],['exchange', 'code', '(/owa/auth.owa)'],['Spark_Worker', 'code', '(Spark Worker at)'],['H3C ER3108G', 'code', '(ER3108G系统管理)'],['深信服防火墙类产品', 'code', '(SANGFOR FW)'],['Citrix-ConfProxy', 'code', '(confproxy)'],['360网站安全检测', 'code', '(webscan.360.cn/status/pai/hash)'],['H3C ER5200G2', 'code', '(ER5200G2系统管理)'],['华为（HUAWEI）安全设备', 'code', '(sweb-lib/resource/)'],['H3C ER6300', 'code', '(ER6300系统管理)'],['华为_HUAWEI_ASG2100', 'code', '(HUAWEI ASG2100)'],['TP-Link 3600 DD-WRT', 'code', '(TP-Link 3600 DD-WRT)'],['NETGEAR WNDR3600', 'code', '(NETGEAR WNDR3600)'],['H3C ER2100', 'code', '(ER2100系统管理)'],['绿盟下一代防火墙', 'code', '(NSFOCUS NF)'],['jira', 'code', '(jira.webresources)'],['金和协同管理平台', 'code', '(金和协同管理平台)'],['Citrix-NetScaler', 'code', '(NS-CACHE)'],['linksys-vpn', 'headers', '(linksys-vpn)'],['通达OA', 'code', '(/static/images/tongda.ico)'],['华为（HUAWEI）Secoway设备', 'code', '(Secoway)'],['华为_HUAWEI_SRG1220', 'code', '(HUAWEI SRG1220)'],['H3C ER2100n', 'code', '(ER2100n系统管理)'],['H3C ER8300G2', 'code', '(ER8300G2系统管理)'],['金蝶政务GSiS', 'code', '(/kdgs/script/kdgs.js)'],['Jboss', 'code', '(Welcome to JBoss|jboss.css)'],['Jboss', 'headers', '(JBoss)'], ]

        super(webInfo, self).__init__()
        self.headers = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
                "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; InfoPath.3; rv:11.0) like Gecko",
                "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
                "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
                "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
                "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; en) Presto/2.8.131 Version/11.11",
                "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Maxthon 2.0)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; TencentTraveler 4.0)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SE 2.X MetaSr 1.0; SE 2.X MetaSr 1.0; .NET CLR 2.0.50727; SE 2.X MetaSr 1.0)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser)",
                "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
                "Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
                "Mozilla/5.0 (iPod; U; CPU iPhone OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
                "Mozilla/5.0 (iPad; U; CPU OS 4_3_3 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8J2 Safari/6533.18.5",
                "Mozilla/5.0 (Linux; U; Android 2.3.7; en-us; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
                "MQQBrowser/26 Mozilla/5.0 (Linux; U; Android 2.3.7; zh-cn; MB200 Build/GRJ22; CyanogenMod-7) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
                "Opera/9.80 (Android 2.3.4; Linux; Opera Mobi/build-1107180945; U; en-GB) Presto/2.8.149 Version/11.10",
                "Mozilla/5.0 (Linux; U; Android 3.0; en-us; Xoom Build/HRI39) AppleWebKit/534.13 (KHTML, like Gecko) Version/4.0 Safari/534.13",
                "Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; en) AppleWebKit/534.1+ (KHTML, like Gecko) Version/6.0.0.337 Mobile Safari/534.1+",
                "Mozilla/5.0 (hp-tablet; Linux; hpwOS/3.0.0; U; en-US) AppleWebKit/534.6 (KHTML, like Gecko) wOSBrowser/233.70 Safari/534.6 TouchPad/1.0",
                "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/20.0.019; Profile/MIDP-2.1 Configuration/CLDC-1.1) AppleWebKit/525 (KHTML, like Gecko) BrowserNG/7.1.18124",
                "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0; HTC; Titan)",
                "UCWEB7.0.2.37/28/999",
                "NOKIA5700/ UCWEB7.0.2.37/28/999",
                "Openwave/ UCWEB7.0.2.37/28/999",
                "Mozilla/4.0 (compatible; MSIE 6.0; ) Opera/UCWEB7.0.2.37/28/999",
                "Mozilla/6.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/8.0 Mobile/10A5376e Safari/8536.25",
            ]),
        }
        self.url = url
        # self.sem = sem
        self.WebInfos = AttribDict()
        self.WebInfos = {}
        self.rex = re.compile('<title>(.*?)</title>')
        self._ssl_error = []
        self.OutInfos = AttribDict()
        self.OutInfos = {}
        self.grab_webinfo()
        self.grab_ruleinfo()

    def grab_ruleinfo(self):
        for rule in self.ruleDatas:
            cms = rule[0]
            rulesRegex = rule[2]
            if 'headers' == rule[1]:
                self.heads(rulesRegex, cms)
            elif 'cookie' == rule[1]:
                self.cookieInfo(rulesRegex, cms)
            else:
                self.bodys(rulesRegex, cms)
        webTitle = ""
        webServer = ""
        webCms = "None"
        for key in self.WebInfos:
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            self.OutInfos[key] = [webCms, webServer, self.WebInfos[key][2], webTitle , len(self.WebInfos[key][1]) , self.WebInfos[key][4]]
            # logger.success("{} {} {} {}".format(mkPut.green(webServer), mkPut.yellow(
            #     WebInfos[key][2]), key, mkPut.blue(webTitle)))

    def heads(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            for head in self.WebInfos[key][0]:
                resHeads = re.findall(rulesRegex, self.WebInfos[key][0][head])
                if resHeads:
                    # logger.success("{} {} {} {} {}".format(mkPut.red(cms), mkPut.green(
                    #     webServer), mkPut.yellow(WebInfos[key][2]), key, mkPut.blue(webTitle)))
                    self.OutInfos[key] = [cms, webServer, self.WebInfos[key][2], webTitle , len(self.WebInfos[key][1]) , self.WebInfos[key][4]]
                    self.WebInfos.pop(key)
                    break

    def bodys(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            resCodes = re.findall(rulesRegex, self.WebInfos[key][1])
            if resCodes:
                # logger.success("{} {} {} {} {}".format(mkPut.red(cms), mkPut.green(
                #     webServer), mkPut.yellow(WebInfos[key][2]), key, mkPut.blue(webTitle)))
                self.OutInfos[key] = [cms, webServer, self.WebInfos[key][2], webTitle , len(self.WebInfos[key][1]) , self.WebInfos[key][4]]
                self.WebInfos.pop(key)
                break

    def cookieInfo(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            for cookie in self.WebInfos[key][3]:
                resCookies = re.findall(rulesRegex, cookie)
                if resCookies:
                    # logger.success("{} {} {} {} {}".format(mkPut.red(cms), mkPut.green(
                    #     webServer), mkPut.yellow(WebInfos[key][2]), key, mkPut.blue(webTitle)))
                    """ cms server status_code title len()  """
                    self.OutInfos[key] = [cms, webServer, self.WebInfos[key][2], webTitle , len(self.WebInfos[key][1]) , self.WebInfos[key][4]]
                    self.WebInfos.pop(key)
                    break

    # def get_detail(self,_req):
    #     try:
    #         text_len = str(len(_req.text))
    #         title = re.findall(r"<title>(.*)</title>" , _req.text)
    #         server = _req.headers['server']
    #         title = title[0] if len(title) != 0 else 'None'
    #         server = server if server is not None else 'None'
    #         return (_req.status_code  , text_len , server  , title , _req.url)
    #     except Exception as e:
    #         # print(re.findall(r"<title>(.*)</title>" , _req.text))
    #         pass

    def get_cert(self,_req):
        """ ssl _req """
        try:
            _pool = _req.connection.poolmanager.connection_from_url(_req.url)
            _conn = _pool.pool.get()
            _pool.pool.put(_conn)
            if _conn is None or _conn.sock is None:
                return 'None'
            cert = _conn.sock.getpeercert()
            issuer = cert
            return issuer
        except Exception as e:
            sys.stderr.write(f"{e}\n")

    def ssl2_req(self,target):
        try:
            s = requests.Session()
            s.mount('https://', MyAdapter())
            _req = s.get(target , headers = self.headers , verify = True)
            issuer = self.get_cert(_req)
            sys.stderr.write(f'{target}\n')
            # print({'https':self.get_detail(_req) , 'cert_detail':self.get_cert(_req)})
            # print({ 'cert_detail':self.get_cert(_req)})
            return _req , self.get_cert(_req)
        except requests.exceptions.SSLError as e:
            try:
                _req = s.get(target , headers = self.headers , verify = False)
                issuer = self.get_cert(_req)
                sys.stderr.write(f'{target}\n')
                # print({'https':self.get_detail(_req) , 'cert_detail':self.get_cert(_req)})
                # print({ 'cert_detail':self.get_cert(_req)})
                return _req , self.get_cert(_req)
            except Exception as e2:
                # sys.stderr.write(f'{e2}\n')
                pass
        except Exception as e1:
            # sys.stderr.write(f'{e1}\n')
            pass

    def grab_webinfo(self):
        url = self.url
        s = requests.Session()
        s.keep_alive = False
        s.headers = self.headers
        # s.mount("http://", HTTPAdapter(max_retries=3))
        # s.mount("https://", HTTPAdapter(max_retries=3))
        # s.verify = False
        shiroCookie = {'rememberMe': '1'}
        s.cookies.update(shiroCookie)
        try:

            if not self.url.startswith('https'):
                s.verify = False
                req = s.get(self.url , timeout = 5)
                issuer = "None"
            else:
                try:
                    try:
                        req = s.get(self.url , timeout = 5)
                        issuer = self.get_cert(req)
                    except requests.exceptions.SSLError as e_:
                        
                        req , issuer = self.ssl2_req(self.url)
                except Exception as e__:
                    s.verify = False
                    req = s.get(self.url , timeout = 5)
                    issuer = 'None'

            # req = s.get(self.url, timeout=5)
            webHeaders = req.headers
            try:
                webCodes = req.content.decode('utf-8')
            except UnicodeDecodeError:
                webCodes = req.content.decode('gbk', 'ignore')
            # WebInfos[url] = webHeaders, webCodes, req.status_code, req.cookies.get_dict()
            # self.WebInfos.append(req.status_code , len(req.content) , title , webHeaders,  req.cookies.get_dict() , Body  )
            self.WebInfos[url] =  ( webHeaders , webCodes , req.status_code , req.cookies.get_dict() , issuer)
            req.close()
            # logging.info("命中{0}个链接".format(len(self.WebInfos)))
        except requests.exceptions.ReadTimeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.ChunkedEncodingError:
            pass
        except KeyboardInterrupt:
            pass

class DnsGen():
    def __init__(self, subdomains, words, base_domain = None):
        self.subdomains = subdomains
        self.base_domain = base_domain
        self.words = words

    def partiate_domain(self, domain):
        '''
        Split domain base on subdomain levels.
        TLD is taken as one part, regardless of its levels (.co.uk, .com, ...)
        '''

        # test.1.foo.example.com -> [test, 1, foo, example.com]
        # test.2.foo.example.com.cn -> [test, 2, foo, example.com.cn]
        # test.example.co.uk -> [test, example.co.uk]
        if self.base_domain:
            subdomain = re.sub(re.escape("." + self.base_domain) + "$", '', domain)
            return subdomain.split(".") + [self.base_domain]

        ext = tld.get_tld(domain.lower(), fail_silently=True, as_object=True, fix_protocol=True)
        base_domain = "{}.{}".format(ext.domain, ext.suffix)

        parts = (ext.subdomain.split('.') + [base_domain])

        return [p for p in parts if p]

    def insert_word_every_index(self, parts):
        '''
        Create new subdomain levels by inserting the words between existing levels
        '''

        # test.1.foo.example.com -> WORD.test.1.foo.example.com, test.WORD.1.foo.example.com,
        #                           test.1.WORD.foo.example.com, test.1.foo.WORD.example.com, ...

        domains = []

        for w in self.words:
            for i in range(len(parts)):
                tmp_parts = parts[:-1]
                tmp_parts.insert(i, w)
                domains.append('{}.{}'.format('.'.join(tmp_parts), parts[-1]))

        return domains

    def insert_num_every_index(self, parts):
        '''
        Create new subdomain levels by inserting the numbers between existing levels
        '''

        # foo.test.example.com ->   foo1.test.example.com, foo.test1.example.com,
        #                            ...

        domains = []

        for num in range(NUM_COUNT):
            for i in range(len(parts[:-1])):
                if num == 0:
                    continue
                # single digit
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}{}'.format(tmp_parts[i], num)
                domains.append('{}.{}'.format('.'.join(tmp_parts), '.'.join(parts[-1:])))

        return domains

    def prepend_word_every_index(self, parts):
        '''
        On every subdomain level, prepend existing content with `WORD` and `WORD-`
        '''

        # test.1.foo.example.com -> WORDtest.1.foo.example.com, test.WORD1.foo.example.com,
        #                           test.1.WORDfoo.example.com, WORD-test.1.foo.example.com,
        #                           test.WORD-1.foo.example.com, test.1.WORD-foo.example.com, ...

        domains = []

        for w in self.words:
            for i in range(len(parts[:-1])):
                # prepend normal
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}{}'.format(w, tmp_parts[i])
                domains.append('{}.{}'.format('.'.join(tmp_parts), parts[-1]))

                # prepend with dash
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}-{}'.format(w, tmp_parts[i])
                domains.append('{}.{}'.format('.'.join(tmp_parts), parts[-1]))

        return domains

    def append_word_every_index(self, parts):
        '''
        On every subdomain level, append existing content with `WORD` and `WORD-`
        '''

        # test.1.foo.example.com -> testWORD.1.foo.example.com, test.1WORD.foo.example.com,
        #                           test.1.fooWORD.example.com, test-WORD.1.foo.example.com,
        #                           test.1-WORD.foo.example.com, test.1.foo-WORD.example.com, ...

        domains = []

        for w in self.words:
            for i in range(len(parts[:-1])):
                # append normal
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}{}'.format(tmp_parts[i], w)
                domains.append('{}.{}'.format('.'.join(tmp_parts), '.'.join(parts[-1:])))

                # append with dash
                tmp_parts = parts[:-1]
                tmp_parts[i] = '{}-{}'.format(tmp_parts[i], w)
                domains.append('{}.{}'.format('.'.join(tmp_parts), '.'.join(parts[-1:])))

        return domains

    def replace_word_with_word(self, parts):
        '''
        If word longer than 3 is found in existing subdomain, replace it with other words from the dictionary
        '''

        # WORD1.1.foo.example.com -> WORD2.1.foo.example.com, WORD3.1.foo.example.com,
        #                            WORD4.1.foo.example.com, ...

        domains = []

        for w in self.words:
            if len(w) <= 3:
                continue

            if w in '.'.join(parts[:-1]):
                for w_alt in self.words:
                    if w == w_alt:
                        continue

                    domains.append('{}.{}'.format('.'.join(parts[:-1]).replace(w, w_alt), '.'.join(parts[-1:])))

        return domains

    def run(self):
        for domain in set(self.subdomains):
            parts = self.partiate_domain(domain)
            permutations = []
            permutations += self.insert_word_every_index(parts)
            permutations += self.insert_num_every_index(parts)
            permutations += self.prepend_word_every_index(parts)
            permutations += self.append_word_every_index(parts)
            permutations += self.replace_word_with_word(parts)

            for perm in permutations:
                yield perm

class AltDNS:
    def __init__(self, subdomains, base_domain = None, words = None, massdns_bin = None,
                 dnsserver = None, tmp_dir = None):
        self.subdomains = subdomains
        self.base_domain = base_domain
        self.words = words
        self.tmp_dir = tmp_dir
        self.dnsserver = dnsserver
        self.dnsgen_output_path = f"/tmp/dnsgen_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"

        self.massdns_output_path = f"/tmp/massdns_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
        self.massdns_bin = massdns_bin

    def dnsgen(self):
        genresult = DnsGen(set(self.subdomains), self.words,
                           base_domain=self.base_domain).run()

        with open(self.dnsgen_output_path, "w") as f:
            for domain in genresult:
                f.write(domain + "\n")

        return self.dnsgen_output_path

    def massdns(self):
        command = shlex.split(
             f"{self.massdns_bin} -q -r {self.dnsserver} -o S -w {self.massdns_output_path} -s 1500 {self.dnsgen_output_path} --root"
        )

        logger.info(" ".join(command))
        _ = subprocess.Popen(
            command 
            ,stdout=subprocess.PIPE
            )
        _.wait()
        return self.massdns_output_path

    def parse_massdns_output(self):
        output = []
        lines = open(self.massdns_output_path).read().splitlines()
        for line in lines:
            data = line.split(" ")
            if len(data) != 3:
                continue
            domain, type, record = data
            item = {
                "domain": domain.strip("."),
                "type": type,
                "record": record.strip()
            }
            output.append(item)

        return output

    def run(self):
        output = []
        try:
            self.dnsgen()
            self.massdns()
            output =  self.parse_massdns_output()
            self._delete_file()
        except Exception as e:
            logger.exception(e)

        return output

    def _delete_file(self):
        try:
            os.unlink(self.dnsgen_output_path)
            os.unlink(self.massdns_output_path)
        except Exception as e:
            logger.warning(e)

def altdns( massdns_bin , dnsserver_list ,   subdomains ,  base_domain = None, words = None  ):
    if len(subdomains) == 0:
        return []

    a = AltDNS(subdomains, base_domain,
            words = words, massdns_bin= massdns_bin,
            dnsserver=dnsserver_list, tmp_dir="/tmp/")
    raw_domains_info = a.run()

    '''解决泛解析的问题'''
    domains_info = []
    records = [x['record'] for x in raw_domains_info]
    records_count = Counter(records)
    for info in raw_domains_info:
        if records_count[info['record']] >= 15:
            continue
        domains_info.append(info)

    return domains_info

class _AltDNS():
    def __init__(self, doamin_info_list, base_domain , altdns_dict_path , massdns_bin , dnsserver_list):
        self.altdns_dict_path = altdns_dict_path
        self.doamin_info_list = doamin_info_list
        self.base_domain = base_domain
        self.dnsserver_list = dnsserver_list
        self.massdns_bin = massdns_bin
        self.domains = []
        self.subdomains = []
        inner_dicts = "test adm admin api app beta demo dev front int internal intra ops pre pro prod qa sit staff stage test uat"
        self.dicts = inner_dicts.split()

    def _fetch_domains(self):
        base_len = len(self.base_domain)
        for item in self.doamin_info_list:
            if not item.get('domain').endswith("."+self.base_domain):
                continue

            # if utils.check_domain_black("a."+ item.get('domain')):
            #     continue

            self.domains.append(item.get('domain'))
            subdomain = item.get('domain')[:- (base_len + 1)]
            if "." in subdomain:
                self.subdomains.append(subdomain.split(".")[-1])

        random.shuffle(self.subdomains)

        most_cnt = 50
        if len(self.domains) < 1000:
            most_cnt = 30
            self.dicts.extend(self._load_dict())

        sub_dicts = list(dict(Counter(self.subdomains).most_common(most_cnt)).keys())
        self.dicts.extend(sub_dicts)



        self.dicts = list(set(self.dicts))

    def _load_dict(self):
        ##加载内部字典
        dict = set()
        for x in self.altdns_dict_path:
            x = x.strip()
            if x:
                dict.add(x)

        return list(dict)

    def run(self):
        t1 = time.time()
        self._fetch_domains()
        logger.info("start {} AltDNS {}  dict {}".format(self.base_domain,
                                                         len(self.domains), len(self.dicts)))

        out = altdns( massdns_bin = self.massdns_bin  , 
            dnsserver_list = self.dnsserver_list , 
            subdomains = self.domains, 
            base_domain = self.base_domain, 
            words = self.dicts)

        elapse = time.time() - t1
        logger.info("end AltDNS result {}, elapse {}".format(len(out), elapse))

        return out

class Recon():
    """ vscan for verify ports 
        naabu2vscan for verify ports
    """ 
    def __init__(
            self ,
            target:str ,
            # ports:list = "1-65535" ,
            ports:list = ["53","21","22","23","24","25","80","81","280","300","443","444","458","464","481","497","500","512","513","514","524","541","543","544","548","554","563","587","593","616","625","631","636","646","648","666","667","683","687","691","700","705","711","714","720","722","726","749","765","777","783","787","800","808","843","873","880","888","898","900","901","902","911","981","987","990","992","995","999","1000","1001","1007","1009","1010","1021","1022","1023","1024","1025","1026","1027","1028","1029","1030","1031","1032","1033","1034","1035","1036","1037","1038","1039","1040","1041","1042","1043","1044","1045","1046","1047","1048","1049","1050","1051","1052","1053","1054","1055","1056","1057","1058","1059","1060","1061","1062","1063","1064","1065","1066","1067","1068","1069","1070","1071","1072","1073","1074","1075","1076","1077","1078","1079","1080","1081","1082","1083","1084","1085","1086","1087","1088","1089","1090","1091","1092","1093","1094","1095","1096","1097","1098","1099","1102","1104","1105","1106","1107","1110","1111","1112","1113","1117","1119","1121","1122","1123","1126","1130","1131","1137","1141","1145","1147","1148","1151","1154","1163","1164","1165","1169","1174","1183","1185","1186","1192","1198","1201","1213","1216","1217","1233","1236","1244","1247","1259","1271","1277","1287","1296","1300","1309","1310","1322","1328","1334","1352","1417","1433","1443","1455","1461","1494","1500","1503","1521","1524","1533","1556","1580","1583","1594","1600","1641","1658","1666","1687","1700","1717","1718","1719","1720","1723","1755","1761","1782","1801","1805","1812","1839","1862","1863","1875","1900","1914","1935","1947","1971","1974","1984","1998","1999","2000","2001","2002","2003","2004","2005","2006","2007","2008","2009","2013","2020","2021","2030","2033","2034","2038","2040","2041","2042","2045","2046","2047","2048","2065","2068","2099","2103","2105","2106","2111","2119","2121","2126","2135","2144","2160","2170","2179","2190","2196","2200","2222","2251","2260","2288","2301","2323","2366","2381","2382","2393","2399","2401","2492","2500","2522","2525","2557","2601","2604","2607","2638","2701","2710","2717","2725","2800","2809","2811","2869","2875","2909","2920","2967","2998","3000","3003","3005","3006","3011","3013","3017","3030","3052","3071","3077","3128","3168","3211","3221","3260","3268","3283","3300","3306","3322","3323","3324","3333","3351","3367","3369","3370","3371","3389","3404","3476","3493","3517","3527","3546","3551","3580","3659","3689","3703","3737","3766","3784","3800","3809","3814","3826","3827","3851","3869","3871","3878","3880","3889","3905","3914","3918","3920","3945","3971","3986","3995","3998","4000","4001","4002","4003","4004","4005","4045","4111","4125","4129","4224","4242","4279","4321","4343","4443","4444","4445","4449","4550","4567","4662","4848","4899","4998","5000","5001","5002","5003","5009","5030","5033","5050","5054","5060","5080","5087","5100","5101","5120","5190","5200","5214","5221","5225","5269","5280","5298","5357","5405","5414","5431","5440","5500","5510","5544","5550","5555","5560","5566","5631","5633","5666","5678","5718","5730","5800","5801","5810","5815","5822","5825","5850","5859","5862","5877","5900","5901","5902","5903","5906","5910","5915","5922","5925","5950","5952","5959","5960","5961","5962","5987","5988","5998","5999","6000","6001","6002","6003","6004","6005","6006","6009","6025","6059","6100","6106","6112","6123","6129","6156","6346","6389","6502","6510","6543","6547","6565","6566","6580","6646","6666","6667","6668","6689","6692","6699","6779","6788","6792","6839","6881","6901","6969","7000","7001","7004","7007","7019","7025","7070","7100","7103","7106","7200","7402","7435","7443","7496","7512","7625","7627","7676","7741","7777","7800","7911","7920","7937","7999","8000","8001","8007","8008","8009","8010","8021","8031","8042","8045","8080","8081","8082","8083","8084","8085","8086","8087","8088","8089","8093","8099","8180","8192","8193","8200","8222","8254","8290","8291","8300","8333","8383","8400","8402","8443","8500","8600","8649","8651","8654","8701","8800","8873","8888","8899","8994","9000","9001","9002","9009","9010","9040","9050","9071","9080","9090","9099","9100","9101","9102","9110","9200","9207","9220","9290","9415","9418","9485","9500","9502","9535","9575","9593","9594","9618","9666","9876","9877","9898","9900","9917","9929","9943","9968","9998","9999","10000","10001","10002","10003","10009","10012","10024","10082","10180","10215","10243","10566","10616","10621","10626","10628","10778","11110","11967","12000","12174","12265","12345","13456","13722","13782","14000","14238","14441","15000","15002","15003","15660","15742","16000","16012","16016","16018","16080","16113","16992","17877","17988","18040","18101","18988","19101","19283","19315","19350","19780","19801","19842","20000","20005","20031","20221","20828","21571","22939","23502","24444","24800","25734","26214","27000","27352","27355","27715","28201","30000","30718","30951","31038","31337","32768","32769","32770","32771","32772","32773","32774","32775","32776","32777","32778","32779","32780","32781","32782","32783","32784","33354","33899","34571","34572","35500","38292","40193","40911","41511","42510","44176","44442","44501","45100","48080","49152","49153","49154","49155","49156","49157","49158","49159","49160","49163","49165","49167","49175","49400","49999","50000","50001","50002","50006","50300","50389","50500","50636","50800","51103","51493","52673","52822","52848","52869","54045","54328","55055","55555","55600","56737","57294","57797","58080","60020","60443","61532","61900","62078","63331","64623","64680","65000","65129","65389","27017","6379","11211","19","20","21","22","23","24","25","30","32","37","42","49","70","79","80","81","82","83","84","88","89","99","106","109","110","113","119","125","135","139","143","146","161","163","179","199","211","222","254","255","259","264","301","306","311","340","366","389","406","416","425","427","7001","8008","9080"],
            udp_ports:list  = None ,
            mode = "domain2portscan" 
        ):
        """
            :target:  "127.0.0.1"  / "bilibili.com"
            :mode:  [ "domain2portscan" , "full" ,
                        "doamin" , "portscan" , 
                        "pocscan" , "bruteforce" , 
                        "dirscan" , "scrapy"
                    ] 
            :ports:  [ 22 , 8000, 27017 ] / "22,8000,27017"
            :{file_path}: file_path
        """

        self.task_id = f"recon_{datetime.now().strftime('%y%m%d%H%M%S%f')}_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
        self.ips , self.domains = Recon.parse_input(target)

        client = MongoClient(f'mongodb://{import_env("mongo_username")}:{quote(import_env("mongo_password"))}@{import_env("mongo_ip")}:{import_env("mongo_port")}/?authSource=admin')
        self.db = client[import_env("mongo_db")]
        

        # 查找依赖文件路径
        self.check_rely()

        # 校验ports输入
        if isinstance(ports , list ):
            self.tcp_port = ",".join([str(i) for i in ports ])
        elif isinstance(ports , str):
            self.tcp_port = ports
        else:
            raise self.RelyError("ports input error")
            sys.exit()

        #TODO 
        self.webreq_ret = []

        # 模式与执行方法 映射
        mode_dict = {
            "domain2portscan": self.domain2portscan,
            "full":self.full,
            "doamin":self.domain , 
            "portscan":self.portscan if self.tcp_port == "1-65535" else self.naabu2vscan ,
            "pocscan": self.pocscan  , 
            "bruteforce":self.bruteforce,
            "dirscan":self.dirscan,
            "scrapy":self.scrapy,
            "icp":self.icpscan,
            "ofa":self.OneforallCtrl
        }
        from pprint import pprint
        # pprint(self.OneforallCtrl(domains = "bilibili.com" ))
        self.result = mode_dict.get(mode , lambda: 'Invalid')()

        # os.remove(self.ip_file)

    def verify_vscan_filter(data):
        if ":" not in data:
            return False
        return True

    def write_file(ips:list):
        """ @input: list(domains)
            @return: filename
        """
        filename = f"/tmp/portscan_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
        """ domain to file  """
        with open(filename , 'w') as f:
            f.write('\n'.join(ips))
        return filename

    def isIP(str):
        try:
            IP(str)
        except ValueError:
            return False
        return True

    def parse_input(targets):
        ips = []
        domains = []
        if isinstance(targets  , list) :
            for i in list(set(targets)):
                if Recon.isIP(i):
                    ips.append(i)
                else:
                    domains.append(i)
        else:
            if Recon.isIP(targets):
                ips.append(targets)
            else:
                domains.append(targets)
        return ips , domains

    def del_file(filename: str ):
        """ util function delete file with filename"""
        os.remove(filename)

    class RelyError(Exception):
            """Exception raised for errors in the input.

            Attributes:
                expression -- input expression in which the error occurred
                message -- explanation of the error
            """
            def __init__(self, message):
                self.message = message

    def filter_execute_file_path(self , filename):
        usr_bin_path = f"/usr/bin/{filename}"
        usr_local_bin_path = f"/usr/local/bin/{filename}"
        abspath = f"{os.path.abspath('.')}/bin/{filename}"
        _path_list = [ usr_bin_path , usr_local_bin_path
            , abspath]
        for i in  _path_list :
            if os.path.isfile(i) and os.access(i , os.X_OK):
                return i

        raise self.RelyError(f"make sure install {filename}")
        sys.exit()

    def check_rely(self ,  ):
        """ check vscan rely
        """
        self.naabu_path = self.filter_execute_file_path("naabu")
        self.vscan_path = self.filter_execute_file_path("vscan-go")
        self.nuclei_path = self.filter_execute_file_path("nuclei")
        self.httpx_path = self.filter_execute_file_path("httpx")
        self.ffuf_path = self.filter_execute_file_path("ffuf")
        self.masscan_path = self.filter_execute_file_path('masscan')
        self.nmap_probe_file = '/'.join(self.vscan_path.split('/')[:-1])+'/nmap-service-probes'
        self.oneforall_path = self.filter_execute_file_path("OneForAll/oneforall.py")
        self.dnsserver = f"{os.path.abspath('.')}/dict/dnsserver.dict"
        self.domain_list = open(f"{os.path.abspath('.')}/dict/domains.dict").read().splitlines()
        self.altDNS_list = open(f"{os.path.abspath('.')}/dict/altDNS.dict").read().splitlines()
        self.massdns_bin = f"{'/'.join(self.oneforall_path.split('/')[:-1])}/thirdparty/massdns/massdns_linux_x86_64"
        
    def get_resp(_str: str):
        s = StringIO()
        pprint( _str , s)
        return s.getvalue()

    def _extract(domain):
        """ extract root domain 
            @domain: subdomain
        """
        _domain = domain.split('.')
        if not 'gov' in domain and not 'edu' in domain:
            if len(_domain) > 2:
                return '.'.join(_domain[1:])
            elif len(_domain) == 2:
                return domain
        else:
            _ = re.findall(r"(gov|edu)" , domain)
            return '.'.join(domain.split(_[0])[0].split('.')[1:])+_[0]+domain.split(_[0])[1]

    def task_wrap(wrap_func):
        @wraps(wrap_func)
        def _wrap_func(*args, **kwargs):
            t1 = datetime.now()
            logger.info(f"<{wrap_func.__name__}> start {t1.strftime('%d/%m/%y %H:%M:%S.%f')}")
            try:
                result = wrap_func(*args , **kwargs)
                return result
            except Exception as e:
                logger.warning(f"<{wrap_func.__name__} {e.args}>")
                import traceback
                traceback.format_exc()
            finally:
                t2 = datetime.now()
                logger.info(f"<{wrap_func.__name__}> finish {t2.strftime('%d/%m/%y %H:%M:%S.%f')}")
                time_cost  = t2 - t1 
                logger.info(f"<{wrap_func.__name__}> cost {time_cost.seconds} second ")
        return _wrap_func

    @task_wrap
    def naabu2vscan(self,ips):
        filename = Recon.write_file(ips)
        naabu_cmd = subprocess.Popen(
                shlex.split(
                    f"{self.naabu_path} -p {self.tcp_port} -list {filename} -rate 8000 -c 50"
                ),
                stdout=subprocess.PIPE,
            )
        vscan_cmd = subprocess.check_output(
            (shlex.split(
                f'{self.vscan_path} -scan-probe-file {self.nmap_probe_file} -routines=2000 -use-all-probes'
            )),
            stdin=naabu_cmd.stdout,
            )
        naabu_cmd.wait()
        _ret = [ json.loads(i) for i in vscan_cmd.decode("utf-8").strip().splitlines() ]
        return _ret

    @task_wrap
    def masscan2vscan(self , ips , tcp_port = "1-65535" , udp_port = None):
        ip_file = Recon.write_file(ips)
        if udp_port:
            masscan_cmd = subprocess.Popen(
                shlex.split(
                    f"{self.masscan_path} -iL {ip_file} -p {tcp_port},U:{udp_port} --rate=50000 "
                ),
                stdout=subprocess.PIPE
            )
        else:
            masscan_cmd = subprocess.Popen(
                shlex.split(
                    f'{self.masscan_path} -iL {ip_file} -p {tcp_port} --rate=50000 '
                ),
                stdout=subprocess.PIPE
            )
        awk_cmd1 = subprocess.Popen(
            shlex.split(
                "awk -F '/' '{print $1\" \"$2}'"
            ),
            stdin = masscan_cmd.stdout,
            stdout=subprocess.PIPE
        )
        awk_cmd2 = subprocess.Popen(
            shlex.split(
                "awk '{print $7\":\"$4\"/\"$5}'"
            ),
            stdin = awk_cmd1.stdout,
            stdout=subprocess.PIPE
        )
        vscan_cmd = subprocess.check_output(
            (shlex.split(
                f'{self.vscan_path} -scan-probe-file {self.nmap_probe_file} -routines=2000'
            ))
            ,
            stdin=awk_cmd2.stdout
        )
        masscan_cmd.wait()
        try:
            vscan_cmd = json.loads(vscan_cmd.decode("utf-8").strip())
        except Exception as e:
            logger.warning('no value')
            os.unlink(ip_file)
            return 
        os.unlink(ip_file)
        return vscan_cmd

    @task_wrap
    def httpx_run(self , urls):
        filename = f"/tmp/httpx_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
        out_filename = f"/tmp/httpx_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
        with open(filename , 'w') as f:
            for url in urls:
                f.write(url+"\n")
        httpx_cmd = subprocess.run(
                shlex.split(
                    f"{self.httpx_path} -l {filename} -t 150 -rl 500 -status-code -title -follow-redirects -silent -no-color -content-length -json -o {out_filename}"
                ),
                stdout=subprocess.PIPE
            )
        # httpx_cmd.wait()
        try:
            httpx_out = [ json.loads(i) for i in open(out_filename).read().splitlines()  ]
        except Exception as e1:
            logger.warning('no value')
            os.unlink(filename)
            os.unlink(out_filename)
            return
        os.unlink(filename)
        os.unlink(out_filename)
        return httpx_out

    @task_wrap
    def nmapscan(self,):
        pass

    def req_CallBackFunc(self , data):
        self.webreq_ret.append(data)

    def grab_req_data(  url):
        _webInfo = webInfo(url)
        return _webInfo.OutInfos

    def multi_req(self , urls ):
        pool = Pool(100)
        pool.map_async(Recon.grab_req_data, urls , callback = req_CallBackFunc)
        pool.close()
        pool.join()

    @task_wrap
    def OneforallCtrl(self , domains  ):
        if isinstance(domains , list):
            filename = Recon.write_file(domains)
        else:
            filename = f"/tmp/portscan_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
            with open(filename , 'w') as f:
                f.write(domains)
        ofa_cmd = subprocess.Popen(
                shlex.split(
                    f"python3 {self.oneforall_path} --targets {filename} --brute False --req False --alive False run --fmt json"
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        ofa_cmd.wait()

        # get datas
        ofa_ret = []
        ips_ret = []
        domains_ret = []
        if isinstance(domains , list):
            for i in domains:
                with open(f"{'/'.join(self.oneforall_path.split('/')[:-1])}/results/{i}.json") as f:
                    _ = json.loads(f.read())
                    ofa_ret.extend(_)
                os.remove(f"{'/'.join(self.oneforall_path.split('/')[:-1])}/results/{i}.json")
        else:
            with open(f"{'/'.join(self.oneforall_path.split('/')[:-1])}/results/{domains}.json") as f:
                _ = json.loads(f.read())
                ofa_ret.extend(_)
            os.remove(f"{'/'.join(self.oneforall_path.split('/')[:-1])}/results/{domains}.json")
        os.unlink(filename)
        for i in ofa_ret:
            domains_ret.append(i['subdomain'])
            # ips_ret.append(i['ip'])
        return domains_ret 
        # return domains_ret , ips_ret

    def gen_prebrute_wordlist(self , domains):
        # 生成待运行domain
        _prerun_domains = []
        if isinstance(domains , list):
            for domain in domains:
                for word in self.domain_list:
                    word = word.strip()
                    _prerun_domains.append(f"{word}.{domain}")
        else:
            for word in self.domain_list:
                word = word.strip()
                _prerun_domains.append(f"{word}.{domains}")
        return _prerun_domains

    @task_wrap
    def alt_dns(self , domain_info_list, base_domain):
        # doamin_info_list, base_domain , altdns_dict_path , massdns_bin , dnsserver_list
        a = _AltDNS(doamin_info_list = domain_info_list, 
            base_domain = base_domain , 
            altdns_dict_path  = self.altDNS_list , 
            massdns_bin = self.massdns_bin , 
            dnsserver_list = self.dnsserver)
        return a.run()

    @task_wrap
    def brutedns(self , domains):
        filename = f"/tmp/portscan_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
        outfilename = f"/tmp/portscan_{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))}"
        with open(filename, "w") as f:
            for domain in domains:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

        # run
        massdns_cmd = subprocess.Popen(
                shlex.split(
                    f"{self.massdns_bin} -q -r {self.dnsserver} -o S -w {outfilename} -s 300 {filename}  --root"
                ),
                stdout=subprocess.PIPE
            )
        massdns_cmd.wait()

        output = []
        # read data
        for line in open(outfilename).read().splitlines():
            data = line.split(" ")
            if len(data) != 3:
                continue
            domain, type, record = data
            item = {
                "domain": domain.strip("."),
                "type": type,
                "record": record.strip().strip(".")
            }
            output.append(item)
        os.unlink(filename)
        os.unlink(outfilename)
        return output

    @task_wrap
    def domain(self ,):
        ofa_ret = self.OneforallCtrl(domains = self.domains)
        _prebrute_list = self.gen_prebrute_wordlist(domains = self.domains)
        _prebrute_list.extend(ofa_ret)
        list(set(_prebrute_list))
        brute_ret = self.brutedns(domains = _prebrute_list)
        return brute_ret

    @task_wrap
    def portscan(self ,):
        portscan_ret = self.naabu2vscan(ips = list(set(self.ips)))
        return portscan_ret

    def gen_scheme(target , port = None):
        if target.startswith('http'):
            if not port :
                return [f"http://{target}" , f"https://{target}" ]
            elif str(port).endswith('443'):
                return [f"https://{target}:{port}"]
            else:
                return [f"http://{target}:{port}"]

    @task_wrap
    def domain2portscan(self ,):
        ips = []
        urls = []
        ofa_ret = self.OneforallCtrl(domains = self.domains)
        _prebrute_list = self.gen_prebrute_wordlist(domains = self.domains)
        _prebrute_list.extend(ofa_ret)
        list(set(_prebrute_list))
        brute_ret = self.brutedns(domains = _prebrute_list)

        for i in brute_ret:
            alt_ret = self.alt_dns(domain_info_list = brute_ret , base_domain = Recon._extract(i.get('domain')))

        brute_ret.extend(alt_ret)
        logger.info(len(brute_ret))
        brute_ret = [dict(t) for t in {tuple(d.items()) for d in brute_ret}]
        logger.info(len(brute_ret))

        for i in brute_ret:
            urls.append(i['domain'])
            if i.get('type') == 'A':
                ips.append(i.get('record'))
        
        self.ips.extend(ips)
        self.ips = list(set(self.ips))
        portscan_ret = self.naabu2vscan(ips = self.ips)

        for i in portscan_ret:
            if i['service'].get('name') in ['http' , 'ssl' , 'unknown']:
                urls.append(f"{i['ip']}:{str(i['port'])}")

        httpx_ret = self.httpx_run(urls = urls )

        self.save_data(data = brute_ret , col_name = 'domain')
        self.save_data(data = portscan_ret , col_name = 'port')
        self.save_data(data = httpx_ret , col_name = 'http')

    @task_wrap
    def dirscan(self ,):
        return 

    @task_wrap
    def scrapy(self ,):
        return 

    @task_wrap
    def bruteforce(self , ):
        return

    @task_wrap
    def nucleiscan(self ,):
        return 

    @task_wrap
    def pocscan(self ,):
        return 

    @task_wrap
    def full(self ,):
        return 

    @task_wrap
    def icpscan(self , ):
        return

    @task_wrap
    def save_data(self , data , col_name ):
        try:
            if isinstance(data , list):
                for i in data:
                    i.update({'taskId':self.task_id} , ordered=False) 
                self.db[col_name].insert_many(data)
                logger.info(f'mongo insert num:{str(len(data))}')
            elif isinstance(data , dict):
                data.update({'taskId':self.task_id})
                self.db[col_name].insert_one(data , ordered=False)
                logger.info(f'mongo insert num:{str(len(data))}')
        except PymongoErrors.BulkWriteError as e:
            logger.warning(e.args)

#TODO 
from sys import argv
if not argv[1:]:
    print(f"python3 {argv[0]} target_domain")
    sys.exit()
scan = Recon(argv[1])