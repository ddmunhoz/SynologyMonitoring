import requests
import json
from IPy import IP
from influxdb import InfluxDBClient
from datetime import timezone, time, datetime, timedelta
import time as alternativeTime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


session = requests.Session()
session.verify = False

baseurl ='https://IP_AND_PORT_OF_YOUR_NAS'
urlAuth = baseurl + '/webapi/auth.cgi'
urlLogout = baseurl + '/webman/logout.cgi'

#Authentication
userName ='USERNAME_WITH_ADMIN_RIGHTS_OF_YOUR_NAS'
passwd ='PASSWORD_OF_NAS'

#Influx Payload
def influx_sender(influx_payload,db):
    influx = InfluxDBClient('IP_OF_YOUR_INFLUXDB', 'PORT_OF_YOUR_INFLUXDB', '','', db)
    influx.write_points(influx_payload)
    
#Get ISO time
def now_iso():
    now_iso = datetime.now(timezone.utc).astimezone().isoformat()
    return now_iso

def time_duration(begin_time):
    s1 = begin_time
    s2 = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
    FMT = '%Y/%m/%d %H:%M:%S'
    tdelta = datetime.strptime(s2, FMT) - datetime.strptime(s1, FMT)
    return tdelta

def errorLvl(argument):
    switcher = {
        "info": 1,
        "warn":2,
        "error":3,
    }
    return switcher.get(argument)

def is_time_between(begin_time, end_time, check_time=None):
    # If check time is not given, default to current UTC time
    check_time = check_time or datetime.utcnow().time()
    if begin_time < end_time:
        return check_time >= begin_time and check_time <= end_time
    else: # crosses midnight
        return check_time >= begin_time or check_time <= end_time

def is_time(eventTime):
    nowDateTime = datetime.now() - timedelta(seconds=30)
    return eventTime >= nowDateTime   

#Auth
def authRest(userName,passwd):
    urlAuth = baseurl + '/webapi/auth.cgi'
    headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.API.Auth',
            'version':'2',
            'method':'login',
            'account':userName,
            'passwd':passwd,
            'session':'DownloadStation'
            }   
    r = session.post(urlAuth, headers=headers, data=body)
    #Parse json response
    jsonDic = json.loads(r.text)
    if r.text == '{"error":{"code":401},"success":false}\n':
        return False
    else:
        #Get Auth Toke
        synoToken = jsonDic['data']['sid']
        return synoToken

def getRunningProccess(authToken):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.System.Process',
            'version':'1',
            'method':'list',                        
            '_sid':authToken
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['process']

    payloadRunningProcess = []
    for item in result:          
        payloadRunningProcess.append(
            {
                    "measurement": "NARS.Remote.System.Processess" ,
                    "tags": {           
                                        "command":item['command'],
                                        "status":item['status']
                            },
                            "time": now_iso(),
                            "fields": { 
                                        "cpu":item['cpu'],
                                        "mem":item['mem'],
                                        "mem_shared":item['mem_shared'],
                                        "pid":item['pid'],
                                        
                                    }
                            }                   
        )        
    influx_sender(payloadRunningProcess,'telegraf')
    return payloadRunningProcess

def getConnectionLogsNars(authToken):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.SyslogClient.Log',
            'keyword':'',
            'level':'',
            'limit':'100',
            'logtype':'connection',
            'method':'list',
            'start':'0',
            'target':'Outland',
            'version':'1'
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['items']

    payloadConnectionLogsNars = []
    for item in result:
        parsedDateTime = datetime.strptime(item['time'],'%Y/%m/%d %H:%M:%S')
        if is_time(parsedDateTime) == True:    
            logLevelInt = errorLvl(item['level'])   
            if 'failed' in item['descr']:
                logLevelInt = 3
            else:
                if 'logged' in item['descr']:
                    logLevelInt = 6
            payloadConnectionLogsNars.append(
                {
                        "measurement": "NARS.Remote.System.Logs.Connection" ,
                        "tags": {           
                                            "user":item['who'],
                                            "logtype":item['logtype'],
                                            "level":item['level'],
                                            "timestamp":item['time'],
                                            'loglevelInt':logLevelInt
                                },
                                "time": now_iso(),
                                "fields": { 
                                            "descr":item['descr'],                                        
                                        }
                                }                   
            )        
            influx_sender(payloadConnectionLogsNars,'telegraf')
    return payloadConnectionLogsNars

def getFileAccessLogsNars(authToken):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.SyslogClient.Log',
            'limit':'100',
            'logtype':'webdav,cifs,tftp,afp',
            'method':'list',
            'version':'1'
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['items']

    payloadConnectionAccessLog = []
    for item in result:            
        parsedDateTime = datetime.strptime(item['time'],'%Y/%m/%d %H:%M:%S')
        if is_time(parsedDateTime) == True:          
            payloadConnectionAccessLog.append(
                {
                        "measurement": "NARS.Remote.System.Logs.FileAccess",
                        "tags": {                                                   
                                            "logtype":item['logtype'],
                                            'orginalLogType':item['orginalLogType'],                                        
                                            "timestamp":item['time'],
                                            "user":item['username'],
                                            "internalIP":item['ip'],                                        
                                            "command":item['cmd']
                                },
                                "time": now_iso(),
                                "fields": {                                        
                                            
                                            "descr":item['descr']                                        
                                        }
                                }                   
            )        
            influx_sender(payloadConnectionAccessLog,'telegraf')
    return payloadConnectionAccessLog

def getConnectedUsersNars(authToken):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.CurrentConnection',
            'version':'1',
            'method':'list',                        
            '_sid':authToken
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['items']

    payloadConnectedUsers = []
    for item in result:       
        timeDuration = time_duration(item['time']) 
        payloadConnectedUsers.append(
            {
                    "measurement": "NARS.Remote.ConnecteClients" ,
                    "tags": {           
                                        "user":item['who'],
                                        "protocol":item['type'],
                                        "internalIP":item['from'],    
                                        "timestamp":item['time']                                      
                            },
                            "time": now_iso(),
                            "fields": { 
                                       "descr":item['descr'],
                                       "time_duration":timeDuration.seconds                               
                                    }
                            }                   
        )        
    influx_sender(payloadConnectedUsers,'telegraf')
    return payloadConnectedUsers

def mainBlock():
    #Main Calls

    #Get System Running Proccess#######################################################
    #getRunningProccess(authToken)
    ################################################################################### 

    #Get Connection logs ##############################################################
    getConnectionLogsNars(authToken)
    ###################################################################################  
    
    #Get File Access logs #############################################################
    getFileAccessLogsNars(authToken)
    ###################################################################################  

    #Get Connected Users ##############################################################
    getConnectedUsersNars(authToken)
    ################################################################################### 

def mainRunner():
        starttime=alternativeTime.time()
        print('Starting query ' + str(now_iso()))
        mainBlock()
        print('Execution finished ' + str(now_iso()))
        alternativeTime.sleep(30.0 - ((alternativeTime.time() - starttime) % 30.0))

#Auth
authToken = authRest(userName,passwd)
#getConnectedUsersNars(authToken)


while True:
    try:
        if authToken == False:
            time.sleep(15.0)
            raise Exception('Not Authenticated')
        else:
            mainRunner()
    except:
        #ReAuth
        print('Failed!')
        authToken = authRest(userName,passwd)
        #mainRunner()

#iptype = IP(item['from']).iptype()
   

