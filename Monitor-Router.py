import requests
import json
from influxdb import InfluxDBClient
from datetime import timezone, time, datetime, timedelta
import time as alternativeTime
import geoip2.database
import socket
import Geohash
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_FILENAME = 'queryOutlandApis.log'
#LOG_FILENAME = 'queryOutlandApis.log'
logging.basicConfig(filename=LOG_FILENAME, level=logging.ERROR)

session = requests.Session()
session.verify = False

baseurl ='https://IP_AND_PORT_OF_YOUR_SYNOLOGY_ROUTER'
urlLogout = baseurl + '/webman/logout.cgi'

#Authentication
userName ='USER_OF_YOUR_SYNOLOGY_ROUTER'
passwd ='PASSWORD_OF_YOUR_SYNOLOGY_ROUTER'

#Influx Payload
def influx_sender(influx_payload,db):
    influx = InfluxDBClient('IP_OF_YOUR_INFLUXDB', 'PORT_OF_YOUR_INFLUX_DB', '','', db)
    influx.write_points(influx_payload)
    
#Get ISO time
def now_iso():
    now_iso = datetime.now(timezone.utc).astimezone().isoformat()
    return now_iso

def errorLvl(argument):
    switcher = {
        "info": 1,
        "warn":2,
        "error":3,
    }
    return switcher.get(argument)

def findDeviceName(jsonDic,deviceMac):
    for item in jsonDic:
        if item['mac'] == deviceMac:
            return item['hostname']

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
            'passwd':passwd
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

def listKnowDevices(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.NGFW.Traffic.Device',
            'version':'1',
            'method':'get',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']
    return result

def vpnPlusHistoricSessions(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.VPNPlus.Connectivity',
            'version':'1',
            'method':'list_uid_aggr',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['uid_aggr_list']
    return result

def vpnPlusOnlineSessions(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.VPNPlus.Connectivity',
            'version':'1',
            'method':'list',
            'status':'online',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['cnt_list']

    influxPayloadVpnPlusActiveSessions= []
    for item in result:
        if item['ip_from'] != "0.0.0.0":
            INFO = GI.city(item['ip_from'])           
            HASH = Geohash.encode(INFO.location.latitude, INFO.location.longitude)
            country_code = INFO.country.iso_code
            if INFO.city.name != "" and INFO.city.name is not None:
                location_name = INFO.city.name
            else:
                location_name = country_code   
        else:
            HASH = "Blocked"
            location_name = "Blocked"
            country_code = "Blocked"            
        influxPayloadVpnPlusActiveSessions.append(
            {
                    "measurement": "OUTLAND.Remote.Network.VPNPlus",
                    "tags": {           
                                        "username":item['username'],
                                        "geohash": HASH,
                                        "country_code":country_code, 
                                        "location_name":location_name,                                                                                                    
                                        "externalIP":item['ip_from'],                                    
                                        "internalIP":item['signature']                                    
                            },
                            "time": now_iso(),
                            "fields": { 
                                        "externalIP":item['ip_from'],                                    
                                        "internalIP":item['signature'],
                                        "abnormal":item['abnormal'],                                                                       
                                        "download":item['download'],                                                                       
                                        "upload":item['upload'],
                                        "count": 1,
                                        "time_duration":item['time_duration'],
                                        "time_start":datetime.fromtimestamp(float(item['time_start'])).strftime('%Y-%m-%d %H:%M:%S')
                                    }
                            }                   
        )
    influx_sender(influxPayloadVpnPlusActiveSessions,'telegraf')
    return influxPayloadVpnPlusActiveSessions

def vpnPlusOpenSites(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.VPNPlus.WebPortal.Sites',
            'version':'1',
            'method':'list',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['sites']
    return result

def coreSystemStatus(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.System.Utilization',
            'version':'1',
            'method':'get',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']
    
    influxPayloadOutlandStatus= []
    influxPayloadOutlandStatus.append(
        {
                "measurement": "OUTLAND.Remote.System.CPU",
                "tags": {           
                        },
                        "time": now_iso(),
                        "fields": {
                                    "user_load":result['cpu']['user_load'],
                                    "system_load":result['cpu']['system_load'],                                                                                           
                                    "other_load":result['cpu']['other_load'],                                                                                           
                                    "1min_load":result['cpu']['1min_load'],                                                                
                                    "5min_load":result['cpu']['5min_load'],  
                                    "15min_load":result['cpu']['15min_load']
                                }
                        }                   
    )
    influx_sender(influxPayloadOutlandStatus,'telegraf')

    influxPayloadOutlandStatus= []
    influxPayloadOutlandStatus.append(
        {
                "measurement": "OUTLAND.Remote.System.Memory",
                "tags": {           
                        },
                        "time": now_iso(),
                        "fields": {
                                    "memory_size":result['memory']['memory_size'],
                                    "total_swap":result['memory']['buffer'],
                                    "total_real":result['memory']['total_real'],                                                                                           
                                    "real_usage":result['memory']['real_usage'],                                                                                           
                                    "avail_real":result['memory']['avail_real'],                                                                
                                    "avail_swap":result['memory']['avail_swap'],  
                                    "buffer":result['memory']['buffer'],
                                    "cached":result['memory']['cached']
                                }
                        }                   
    )
    influx_sender(influxPayloadOutlandStatus,'telegraf')
    return influxPayloadOutlandStatus

def networkConnectedDevices(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.Network.NSM.Device',
            'version':'1',
            'method':'get',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['devices']

    influxPayloadConnectedDevices= []
    for item in result:    
        if True == item['is_online']:
            if True == item['is_wireless']:
                influxPayloadConnectedDevices.append(
                            {
                                "measurement": "OUTLAND.Remote.Network.ConnectedDevices",
                                "tags": {
                                    "band":item['band'],
                                    "connection":item['connection'],                                
                                    "hostname": item['hostname'],                                
                                    "is_baned":item['is_baned'],
                                    "is_guest":item['is_guest'],
                                    "is_high_qos":item['is_high_qos'],
                                    "is_low_qos":item['is_low_qos'],
                                    "is_qos":item['is_qos'],
                                    "is_wireless":item['is_wireless'],                                                                
                                    "mac":item['mac']                                                        
                                    #"mesh_node_id":item['mesh_node_id'],                                
                                },
                                "time": now_iso(),
                                "fields": {                                    
                                        "max_rate":item['max_rate'], 
                                        "current_rate":item['current_rate'],
                                        "transferRXRate":item['transferRXRate'],     
                                        "transferTXRate":item['transferTXRate'],
                                        "signalstrength":item['signalstrength'],
                                        "rate_quality":item['rate_quality'],
                                        "internalIP":item['ip_addr']                                                            
                                }
                            }
                )
            else:
                influxPayloadConnectedDevices.append(
                            {
                                "measurement": "OUTLAND.Remote.Network.ConnectedDevices",
                                "tags": {
                                    "connection":item['connection'],
                                    "hostname":item['hostname'],                                
                                    "is_baned":item['is_baned'],
                                    "is_high_qos":item['is_high_qos'],
                                    "is_low_qos":item['is_low_qos'],
                                    "is_qos":item['is_qos'],                                
                                    "is_wireless":item['is_wireless'],
                                    "mac":item['mac']                               
                                },
                                "time": now_iso(),
                                "fields": {       
                                    "internalIP":item['ip_addr']                          
                                }
                            }
                )
            influx_sender(influxPayloadConnectedDevices,'telegraf')
    return influxPayloadConnectedDevices

def networkDHCPDevices(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.Network.DHCPServer.ClientList',
            'version':'2',
            'method':'list',
            'ifname':'lbr0',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['clientList']['ipv4']

    influxPayloadConnectedDevicesDHCP= []
    for item in result:   
        influxPayloadConnectedDevicesDHCP.append(
            {
                    "measurement": "OUTLAND.Remote.Network.DHCP",
                    "tags": {           
                                        "hostname":item['hostname'],
                                        "mac":item['clid']
                            },
                            "time": now_iso(),
                            "fields": {                                    
                                        "expire":item['expire'],
                                        "internalIP":item['ip']   
                                    }
                            }                   
        )
    influx_sender(influxPayloadConnectedDevicesDHCP,'telegraf')
    return influxPayloadConnectedDevicesDHCP

def networkWifiChannel(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.Network.Wifi.Hotspot',
            'version':'2',
            'method':'list' ,
            '_sid':token           
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']

    influxPayloadWifiChannels= []
    for item in result:   
        influxPayloadWifiChannels.append(
            {
                    "measurement": "OUTLAND.Remote.Network.Wifi.Channels",
                    "tags": {           
                                        "netif":item['netif']                                    
                            },
                            "time": now_iso(),
                            "fields": {                                    
                                        "current_channel":item['current_channel'],                                    
                                        "status":item['status']
                                    }
                            }                   
        )
    influx_sender(influxPayloadWifiChannels,'telegraf')
    return influxPayloadWifiChannels

def networkFirewallConnectionsLastDay(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.NGFW.Traffic.Domain',
            'version':'1',
            'method':'get_devices',
            'interval':'day',
            '_sid':token           
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']

    influxPayloadNetworkFirewallConnectionsLastDay= []
    totalConnections = sum(d['count'] for d in result if d) 
    for item in result:           
        userTotal = (int((item['count']) * 100) / totalConnections)
        userTotal = round(userTotal,1)
        influxPayloadNetworkFirewallConnectionsLastDay.append(
            {
                    "measurement": "OUTLAND.Remote.Network.FW.Summary.LastDay",
                    "tags": {           
                                        "hostname":item['hostname']                                    
                            },
                            "time": now_iso(),
                            "fields": { 
                                        "count":item['count'],
                                        "percentage":userTotal
                                    }
                            }                   
        )
    influx_sender(influxPayloadNetworkFirewallConnectionsLastDay,'telegraf')
    return influxPayloadNetworkFirewallConnectionsLastDay

def networkFirewallBandwidthCheck(token,interval):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.NGFW.Traffic',
            'version':'1',
            'method':'get',
            'interval':interval,
            'mode':'net_l7',
            '_sid':token           
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']

    #Get List of Know Devices
    knowDevices = listKnowDevices(authToken)
    influxPayloadNetworkFirewallBandwidthLastDay= []
    for item in result:           
        deviceName = findDeviceName(knowDevices,item['deviceID'])
        influxPayloadNetworkFirewallBandwidthLastDay.append(
            {
                    "measurement": "OUTLAND.Remote.Network.FW.Summary.Bandwidth." + interval,
                    "tags": {           
                                        "hostname":deviceName                                  
                            },
                            "time": now_iso(),
                            "fields": { 
                                        "download":item['download'],
                                        "download_packets":item['download_packets'],
                                        "upload":item['upload'],
                                        "upload_packets":item['upload_packets'],
                                    }
                            }                   
        )
        influx_sender(influxPayloadNetworkFirewallBandwidthLastDay,'telegraf')
    return influxPayloadNetworkFirewallBandwidthLastDay

def networkFirewallDomainLastDay(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.NGFW.Traffic.Domain',
            'version':'1',
            'method':'get',
            'interval':'day',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']

    payloadDomainLastDay= []
    for item in result:  
        if item['count']  > 5:      
            payloadDomainLastDay.append(
                {
                        "measurement": "OUTLAND.Remote.Network.FW.Summary.Domain.day" ,
                        "tags": {           
                                            "domainName":item['domainName']                                  
                                },
                                "time": now_iso(),
                                "fields": { 
                                            "count":item['count'],
                                            "domainId":item['domainId']
                                        }
                                }                   
            )
            influx_sender(payloadDomainLastDay,'telegraf')
    return payloadDomainLastDay
    
def networkFirewallUrlLive(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.NGFW.Traffic.Domain',
            'version':'1',
            'method':'get',
            'interval':'live',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']

    #Get List of Know Devices
    knowDevices = listKnowDevices(authToken)

    payloadUrlLive = []
    for item in result:  
        try:
            ipData = item['domain'].split(':')[0]
            ipData = socket.gethostbyname(ipData)
        except:
            ipData = '0.0.0.0'
        if ipData != '0.0.0.0':
            try:
                INFO = GI.city(ipData)
                HASH = Geohash.encode(INFO.location.latitude, INFO.location.longitude)
                country_code = INFO.country.iso_code
                if INFO.city.name != "" and INFO.city.name is not None:
                    location_name = INFO.city.name
                else:
                    location_name = country_code
            except:
                HASH = "Unknow"
                location_name = "Unknow"
                country_code = "Unknow"
        else:
            HASH = "Blocked"
            location_name = "Blocked"
            country_code = "Blocked"
        #print(str(location_name)  + ' - ' +  str(country_code))
        parsedDateTime = datetime.fromtimestamp(float(item['timestamp']))
        if is_time(parsedDateTime) == True:
            deviceName = findDeviceName(knowDevices,item['mac'])
            payloadUrlLive.append(
                {
                        "measurement": "OUTLAND.Remote.Network.FW.Summary.Url.Live",
                        "tags": {           
                                            "deviceName":deviceName,
                                            "country_code":country_code, 
                                            "location_name":location_name,
                                            "geohash": HASH,
                                            "protocol":item['protocol']                            
                                },
                                "time": now_iso(),
                                "fields": { 
                                            "detail":item['detail'],
                                            "domainName":item['domain'],
                                            "count": 1,
                                            "timestamp":parsedDateTime.strftime('%Y-%m-%d %H:%M:%S')
                                        }
                                }                   
            )
            influx_sender(payloadUrlLive,'telegraf')
    return payloadUrlLive

def networkFirewallWebTraffic(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.NGFW.Traffic',
            'version':'1',
            'method':'get',
            'mode':'net',
            'interval':'live',
            '_sid':token
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']

    #Get List of Know Devices
    knowDevices = listKnowDevices(authToken)

    payloadWebTrafficLive = []
    for item in result:  
        deviceName = findDeviceName(knowDevices,item['deviceID'])
        payloadWebTrafficLive.append(
            {
                    "measurement": "OUTLAND.Remote.Network.FW.WebTraffic.Live" ,
                    "tags": {           
                                        "deviceName":deviceName                                     
                            },
                            "time": now_iso(),
                            "fields": { 
                                        "download":item['download'],
                                        "upload":item['upload']                                        
                                    }
                            }                   
        )
        influx_sender(payloadWebTrafficLive,'telegraf')
    return payloadWebTrafficLive

def getConnectionLogsOutland(token):
    url = baseurl + '/webapi/entry.cgi'
    headers = {
           'Content-Type': 'application/x-www-form-urlencoded'
        }
    body = {
             'Content-Type': 'application/x-www-form-urlencoded',
            'api':'SYNO.Core.SyslogClient.Log',            
            'limit':'100',            
            'method':'list',            
            'target':'LOCAL',            
            'version':'1',
            '_sid':token            
            }   
    r = session.post(url, headers=headers, data=body)
    jsonDic = json.loads(r.text)
    result = jsonDic['data']['items']

    payloadConnectionLogsOutland = []    
    for item in result:                 
        parsedDateTime = datetime.strptime(item['time'],'%Y/%m/%d %H:%M:%S')
        if is_time(parsedDateTime) == True:
            logLevelInt = errorLvl(item['level'])   
            if 'failed' in item['descr']:
                logLevelInt = 3
            else:
                if 'logged' in item['descr']:
                    logLevelInt = 6
            payloadConnectionLogsOutland.append(
                {
                        "measurement": "OUTLAND.Remote.System.Logs.Connection" ,
                        "tags": {                                                   
                                            "user":item['who'],                                        
                                            "logtype":item['logtype'],
                                            "level":item['level'],                                                                                
                                            "timestamp":item['time'],      
                                            'orginalLogType':item['orginalLogType'],                                                                      
                                            'loglevelInt':logLevelInt
                                },
                                "time": now_iso(),
                                "fields": {      
                                            "descr":item['descr']                                        
                                        }
                                }                   
            )        
            influx_sender(payloadConnectionLogsOutland,'telegraf')
    return payloadConnectionLogsOutland

def mainBlock():
    #historicSssions = vpnPlusHistoricSessions(authToken)
    #openSites = vpnPlusOpenSites(authToken)

    #Main Calls

    #System Status CPU/Memory ##########################################################
    coreSystemStatus(authToken)
    ###################################################################################

    #Network DHCP Clients #############################################################
    networkDHCPDevices(authToken)
    ###################################################################################

    #Wifi Channels ####################################################################
    runWindowHourly = is_time_between(time(int(datetime.now().hour),00,00), time(int(datetime.now().hour),00,45),datetime.now().time())
    if runWindowHourly == True:
        networkWifiChannel(authToken)
    ###################################################################################

    #Connected Devices ################################################################
    networkConnectedDevices(authToken)
    ###################################################################################

    #VPN Plus Active Sessions #########################################################
    vpnPlusOnlineSessions(authToken)
    ###################################################################################

    #Firewall Get Connections Last Day 
    runWindowHourly = is_time_between(time(int(datetime.now().hour),00,00), time(int(datetime.now().hour),00,45),datetime.now().time())
    if runWindowHourly == True:
        networkFirewallConnectionsLastDay(authToken)
    ###################################################################################

    #Firewall Get Bandwidth Last Day #################################################
    runWindowDay = is_time_between(time(int(datetime.now().hour),00,00), time(int(datetime.now().hour),00,30),datetime.now().time())
    if runWindowDay == True:
        networkFirewallBandwidthCheck(authToken,'day')
    runWindowDay = is_time_between(time(3,1,00), time(3,1,30),datetime.now().time())
    if runWindowDay == True:
        networkFirewallBandwidthCheck(authToken,'week')
    runWindowDay = is_time_between(time(3,2,00), time(3,2,30),datetime.now().time())
    if runWindowDay == True:
        networkFirewallBandwidthCheck(authToken,'month')
    runWindowDay = is_time_between(time(3,3,00), time(3,3,30),datetime.now().time())
    if runWindowDay == True:
        networkFirewallBandwidthCheck(authToken,'year')
     
    ###################################################################################

    #Firewall Get Domain Last Day
    #runWindowDay = is_time_between(time(int(datetime.now().hour),00,30), time(int(datetime.now().hour),00,59),datetime.now().time())
    runWindowDay = is_time_between(time(5,00,30), time(5,00,59),datetime.now().time())
    if runWindowDay == True:
        networkFirewallDomainLastDay(authToken)
    ###################################################################################

    #Firewall Get URL Live
    networkFirewallUrlLive(authToken)
    ###################################################################################

    #Firewall Get Live Web Traffic
    networkFirewallWebTraffic(authToken)
    ###################################################################################

    #Firewall Get Live Web Traffic
    getConnectionLogsOutland(authToken)
    ###################################################################################


def mainRunner():
    starttime=alternativeTime.time()
    #print('Starting query ' + str(now_iso()))
    mainBlock()
    #print('Execution finished ' + str(now_iso()))
    alternativeTime.sleep(30.0 - ((alternativeTime.time() - starttime) % 30.0))

#Auth
authToken = authRest(userName,passwd)
GI = geoip2.database.Reader('GeoLite2-City.mmdb')
#GI = geoip2.database.Reader('GeoLite2-City.mmdb')
networkFirewallUrlLive(authToken)

while True:
    try:
        if authToken == False:
            time.sleep(15.0)
            authToken = authRest(userName,passwd)
            print('Not Authenticated')
        else:
            mainRunner()
    except Exception as e:
        #ReAuth
        print('Failed! - ' +  str(e))
        logging.exception('Failed on main while!')
        authToken = authRest(userName,passwd)
        raise
        #mainRunner()