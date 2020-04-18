# Synology Monitoring scripts

Hello Hello Gents of the Internet!
A few days ago I posted a screenshot from my iPhone of my Synology Infra monitoring dashboard. Some people demonstrated interest and asked me to provide instructions on how to achieve the same.
The idea here is to provide what you need to download and provide de configuration files for it. I won't go step by step since text is not the best form to explain complex procedures. That being said I believe anyone with a lit bit more than Basic knowledge will be able to follow along and deploy your version of this stack.

!!! DISCLAIMER !!!
This is a pre alpha release, expect bugs, dirty code and be ready to spot lots of improvements that will come down the road when I turn everything you see here in a library.

Tools -

Telegraf -  docker pull telegraf
InfluxDB - docker pull influxdb
Grafana -  docker pull grafana/grafana
Python3 + Scripts - docker pull centos

For the Python part I recommend pulling the CentOS docker base image and installing python3 on it. After that clone this repository and store and configure those scripts to run using crontab on your container.

Monitor-Internet.py    - Update the included config_internet.ini file to reflect your InfluxDB IP/Username/Database Name

Monitor-Pihole.py      -  Update the included config_pihole.ini file to reflect your Pihole IP/Username/API Location

Monitor-NAS.py         -   Update lines 14-20 to reflect your NAS IP/Username/Password - IMPORTANT: This user must be a NAS admin, otherwise the API calls performed by the python script will fail. Not my fault! I'm just emulating the act of browsing your nas interface and extracting this information. Half of the APIS used by me are not documented by Synology and they were extracted by a process of observation and experimentation. 

Monitor-ROUTER.py       - Update lines 20-25 to reflect your NAS IP/Username/Password - IMPORTANT: This user must be a ROUTER admin(Follow this guide to create a second admin user on your Synology router), otherwise the API calls performed by the python script will fail. Not my fault! I'm just emulating the act of browsing your nas interface and extracting this information. Half of the APIS used by me are not documented by Synology and they were extracted by a process of observation and experimentation. 
Both Monitor-NAS and Monitor-Router use the default telegram database called telegraf to store data. The following series are available:


NAS - Everything is collected every 30+- secs.

NARS.Remote.System.Processess
NARS.Remote.System.Logs.Connection
NARS.Remote.System.Logs.FileAccess
NARS.Remote.ConnecteClients

ROUTER - Default collection time is every 30+- secs, with a few exceptions. Check below:

OUTLAND.Remote.Network.VPNPlus
OUTLAND.Remote.System.CPU
OUTLAND.Remote.System.Memory
OUTLAND.Remote.Network.ConnectedDevices
OUTLAND.Remote.Network.DHCP
OUTLAND.Remote.Network.Wifi.Channels                  - Collected every 1 hour.
OUTLAND.Remote.Network.FW.Summary.LastDay             - Collected every 1 hour.
OUTLAND.Remote.Network.FW.Summary.Bandwidth.Day       - Collected every 1 hour.
OUTLAND.Remote.Network.FW.Summary.Bandwidth.Week      - Collected every 1 day(at 3AM+-)
OUTLAND.Remote.Network.FW.Summary.Bandwidth.Month     - Collected every 1 day(at 3AM+-)
OUTLAND.Remote.Network.FW.Summary.Bandwidth.Year.     - Collected every 1 day(at 3AM+-)
OUTLAND.Remote.Network.FW.Summary.Domain.day          - Collected every day(at 5AM+-)
OUTLAND.Remote.Network.FW.Summary.Url.Live
OUTLAND.Remote.Network.FW.WebTraffic.Live
OUTLAND.Remote.System.Logs.Connection







