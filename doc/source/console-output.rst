Console Output
==============

Console/Log Startup
-------------------

At start up,  the logs and console output give you information about the status of Meer. 
For example,  you will want to note the ``Redis`` and ``Elasticsearch``,  such as the driver and whether
a successful connection was made.  If there is a problem making a connection to your database, 
Meer will display the error that is causing the issues. 

Another important item to note is the database sensor ID.  This will be the ID number used in
the database to store events. 

Common issues are database rights and directory/file permission problems. 

If Meer makes it to the ``Waiting of new data...``,  then Meer has successfully started. 

::

[*] [10/20/2021 20:55:23] Configuration '/usr/local/etc/meer.yaml' for host 'dev' successfully loaded.
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23]  @@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    Meer version 1.0.0-git
[*] [10/20/2021 20:55:23]  @@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security
[*] [10/20/2021 20:55:23]  @!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com
[*] [10/20/2021 20:55:23]  !!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018-2021
[*] [10/20/2021 20:55:23]   :      :   : :: ::  : :: ::   :   : :
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Meer's PID is 14606
[*] [10/20/2021 20:55:23] Dropping privileges! [UID: 1011 GID: 1011]
[*] [10/20/2021 20:55:23] Loaded 40382 entries from OUI database [/usr/local/etc/manuf].
[*] [10/20/2021 20:55:23] Classifications file loaded [/usr/local/etc/sagan-rules/classification.config].
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Fingerprint support    : enabled
[*] [10/20/2021 20:55:23] Health updates         : enabled
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] GeoIP support          : enabled
[*] [10/20/2021 20:55:23] GeoIP database         : /usr/local/share/GeoIP2/GeoLite2-City.mmdb
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Waldo loaded. Current position: 2345
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] --[ Redis output information ]--------------------------------------
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Successfully connected to Redis server at 127.0.0.1:6379.
[*] [10/20/2021 20:55:23] Got PONG from Redis at 127.0.0.1:6379.
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Write 'alert'        : enabled
[*] [10/20/2021 20:55:23] Write 'stats'        : enabled
[*] [10/20/2021 20:55:23] Write 'email'        : enabled
[*] [10/20/2021 20:55:23] Write 'dns'          : enabled
[*] [10/20/2021 20:55:23] Write 'flow'         : enabled
[*] [10/20/2021 20:55:23] Write 'http'         : enabled
[*] [10/20/2021 20:55:23] Write 'tls'          : enabled
[*] [10/20/2021 20:55:23] Write 'ssh'          : enabled
[*] [10/20/2021 20:55:23] Write 'smtp'         : enabled
[*] [10/20/2021 20:55:23] Write 'files'        : enabled
[*] [10/20/2021 20:55:23] Write 'fileinfo'     : enabled
[*] [10/20/2021 20:55:23] Write 'dhcp'         : enabled
[*] [10/20/2021 20:55:23] Write 'rdp'          : enabled
[*] [10/20/2021 20:55:23] Write 'sip'          : enabled
[*] [10/20/2021 20:55:23] Write 'ftp'          : enabled
[*] [10/20/2021 20:55:23] Write 'ikev2'        : enabled
[*] [10/20/2021 20:55:23] Write 'nfs'          : enabled
[*] [10/20/2021 20:55:23] Write 'tftp'         : enabled
[*] [10/20/2021 20:55:23] Write 'smb'          : enabled
[*] [10/20/2021 20:55:23] Write 'dcerpc'       : enabled
[*] [10/20/2021 20:55:23] Write 'mqtt'         : enabled
[*] [10/20/2021 20:55:23] Write 'netflow'      : enabled
[*] [10/20/2021 20:55:23] Write 'metadata'     : enabled
[*] [10/20/2021 20:55:23] Write 'dnp3'         : enabled
[*] [10/20/2021 20:55:23] Write 'anomaly'      : enabled
[*] [10/20/2021 20:55:23] Write 'client_stats' : enabled
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] --[ Elasticsearch output information ]---------------------------
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] URL to connect to       : "https://127.0.0.1:9200/_bulk"
[*] [10/20/2021 20:55:23] Index template          : "suricata_$EVENTTYPE_$YEAR$MONTH$DAY"
[*] [10/20/2021 20:55:23] Batch size per/POST     : 100
[*] [10/20/2021 20:55:23] Threads                 : 10
[*] [10/20/2021 20:55:23] Authentication          : enabled
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Record 'alert'    : enabled
[*] [10/20/2021 20:55:23] Record 'files'    : enabled
[*] [10/20/2021 20:55:23] Record 'flow'     : enabled
[*] [10/20/2021 20:55:23] Record 'dns'      : enabled
[*] [10/20/2021 20:55:23] Record 'http'     : enabled
[*] [10/20/2021 20:55:23] Record 'tls'      : enabled
[*] [10/20/2021 20:55:23] Record 'ssh'      : enabled
[*] [10/20/2021 20:55:23] Record 'smtp'     : enabled
[*] [10/20/2021 20:55:23] Record 'email'    : enabled
[*] [10/20/2021 20:55:23] Record 'fileinfo' : enabled
[*] [10/20/2021 20:55:23] Record 'dhcp'     : enabled
[*] [10/20/2021 20:55:23] Record 'stats'    : enabled
[*] [10/20/2021 20:55:23] Record 'rdp'      : enabled
[*] [10/20/2021 20:55:23] Record 'sip'      : enabled
[*] [10/20/2021 20:55:23] Record 'ftp'      : enabled
[*] [10/20/2021 20:55:23] Record 'nfs'      : enabled
[*] [10/20/2021 20:55:23] Record 'tftp'     : enabled
[*] [10/20/2021 20:55:23] Record 'smb'      : enabled
[*] [10/20/2021 20:55:23] Record 'mqtt'     : enabled
[*] [10/20/2021 20:55:23] Record 'dcerpc'   : enabled
[*] [10/20/2021 20:55:23] Record 'netflow'  : enabled
[*] [10/20/2021 20:55:23] Record 'metadata' : enabled
[*] [10/20/2021 20:55:23] Record 'dnp3'     : enabled
[*] [10/20/2021 20:55:23] Record 'anomaly'  : enabled
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Spawning 10 Elasticsearch threads.
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] --[ Meer engine information ]-------------------------------------
[*] [10/20/2021 20:55:23] 
[*] [10/20/2021 20:55:23] Successfully opened /home/champ/test.eve
[*] [10/20/2021 20:55:23] Skipping to record 2345 in /home/champ/test.eve
[*] [10/20/2021 20:55:23] Reached target record of 2345.  Processing new records.
[*] [10/20/2021 20:55:23] Read in 2345 lines
[*] [10/20/2021 20:55:23] Waiting for new data......

