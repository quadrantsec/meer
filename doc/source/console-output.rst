Console Output
==============

Console/Log Startup
-------------------

At start up,  the logs and console output give you information about the status of Meer. 
For example,  you will want to note the ``SQL information``,  such as the driver and whether
a successful connection was made.  If there is a problem making a connection to your database, 
Meer will display the error that is causing the issues. 

Another important item to note is the database sensor ID.  This will be the ID number used in
the database to store events. 

Common issues are database rights and directory/file permission problems. 

If Meer makes it to the ``Waiting of new data...``,  then Meer has successfully started. 

::

[*] [11/09/2018 03:24:29] -  @@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    Meer version 0.0.3-git
[*] [11/09/2018 03:24:29] -  @@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security
[*] [11/09/2018 03:24:29] -  @!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com
[*] [11/09/2018 03:24:29] -  !!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018
[*] [11/09/2018 03:24:29] -   :      :   : :: ::  : :: ::   :   : :
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] - Dropping privileges! [UID: 999 GID: 999]
[*] [11/09/2018 03:24:29] - Classifications file loaded [/etc/suricata/classification.config].
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] - Decode 'json'    : enabled
[*] [11/09/2018 03:24:29] - Decode 'metadata': enabled
[*] [11/09/2018 03:24:29] - Decode 'flow'    : enabled
[*] [11/09/2018 03:24:29] - Decode 'http'    : enabled
[*] [11/09/2018 03:24:29] - Decode 'tls'     : enabled
[*] [11/09/2018 03:24:29] - Decode 'ssh'     : enabled
[*] [11/09/2018 03:24:29] - Decode 'smtp'    : enabled
[*] [11/09/2018 03:24:29] - Decode 'email'   : enabled
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] - Waldo loaded. Current position: 191000
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] - --[ SQL information ]--------------------------------------------
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] - SQL Driver: MySQL/MariaDB
[*] [11/09/2018 03:24:29] - Extra data: enabled
[*] [11/09/2018 03:24:29] - Legacy Reference System': disabled
[*] [11/09/2018 03:24:29] - 
[*] [11/09/2018 03:24:30] - Successfully connected to MySQL/MariaDB database. 
[*] [11/09/2018 03:24:30] - Using Database Sensor ID: 1 
[*] [11/09/2018 03:24:30] - Last CID: 586325 
[*] [11/09/2018 03:24:30] - 
[*] [11/09/2018 03:24:30] - Recird 'json'    : enabled
[*] [11/09/2018 03:24:30] - Record 'metadata': enabled 
[*] [11/09/2018 03:24:30] - Record 'flow'    : enabled 
[*] [11/09/2018 03:24:30] - Record 'http'    : enabled 
[*] [11/09/2018 03:24:30] - Record 'tls'     : enabled 
[*] [11/09/2018 03:24:30] - Record 'ssh'     : enabled 
[*] [11/09/2018 03:24:30] - Record 'smtp'    : enabled 
[*] [11/09/2018 03:24:30] - Record 'email'   : enabled 
[*] [11/09/2018 03:24:30] - 
[*] [11/09/2018 03:24:30] - --------------------------------------------------------------------------- 
[*] [11/09/2018 03:24:30] - Skipping to record 191000 in /var/log/suricata/alert.json 
[*] [11/09/2018 03:24:31] - Reached target record of 191000.  Processing new records. 
[*] [11/09/2018 03:24:31] - Read in 191000 lines 
[*] [11/09/2018 03:24:31] - Waiting for new data...... 


Console/Log Shutdown
--------------------

Upon shutdown,  the Meer console and logs provide information about the previous execution.  For
example,  how efficient DNS caching performed,  how much data was stored in flow, http, tls, 
ssh, smtp, and meta data tables, and how efficient SQL caches performed.  It also displays the last
``Waldo Position``,  which indicates what position it left off in the file.   Another important 
item to note is the ``CID``,  which is the last database position Meer left off. 


::

[*] [11/09/2018 03:24:29] - --[ Meer Statistics ]---------------------------------------
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] -  - Decoded Statistics:
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] -  Waldo Postion : 191000
[*] [11/09/2018 03:24:29] -  JSON          : 8987
[*] [11/09/2018 03:24:29] -  Flow          : 8987
[*] [11/09/2018 03:24:29] -  HTTP          : 8889
[*] [11/09/2018 03:24:29] -  TLS           : 0
[*] [11/09/2018 03:24:29] -  SSH           : 16
[*] [11/09/2018 03:24:29] -  SMTP          : 0
[*] [11/09/2018 03:24:29] -  Email         : 0
[*] [11/09/2018 03:24:29] -  Metadata      : 8782
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] -  - DNS Statistics:
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] -  DNS Lookups   : 7374
[*] [11/09/2018 03:24:29] -  DNS Cache Hits: 45780 (86.127%)
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] -  - MySQL/MariaDB Statistics:
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] -  Health Checks          : 17590
[*] [11/09/2018 03:24:29] -  INSERT                 : 88920
[*] [11/09/2018 03:24:29] -  SELECT                 : 104
[*] [11/09/2018 03:24:29] -  UPDATE                 : 26578
[*] [11/09/2018 03:24:29] -  Class Cache Misses     : 15
[*] [11/09/2018 03:24:29] -  Class Cache Hits       : 26562 (99.944%)
[*] [11/09/2018 03:24:29] -  Signature Cache Misses : 15
[*] [11/09/2018 03:24:29] -  Signature Cache Hits   : 26562 (99.944%)
[*] [11/09/2018 03:24:29] -
[*] [11/09/2018 03:24:29] - Last CID is : 586325.
[*] [11/09/2018 03:24:29] - Shutdown complete.

