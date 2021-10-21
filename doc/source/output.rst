
Output Plugins
==============

Redis
-----

This controls how Meer logs to a Redis database.  Meer can record alert records to 
Redis similar to how Suricata with Redis support enabled does.  Redis is also used
as a temporary storage engine for ``client_stats`` (Sagan only) and ``fingerprint``
data if enabled.

::

  ###########################################################################
  # redis
  # 
  # This allows you to send Suricata/Sagan EVE data to a Redis database. 
  # This will mimic the way Suricata writes EVE data to Redis with the 
  # exception of "client_stats" which is a Sagan specific processor. 
  ###########################################################################

  redis:

    enabled: no
    debug: no
    server: 127.0.0.1
    #password: "mypassword"
    port: 6379
    batch: 1                 # Batching (pipelining) data.  When set to 1, 
                             # no batching is performed and data is immediately 
                             # sent to Redis.  If increase,  data is batched 
                             # and sent in bulk to increase performance.  The max
                             # is 100.
    key: "suricata"	     # Default 'channel' to use.  If none is specified, the 
                             # channel name will become the "event_type".
                             # (ie - alert, dhcp, dns, flow, etc). 
    mode: lpush              # How to publish data to Redis.  Valid types are 
                             # "list" ("lpush"), "rpush", "channel" ("publish"), 
                             # "set".
    append_id: disabled      # If enabled, this will append the "hostname" and
                             # waldo position to the key.  For example,  the 
                             # Redis object can become "alert|hostname|1". This
                             # is good when you are using the "set" mode. 

    # This controls event_types to send to Redis. 

    alert: enabled
    files: enabled
    flow: enabled
    dns: enabled
    http: enabled
    tls: enabled
    ssh: enabled
    smtp: enabled
    email: enabled
    fileinfo: enabled
    dhcp: enabled
    stats: enabled
    rdp: enabled
    sip: enabled
    ftp: enabled
    ikev2: enabled
    nfs: enabled
    tftp: enabled
    smb: enabled
    dcerpc: enabled
    mqtt: enabled
    netflow: enabled
    metadata: enabled
    dnp3: enabled
    anomaly: enabled

    # Fingerprint data can be temporarily stored in a Redis database.  When an alert
    # fires, this information can be used to determine the targets operating system, 
    # type (client/server), etc.  This can be useful in determining the validity of
    # an event. If used in conjunction with the SQL output,  the fingerprint data for
    # the targeted system is stored in the 'fingerprint' table.

    fingerprint: enabled

    # This controls sending Sagan client tracking data to Redis.  This has no affect 
    # on Suricata systems. 

    client_stats: disabled

enabled
~~~~~~~

Enable or disable the Redis output.

debug
~~~~~

Enable or disabled Redis debugging.

server
~~~~~~

The Redis server address you want to store data to.

port
~~~~

Port of the target Redis server.

batch
~~~~~

The ``batch`` is the amount of data to collect before sending it to Redis.  This has no 
affect when using Redis with either ``client_stats`` or ``fingerprint`` data.

key
~~~

The ``key`` is the default Redis channel or key to use. 

mode
~~~~

The ``mode`` controls how data is stored to Redis.  Valid options are ``list``, ``lpush``, 
``rpush``, ``channel`` or ``publish``.  The default is ``list``.  The method Meer stores the
data is compatible with Suricata's Redis output format.  Note; This option does not have any
affect on ``client_stats`` or ``fingerprint`` recording.

alert
~~~~~

Enable or disable storing ``alert`` data into Redis.

files
~~~~~

Enable or disable storing ``files`` data into Redis.

flow
~~~~

Enable or disable storing ``flow`` data into Redis.

dns
~~~

Enable or disable storing ``dns`` data into Redis.

http
~~~~

Enable or disable storing ``http`` data into Redis.

tls
~~~

Enable or disable storing ``tls`` data into Redis.

ssh
~~~

Enable or disable storing ``ssh`` data into Redis.

smtp
~~~~

Enable or disable storing ``smtp`` data into Redis.

fileinfo
~~~~~~~~

Enable or disable storing ``fileinfo`` data into Redis.

dhcp
~~~~

Enable or disable storing ``dhcp`` data into Redis.


fingerprint
~~~~~~~~~~~

Enable or disable storing ``fingerprint`` data in the Redis database.  This is a temporary 
storage system for ``fingerprint`` data.   This allows correlation between device fingerprints
(ie - operating systems, devices types, etc) with alerts. 

client_stats
~~~~~~~~~~~~

This is a Sagan only option.  This option temporarily stores devices that are sending Sagan 
logs along with an example log entry.   This has no affect with Suricata. 

Elasticsearch
-------------

This option enables the Elasticseaerch output.

::

  ###########################################################################
  # elasticsearch
  #
  # This section allows you to route data to Elasticsearch.  This module 
  # supports authentication and TLS support.
  ###########################################################################

  elasticsearch:

    enabled: no
    debug: no
    url: "http://127.0.0.1:9200/_bulk"
    index: "suricata_$EVENTTYPE_$YEAR$MONTH$DAY"
    insecure: true                                      # Only applied when https is used.
    batch: 100						# Batch size per/writes.
    threads: 10						# Number of "writer" threads.
    #username: "myusername"
    #password: "mypassword"

    alert: enabled
    files: enabled
    flow: enabled
    dns: enabled
    http: enabled
    tls: enabled
    ssh: enabled
    smtp: enabled
    email: enabled
    fileinfo: enabled
    dhcp: enabled
    stats: enabled
    rdp: enabled
    sip: enabled
    ftp: enabled
    ikev2: enabled
    nfs: enabled
    tftp: enabled
    smb: enabled
    dcerpc: enabled
    mqtt: enabled
    netflow: enabled
    metadata: enabled
    dnp3: enabled
    anomaly: enabled


External
--------

This option allows signatures to call "external" programs.  For example,  if a signature the
proper "metadata" (``metadata: meer external`` or a set policy),  Meer will fork a copy
of the specified program and pass the EVE via stdin.  This feature can be useful for creating
custom firewalling routines or routing data to alternate programs.  The "external" program
can be written in any language that suites you.

::
  
  ###########################################################################
  # external 
  #
  # EVE data (JSON) is passed via stdin to the external program.   The 
  # external program can be written in any language you choose (shell script, 
  # Python, Perl, etc). 
  #
  # This can be useful for automatic firewalling,  building block lists, 
  # replicating "snortsam" functionality, etc.  See the "tools/external"
  # directory for example routines that use this feature.
  #
  # If this option is enabled, any rule that has the metadata of "meer 
  # external" (ie - "metadata:meer external") will cause the external script 
  # to be executed.  Execution can also be controlled by Snort metadata
  # "policies".
  ###########################################################################

  external:

    enabled: no
    debug: no

    # Execution of an external program based on metadata "policy".  When Meer
    # encounters a "policy" (security-ips, balanced-ips, connectivity-ips, 
    # and max-detect-ips),  Meer will execute the specified routine.  
    # Currently only Snort rules have these types of polices.  This can be
    # useful when you want to execute an external script that will to "block"
    # or "firewall" based off the policy types.  This section only applies if
    # you are using Suricata with Snort rules.  Snort's polices are
    # below:

    # connectivity-ips  - You run a lot of real time applications (VOIP, 
    # financial transactions, etc), and don't want to run any rules that 
    # could affect the current performance of your sensor.  The rules in this 
    # category make snort happy, additionally this category focuses on the high
    # profile most likely to affect the largest number of people type of
    # vulnerabilities.

    # balanced-ips - You are normal, you run normal stuff and you want normal
    # security protections.  This is the best policy to start from if you are 
    # new, old, or just plain average.  If you don't have any special
    # requirements for super high speeds or super secure networks start here.

    # security-ips - You don't care about dropping your bosses email, everything
    # in your environment is tightly regulated and you don't tolerate people 
    # stepping outside of your security policy.  This policy hates on IM, P2P,
    # vulnerabilities, malware, web apps that cause productivity loss, remote
    # access, and just about anything not related to getting work done.  
    # If you run your network with an iron fist start here.

    # I can't seem to find any documentation on what "max-detect-ips" is :(
   
    program: "/usr/local/bin/external_program"

    meer_metadata: enabled
    cisco_policies: "policy-security-ips,policy-max-detect-ips,policy-connectivity-ips,policy-balanced-ips"
    et_signature_severity: "critical,major"		# Critical,Major,Minor,Informational


    alert: enabled
    files: disabled
    flow: disabled
    dns:  disabled
    http: disabled
    tls: disabled
    ssh: disabled
    smtp: disabled
    email: disabled
    fileinfo: disabled
    dhcp: disabled
    stats: disabled
    rdp: disabled
    sip: disabled
    ftp: disabled
    ikev2: disabled
    nfs: disabled
    tftp: disabled
    smb: disabled
    dcerpc: disabled
    mqtt: disabled
    netflow: disabled
    metadata: disabled
    dnp3: disabled
    anomaly: disabled


enabled
~~~~~~~

Keyword is used to enable/disable ``external`` output. 

debug
~~~~~

When enabled,  this option will display and log debugging information. 

policy-security-ips
~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-security-ips`` is encountered.

policy-max-detect-ips
~~~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-max-detect-ips`` is encountered.

policy-connectivity-ips
~~~~~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-connectivity-ips`` is encountered.

policy-balanced-ips
~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-balanced-ips`` is encountered.


program
~~~~~~~

``external`` program to execute when conditions are met. 



Pipe
----

Below is an example of the "pipe" output plugin.  This takes data being written to the EVE
file and puts it into a named pipe (FIFO).  This can be useful if you want a third party
program (for example, Sagan - https://sagan.io) to analyze the data. 

::
  
  ###########################################################################
  # pipe
  # 
  # This allows Meer to send a copy of an event to a named pipe (FIFO) in 
  # its raw,  JSON form.  This allows for third party tools, like Sagan, 
  # to do further analysis on the event. 
  ###########################################################################
  
  pipe:

    enabled: no
    pipe_location: /var/sagan/fifo/sagan.fifo
    pipe_size: 1048576                        # System must support F_GETPIPE_SZ/F_SETPIPE_SZ

    # Below are the "event_types" from Suricata/Sagan. This tells Meer what to send
    # to the named pipe/FIFO. 

    alert: enabled
    files: enabled
    flow: enabled
    dns: enabled
    http: enabled
    tls: enabled
    ssh: enabled
    smtp: enabled
    email: enabled
    fileinfo: enabled
    dhcp: enabled
    stats: enabled
    rdp: enabled
    sip: disabled
    ftp: enabled
    ikev2: enabled
    nfs: enabled
    tftp: enabled
    smb: enabled
    dcerpc: enabled
    mqtt: enabled
    netflow: enabled
    metadata: enabled
    dnp3: enabled
    anomaly: enabled


enabled
~~~~~~~

Enabled/disabled the 'pipe' output. 

pipe_location
~~~~~~~~~~~~~

Location of the named pipe on the file system.

pipe_size
~~~~~~~~~

Number of bytes will set the size of the named pipe/FIFO to.  

metadata
~~~~~~~~

This option controls Meer's ability to record decoded alert metadata to the named pipe.
If "metadata" is detected within the EVE/JSON  and the ``metadata``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded to the named
pipe.

flow
~~~~

This option controls Meer's ability to record decoded alert flow to named pipe.
If "flow" is detected within the EVE/JSON  and the ``flow``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded to the 
named pipe.

http
~~~~

This option controls Meer's ability to record decoded alert http to the named pipe.
If "http" is detected within the EVE/JSON  and the ``http``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the named pipe.

tls
~~~

This option controls Meer's ability to record decoded alert tls to the named pipe.
If "tls" is detected within the EVE/JSON  and the ``tls``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the named pipe.

ssh
~~~

This option controls Meer's ability to record decoded alert ssh to the named pipe.
If "ssh" is detected within the EVE/JSON  and the ``ssh``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the named pipe.

smtp
~~~

This option controls Meer's ability to record decoded alert smtp to the named pipe.
If "smtp" is detected within the EVE/JSON  and the ``smtp``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the named pipe.

email
~~~~~

This option controls Meer's ability to record decoded alert email to the named pipe.
If "email" is detected within the EVE/JSON  and the ``email``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the named pipe.  This is not to be confused with the ``smtp`` table.

fileinfo
~~~~~~~~

This option controls Meer's ability to record decoded alert fileinfo to the named pipe.
If "fileinfo" is detected within the EVE/JSON  and the ``fileinfo``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the named pipe.

dhcp
~~~~

This option controls Meer's ability to record decoded alert dhcp to the named pipe.
If "dhcp" is detected within the EVE/JSON  and the ``dhcp``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the named pipe.



File
----

This configures the 'file' output plugin.

::

  ###########################################################################
  # file
  # 
  # The 'file' output writes post processed EVE data to a file.  For example,
  # if Meer is adding GeoIP and DNS information,  the new JSON data will 
  # written to the 'file_location'.
  ###########################################################################

  file:

    enabled: no
    file_location: "/path/to/output/file"

    alert: enabled
    files: enabled
    flow: enabled
    dns: enabled
    http: enabled
    tls: enabled
    ssh: enabled
    smtp: enabled
    email: enabled
    fileinfo: enabled
    dhcp: enabled
    stats: enabled
    rdp: enabled
    sip: disabled
    ftp: enabled
    ikev2: enabled
    nfs: enabled
    tftp: enabled
    smb: enabled
    dcerpc: enabled
    mqtt: enabled
    netflow: enabled
    metadata: enabled
    dnp3: enabled
    anomaly: enabled


SQL
---

Below is an example of the "output-plugins" from the ``meer.yaml``.  This section controls 
the SQL output.

::

   output-plugins:

     # MySQL/MariaDB output - Stores data from Suricata or Sagan into a semi-
     # traditional "Barnyard2/Snort"-like database.

     sql:

       enabled: yes
       driver: mysql        # "mysql" or "postgresql"
       port: 3306           # Change to 5432 for PostgreSQL
       debug: no
       server: 127.0.0.1
       port: 3306
       username: "XXXX"
       password: "XXXXXX"
       database: "snort_test"

       # Automatically reconnect to the database when disconnected.

       reconnect: enabled
       reconnect_time: 10

       # Store decoded JSON data that is similar to Unified2 "extra" data to the
       # "extra" table.

       extra_data: enabled

       # Store extra decoded JSON metadata from Suricata or Sagan.  This requires
       # your database to have the metadata, flow, http, etc. tables.  If all are
       # disabled,  Meer will store data in strictly a Barnyard2/Snort method.
       # If you want to store this decoded information,  and you likely do,  make
       # sure you have the decoders enabled in the "core" section of this Meer
       # configuration file!

       metadata: enabled
       flow: enabled
       http: enabled
       tls: enabled
       ssh: enabled
       smtp: enabled
       email: enabled
       json: enabled

       # If you would like Meer to mimic the legacy "reference" tables from
       # Snort/Barnyard2, enable it here.  If you are using more than one database
       # to store Suricata or Sagan data, you will likely want to leave this
       # disabled. The legacy reference system is not very efficient and there are
       # better ways to keep track of this data.  This is also a memory hog and
       # performance killer.  See tools/reference_handler/reference_handler.pl to
       # build a centralized reference table.

       reference_system: disabled
       sid_file: "/etc/suricata/rules/sid-msg.map"   # Created with "create-sidmap"
       reference: "/etc/suricata/reference.config"

       #sid_file: "/usr/local/etc/sagan-rules/sagan-sid-msg.map"
       #reference: "/usr/local/etc/sagan-rules/reference.config"


enabled
~~~~~~~

When this option is set to ``yes`` or ``no``, it enables or disables the SQL section of
the Meer output plugin.

driver
~~~~~~

This controls what SQL database driver Meer will use.  Valid types are ``mysql`` (for both
MySQL and MariaDB) and ``postgresql``.

port
~~~~

The port the target SQL server is listening on.

server
~~~~~~

The IP address of the SQL server.

debug
~~~~~

When ``debug`` is enabled,  Meer will display SQL statements and transactions to stdout and to the
``meer_log``.  This can be useful for debugging SQL errors and issues.  By default, this is disabled.

username
~~~~~~~~

The username to use during authentication with the SQL database.

password
~~~~~~~~

The password to use during authentication with the SQL database.

reconnect
~~~~~~~~~

If Meer encounters an issue with connecting to the SQL database,  if this 
option is ``enabled``,  Meer will continually try to reconnect until it is
successful.

reconnect_time
~~~~~~~~~~~~~~

This is how long to pause, in seconds,  before attempting to reconnect to the
SQL database if the ``reconnect`` option is enabled.

extra_data
~~~~~~~~~~

When the ``extra_data`` option is enabled,  Meer will record certain information
(XFF, DNS data,  SMTP data, etc) in the legacy ``extra`` table.  

metadata
~~~~~~~~

This option controls Meer's ability to record decoded alert metadata to the ``metadata``
SQL table.  If "metadata" is detected within the EVE/JSON  and the ``metadata``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the ``metadata`` SQL table. 

flow
~~~~

This option controls Meer's ability to record decoded alert flow to the ``flow``
SQL table.  If "flow" is detected within the EVE/JSON  and the ``flow``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the ``flow`` SQL table.

http
~~~~

This option controls Meer's ability to record decoded alert http to the ``http``
SQL table.  If "http" is detected within the EVE/JSON  and the ``http``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the ``http`` SQL table.

tls
~~~

This option controls Meer's ability to record decoded alert tls to the ``tls``
SQL table.  If "tls" is detected within the EVE/JSON  and the ``tls``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the ``tls`` SQL table.

ssh
~~~

This option controls Meer's ability to record decoded alert ssh to the ``ssh``
SQL table.  If "ssh" is detected within the EVE/JSON  and the ``ssh``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the ``ssh-client``and ``ssh-server`` SQL tables.

smtp
~~~

This option controls Meer's ability to record decoded alert smtp to the ``smtp``
SQL table.  If "smtp" is detected within the EVE/JSON  and the ``smtp``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the ``smtp`` SQL table.

email
~~~~~

This option controls Meer's ability to record decoded alert email to the ``email``
SQL table.  If "email" is detected within the EVE/JSON  and the ``email``
decoder is enabled (controlled in the ``meer-core``),  then it will be recorded
to the ``email`` SQL tables.  This is not to be confused with the ``smtp`` table.

reference_system
~~~~~~~~~~~~~~~~

The ``reference_system`` allows Meer to store alert reference data in a traditional
"Barnyard2" format.  If you are using a single database for all events,  this 
option might be useful to you.  If you are using UIs like Snorby,  Squeel, etc. 
you will likely want to enable this option.  If you are using multiple databases, 
then consider looking at the "reference_handler.pl" script that ships with Meer. 

sid_file
~~~~~~~~

The ``sid_file`` is a legacy "signature message map" file that points signature
IDs to their references.  If you want to use the legacy ``reference_system``, 
you will need a "signature message map" (``sid_file``) for Meer to read.

External
--------

This option allows signatures to call "external" programs.  For example,  if a signature the
proper "metadata" (``metadata: meer external`` or a set policy),  Meer will fork a copy
of the specified program and pass the EVE via stdin.  This feature can be useful for creating
custom firewalling routines or routing data to alternate programs.  The "external" program
can be written in any language that suites you.

::

     ###########################################################################
     # external 
     #
     # EVE data (JSON) is passed via stdin to the external program.   The 
     # external program can be written in any language you choose (shell script, 
     # Python, Perl, etc). 
     #
     # This can be useful for automatic firewalling,  building block lists, 
     # replicating "snortsam" functionality, etc.  See the "tools/external"
     # directory for example routines that use this feature.
     #
     # If this option is enabled, any rule that has the metadata of "meer 
     # external" (ie - "metadata:meer external") will cause the external script 
     # to be executed.  Execution can also be controlled by Snort metadata
     # "policies".
     ###########################################################################

     external:

       enabled: no
       debug: no

       # Execution of an external program based on metadata "policy".  When Meer
       # encounters a "policy" (security-ips, balanced-ips, connectivity-ips, 
       # and max-detect-ips),  Meer will execute the specified routine.  
       # Currently only Snort rules have these types of polices.  This can be
       # useful when you want to execute an external script that will to "block"
       # or "firewall" based off the policy types.  This section only applies if
       # you are using Suricata with Snort rules.  Snort's polices are
       # below:

       # connectivity-ips  - You run a lot of real time applications (VOIP, 
       # financial transactions, etc), and don't want to run any rules that 
       # could affect the current performance of your sensor.  The rules in this 
       # category make snort happy, additionally this category focuses on the high
       # profile most likely to affect the largest number of people type of
       # vulnerabilities.

       # balanced-ips - You are normal, you run normal stuff and you want normal
       # security protections.  This is the best policy to start from if you are 
       # new, old, or just plain average.  If you don't have any special
       # requirements for super high speeds or super secure networks start here.

       # security-ips - You don't care about dropping your bosses email, everything
       # in your environment is tightly regulated and you don't tolerate people 
       # stepping outside of your security policy.  This policy hates on IM, P2P,
       # vulnerabilities, malware, web apps that cause productivity loss, remote
       # access, and just about anything not related to getting work done.  
       # If you run your network with an iron fist start here.

       # I can't seem to find any documentation on what "max-detect-ips" is :(

       policy-security-ips: enabled
       policy-max-detect-ips: enabled
       policy-connectivity-ips: enabled
       policy-balanced-ips: enabled

       program: "/usr/local/bin/external_program"



enabled
~~~~~~~

Keyword is used to enable/disable ``external`` output. 

debug
~~~~~

When enabled,  this option will display and log debugging information. 

policy-security-ips
~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-security-ips`` is encountered.

policy-max-detect-ips
~~~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-max-detect-ips`` is encountered.

policy-connectivity-ips
~~~~~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-connectivity-ips`` is encountered.

policy-balanced-ips
~~~~~~~~~~~~~~~~~~~

Execute ``external`` program when the ``policy-balanced-ips`` is encountered.


program
~~~~~~~

``external`` program to execute when conditions are met. 

