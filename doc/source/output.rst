
Output Plugins
==============

redis
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
    key: "suricata"          # Default 'channel' to use.  If none is specified, the
                             # channel name will become the "event_type".
                             # (ie - alert, dhcp, dns, flow, etc).
    mode: lpush              # How to publish data to Redis.  Valid types are
                             # "list" ("lpush"), "rpush", "channel" ("publish"),
                             # "set".
    append_id: disabled      # If enabled, this will append the "hostname" and
                             # waldo position to the key.  For example,  the
                             # Redis object can become "alert|hostname|1". This
                             # is good when you are using the "set" mode.

    routing:

      - alert
      - files
      - flow
      - dns
      - http
      - tls
      - ssh
      - smtp
      - email
      - fileinfo
      - dhcp
      - stats
      - rdp
      - sip
      - ftp
      - ikev2
      - nfs
      - tftp
      - smb
      - dcerpc
      - mqtt
      - netflow
      - metadata
      - dnp3
      - anomaly
      - fingerprint

    # This controls sending Sagan client tracking data to Redis.  This has no affect 
    # on Suricata systems. 

      - client_stats


The ``mode`` controls how data is stored to Redis.  Valid options are ``list``, ``lpush``, 
``rpush``, ``channel`` or ``publish``.  The default is ``list``.  The method Meer stores the
data is compatible with Suricata's Redis output format.  Note; This option does not have any
affect on ``client_stats`` or ``fingerprint`` recording.

The ``routing`` option tells Meer "what" Suricata or Sagan to store in Redis.


elasticsearch
-------------

This option enables the Elasticsearch output.  This option is compatible with 
Opensearch, Elasticsearch and Zincsearch (https://github.com/zinclabs/zinc).

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
    batch: 100                                          # Batch size per/writes.
    threads: 10                                         # Number of "writer" threads.
    #username: "myusername"
    #password: "mypassword"

    routing:

      - alert
      - files
      - flow
      - dns
      - http
      - tls
      - ssh
      - smtp
      - email
      - fileinfo
      - dhcp
      - stats
      - rdp
      - sip
      - ftp
      - ikev2
      - nfs
      - tftp
      - smb
      - dcerpc
      - mqtt
      - netflow
      - metadata
      - dnp3
      - anomaly
      - fingerprint
      - ndp


external
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

    #meer_metadata: enabled
    #cisco_policies: "policy-security-ips,policy-max-detect-ips,policy-connectivity-ips,policy-balanced-ips"
    #et_signature_severity: "critical,major"		# Critical,Major,Minor,Informational

    # You likely don't want to route to much data to a external program. External
    # output is slow.

    routing:

      - alert


pipe
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

    routing:

      - alert
      - files
      - flow
      - dns
      - http
      - tls
      - ssh
      - smtp
      - email
      - fileinfo
      - dhcp
      - stats
      - rdp
      - sip
      - ftp
      - ikev2
      - nfs
      - tftp
      - smb
      - dcerpc
      - mqtt
      - netflow
      - metadata
      - dnp3
      - anomaly
      - fingerprint
  

syslog
------

This allows you to route Suricata and Sagan EVE data to syslog.  You can then use
your favorite syslog daemon (syslog-ng, rsyslog) to route the EVE data to it's
final destination. 

::


  ###########################################################################
  # syslog
  # 
  # The 'syslog' output plugin write EVE data to syslog.  You can then use 
  # your favorite syslog daemon (rsyslog, syslog-ng, etc) to route data to 
  # its final destination.
  ###########################################################################

  syslog:

    enabled: yes
    facility: LOG_AUTH
    priority: LOG_ALERT
    extra: LOG_PID

    routing:

      - alert

