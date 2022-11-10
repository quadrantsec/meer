Meer configuration:
=====================

Meers operations are mainly controlled by the ``meer.yaml`` file.  The configuration file is split into three sections.  The ``meer-core`` controls how Meer processes incoming data from EVE files.  The ``input-plugins`` controls how Meer receives data.  The ``output-plugins`` controls how data extracted from the EVE files is transported to a database backend.  To view a full example ```meer.yaml``` configuration file,  go to: https://github.com/quadrantsec/meer/blob/main/etc/meer.yaml

'core' options
-------------------

Below describes the options in the `core` section of the ``meer.yaml``.

hostname
~~~~~~~~

Texts field that is added to Suricata/Sagan EVE JSON.  This short text field represents
"were" the data is originating from.  This is a required option. For example:::

  hostname: "awesome-sensor.example.com"

interface
~~~~~~~~~

This describes in what interface the data was collected.  With Suricata, this might description 
the device network traffic is being acquired from ("etho", "bridge0", etc).  With Sagan, this 
might describe log sources ("windows-logs", "cisco-logs", etc).  This is a required option.  For example:::

  interface: "eth0"

description
~~~~~~~~~~~

This is a text field that description the sensor (what it is monitoring, etc).  This is typically
a short sentence.  For example:::

  description: "DMZ - web services and SQL databases". 

This data is add to the Suricata or Sagan EVE data. 

type
~~~~

The ``type`` is a single text field to describe the sensor.  At Quadrant Information Security, 
we use this field to describe the sensor function in life.  For example:::

  type: "pie"           # PIE == Packet Inspection Engine / LAE == Log Analysis Engine

payload-buffer-size
~~~~~~~~~~~~~~~~~~~

The max memory to be allocate per EVE log line.  This should match you Suricata or Sagan buffer size.  If you
EVE data is being truncated, consider increasing this.  The default a ```1mb`` of RAM:::

  payload-buffer-size: 1024kb  # Can end with kb, mb, gb. 

runas
~~~~~

This is the user name the Meer process should "run as".  You will likely 
want to run Meer as the same user name that is collecting information (for example, 
"suricata" or "sagan").  The ``runas`` can protect your system from security flaws in
Meer.  **Do not run as "root"**.  This option is required:::

  runas: "suricata"

classification
~~~~~~~~~~~~~~

The ``classification`` option tells Meer where to find classification types.  This file
typically ships with Sagan, Suricata, and Snort rules.  It defines a 'classtype' (for 
example, "attempt-recon") and assigns a numeric priority to the event.  This option is
required:::

  classification: "/etc/suricata/classification.config"

meer_log
~~~~~~~~

The ``meer_log`` is the location of the file for Meer to record errors and statistics 
to.  The file will need to be writable by the same user specified in the ``runas`` 
option.  If not specified,  the default file location is ``/var/log/meer.log``.:::

  meer_log: "/var/log/meer/meer.log"

lock_file
~~~~~~~~~

The ``lock_file`` is used to help avoid multiple Meer processes from processing the
same data.  The lock_file should be unique per Meer instance.   The lock file contains
the process ID (PID) of instance of Meer.  This option is required.:::

  lock_file: "/var/log/meer/meer.lck"

input-type
~~~~~~~~~~

This tells Meer where to acquire data from.  This controls which input plugin (``input-plugins``) to 
use.  This option is required.:::

  input-type: "file"

calculate-stats
~~~~~~~~~~~~~~~

When statistics (event_type "stats") from Suricata are collected,  they are represented in a accumulated 
manor (ie - "1000,2000,3000,4000").  While this works well for some utilities (rrdtool , librenms, etc),
it doesn't work well with others (SQL databases, etc).  When this option is enabled,  Meer will track and
do the math to convert the statistics as a accumulated metric (ie "1000, 2000, 3000, 4000") to time based, 
between "stats" metric (ie - "1000,1000,1000,1000").  Another example would be,  rather than reporting
Suricata has seen X number of bytes since this initial start of Suricata,  X number of bytes has been seen
since the last statistics where reported.  This option does not process all ``stats`` but rather a small
subset.  They are ``kernel_packets``, ``kernel_drops``, ``errors``, ``bytes``, ``invalid``, ``ipv4``, 
``ipv6``, ``tcp`` and ``udp``.  When the ``calculate-stats`` option is enabled,  a new JSON nest is added
to the event_type ``stats`` with these aggregate statistics. :::

  calculate-stats: false


fingerprint
~~~~~~~~~~~

The ``fingerprint`` option tells Meer to decode "fingerprint" rules and route the
data differently.  Fingerprint rules do not work like normal rules.  The data from
these rules is used to passively fingerprint systems for operating systems and types
(client/server).  This information can be valuable to determine if an attack might have
been successful or not.  

For a full explanation of our Meer handles Suricata and Sagan "fingerprinting" signatures, 
please watch Jeremy Groves "Passive Fingerprinting Suricata" on Youtube 
(https://www.youtube.com/watch?v=n5O4-iqAlVo). :::


    fingerprint: disabled
    fingerprint_networks: "10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12"

    fingerprint_reader: enabled         # This option appends "fingerprint"
                                        # data to "alert".

    fingerprint_writer: enabled         # This option detects "fingerprint"
                                        # alerts and writes them to Redis.


The ``fingerprint_networks`` are you networks.  These are the IP address spaces we want to record
device fingerprint data from.  The ``fingerprint_reader`` tells Meer to "append" fingerprint 
data to ``alert`` EVE JSON.  The ```fingerprint_writer`` configures Meer to "write" fingerprint 
data about devices to Redis.  By default, this option is disabled.

client_stats
~~~~~~~~~~~~

This option has no affect on Suricata data.  This option can be used when processing Sagan data.  The
``client_stats`` option works in conjunction with the Sagan ``client-stats`` option.  The basic concept
is that Sagan will write out information at intervals (example log data, bytes sent from individual clients, 
etc). This option will read in this JSON and report it to a Redis backend.  By default, this option is disabled.:::

  client_stats: disabled

oui_lookup
~~~~~~~~~~

When Meer encounters a MAC address within an EVE file,  it will lookup the vendor of the MAC address.  This 
data is added to the EVE JSON.  By default, this is disabled. :::

    oui_lookup: disabled
    oui_filename: "/usr/local/etc/manuf"	
						# https://gitlab.com/wireshark/wireshark/raw/master/manuf
						# This file contains MAC/OUI data.



dns
~~~

The ``dns`` option tells Meer to perform a DNS PTR (reverse) record lookup of the 
IP addresses involved in an alert.  This option is useful because it records the
DNS in your EVE JSON at the time the event occurred.  This is enabled by default. :::

    dns: enabled
    dns_cache: 900      			# Time in seconds / cache timeout
    dns_lookup_types: "alert,ssh,http,rdp,ftp"  # The event_type to do DNS
                                                # PTR lookups for.  This can
                                                # be the event_type or "all".


When ``dns`` is enabled,  Meer will internally cache records to avoid repetitive
lookups.  For example, if 1000 alerts come in from a single IP address,  Meer
will look up the DNS PTR record one time and use the cache for the other 999
times.   This saves on lookup time and extra stress on the internal DNS server.  If you
do not want Meer to cache DNS data,  simply set this option to 0.  The ``dns_cache``
time is in seconds.

``dns_lookup_types`` are Suricata ``event_types`` that DNS queries will be performed 
on. 

geoip
~~~~~

If Meer is compiled with the ``--enable-geoip`` option,  this will allow Meer to do 
GeoIP lookups from a Maxmind (https://maxmind.com) data.  GeoIP information is stored
within the EVE JSON as a new JSON nest named ``geoip_src`` and ``geoip_dest``.  This 
data can include country code, subdivision, City, postal code, timezone, longitude and
longitude.  By default, this option is disabled. :::

    geoip: disabled
    geoip_database: "/usr/local/share/GeoIP2/GeoLite2-City.mmdb"

The ``geoip_database`` is the location of your Maxmind database file.  This is loaded when
Meer is started.  You can download GeoIP "Lite" databases from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data


ndp-collector
~~~~~~~~~~~~~

The NDP collector (Network Data Point) is an option of distilling data from Suricata into "non-repetitive"
data points.  The concept is that store data into Elasticsearch, Opensearch or Zincsearch 
(https://github.com/zinclabs/zinc) for "quick" IOC (Indicator of Compromise) searches.  Since the data
is "non-repetitive",  the NDP collector only stores the minimal amount of data around an event.  This option
is disabled by default.  We will be adding more information about this option as it comes available. :::

    ndp-collector: disabled
    ndp-debug: disabled
    ndp-ignore-networks: "10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12"
    ndp-routing: "flow, http, ssh, fileinfo, tls, dns, smb, ftp"

    ndp-smb: "SMB2_COMMAND_CREATE, SMB2_COMMAND_WRITE"
    ndp-smb-internal: true

    ndp-ftp: "STOR, RETR, USER"

The ``ndp-ignore-networks`` should represent any public or internal network blocks you use.  The NDP collector
not store data about these networks as they are typically not useful for rapid IoC searches.

The ``ndp-routing`` tells Meer where to pull non-repetitive data from.  Since we are storing non-repetitive
data,  the only options are flow, http, ssh, fileinfo, tls, dns, smb and ftp.

The ``ndp-smb`` option configures Meer to only store SMB command related to this list.  Typically,  to keep
datasets small,  we only want to record SMB2_COMMAND_CREATE and SMB2_COMMAND_WRITE.  Because SMB is not 
typically used over the Internet, the ``ndp-smb-internal`` option configures Meer to record all internal
SMB traffic.   This is done because SMB is used by attackers to move laterally within a network.

The ``ndp-ftp`` option records FTP traffic but only commands related to this list. 

If this option is being used,  use the ``input-type`` of ``redis`` is probably the most efficient. 


