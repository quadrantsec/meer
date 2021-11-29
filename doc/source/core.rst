'core' configuration:
=====================

Meers operations are mainly controlled by the ``meer.yaml`` file.  The configuration file is split into two sections.  The ``meer-core`` controls how Meer processes incoming data from EVE files.  The ``output-plugins`` controls how data extracted from the EVE files is transported to a database backend.

'meer-core' example
-------------------

::

  meer-core:

  core:

    hostname: "mysensor"  # Unique name for this sensor (no spaces)
    interface: "eth0"     # Can be anything.  Sagan "syslog", suricata "eth0".

    description: "My awesome sensor!"   # Description of this sensor.  This 
                                        # will be added to _all_ logs!

    payload-buffer-size: 1024kb         # This is the max size buffer that can
                                        # be read in/written out.  It should
                                        # match your payload-buffer-size in 
                                        # Surcata or be larger.  Valid 
                                        # Notations are "kb", "mb" and "gb".

    runas: "suricata"     # User to "drop privileges" too. 
    #runas: "sagan"

    classification: "/etc/suricata/classification.config"
    #classification: "/usr/local/etc/sagan-rules/classification.config"

    meer_log: "/var/log/meer/meer.log"          # Meer log file
    waldo_file: "/var/log/meer/meer.waldo"      # Where to store the last 
                                                # position in the 
                                                # "follow-eve" file. 

    lock_file: "/var/log/meer/meer.lck"         # To prevent dueling processes.

    follow_eve: "/var/log/suricata/alert.json"  # The Suricata/Sagan file to monitor
    #follow-eve: "/var/log/sagan/alert.json"   

   #########################################################################
    # fingerprint
    #
    # This enables the "fingerprint" option.  When used in conjunction with the 
    # "fingerprint.rules" (https://github.com/quadrantsec/fingerprint-rules), 
    # this will record things like operating system type,  type of system it is
    # (client/server), etc.  This data get routed differently and does not 
    # generate "alerts". 
    #########################################################################

    fingerprint: enabled
    fingerprint_networks: "10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12"
    #########################################################################
    # client_stats
    #
    # "client_stats" are specific to Sagan and allow Sagan/Meer to record
    # information about systems sending Sagan data.  This has no affect on 
    # Suricata. 
    #########################################################################

    client_stats: disabled

    #########################################################################
    # oui_lookup
    #
    # The "oui_lookup" allows Meer to lookup vender information based off
    # a MAC address.  Information is stored in fingerprinting JSON.  The
    # MAC/OUI database
    #
    # https://gitlab.com/wireshark/wireshark/raw/master/manuf
    #########################################################################

    oui_lookup: disabled
    oui_filename: "/usr/local/etc/manuf"

   #########################################################################
    # dns
    #
    # If "dns" is enabled, Meer will do reverse DNS (PTR) lookups of an IP. 
    # The "dns_cache" is the amount of time Meer should "cache" a PTR record
    # for.  The DNS cache prevents Meer from doing repeated lookups of an 
    # already looked up PTR record.  This reduces overloading DNS servers.
    #########################################################################

    dns: enabled
    dns_cache: 900      # Time in seconds. 

    #########################################################################
    # geoip
    #
    # If "geoip" is enabled, Meer will add GeoIP information (JSON) to 
    # "alert" data.  You'll need to compile Meer with Maxmind's GeoIP
    # support (--enable-geoip). Data that will be added,  when available, 
    # includes ISO country code, city, subdivision, postal code, 
    # timezone,  latitude and longitude. 
    #########################################################################

    geoip: disabled
    geoip_database: "/usr/local/share/GeoIP2/GeoLite2-City.mmdb"


'meer-core' options
-------------------

Below describes the options in the `meer-core` section of the ``meer.yaml``.

hostname
~~~~~~~~

This is stored in the database in the ``sensor`` table under the ``hostname`` column. 
 The ``interface`` is appended to the ``hostname``.  This option is required.

interface
~~~~~~~~~

The ``interface`` is stored in the ``sensor`` table appended to the ``hostname`` and 
``interface`` columns.  This describes in what interface the data was collected.  This can 
be any descriptive string.  For example, "eth0", "syslog", etc.   This option is required.

runas
~~~~~

This is the user name the Meer process should "drop privileges" to.  You will likely 
want to run Meer as the same user name that is collecting information.  For example, 
"sagan" or "suricata".  The ``runas`` can protect your system from security flaws in
Meer.  **Do not run as "root"**.  This option is required.

classification
~~~~~~~~~~~~~~

The ``classification`` option tells Meer where to find classification types.  This file
typically ships with Sagan, Suricata, and Snort rules.  It defines a 'classtype' (for 
example, "attempt-recon") and assigns a numeric priority to the event.  This option is
required.

meer_log
~~~~~~~~

The ``meer_log`` is the location of the file for Meer to record errors and statistics 
to.  The file will need to be writable by the same user specified in the ``runas`` 
option.

metadata
~~~~~~~~

The ``metadata`` option tells Meer to decode "metadata" from Suricata or Sagan.  If 
the "metadata" is present in the alert,  Meer will decode it and store its contents
in memory for later use.

flow
~~~~

The ``flow`` option tells Meer to decode "flow" data from Suricata or Sagan.  If
the "flow" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.

http
~~~~

The ``http`` option tells Meer to decode "http" data from Suricata or Sagan.  If
the "http" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.


tls
~~~

The ``tls`` option tells Meer to decode "tls" data from Suricata or Sagan.  If
the "tls" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.

ssh
~~~

The ``ssh`` option tells Meer to decode "ssh" data from Suricata or Sagan.  If
the "ssh" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.

smtp
~~~~

The ``smtp`` option tells Meer to decode "smtp" data from Suricata or Sagan.  If
the "smtp" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.

email
~~~~~

The ``email`` option tells Meer to decode "email" data from Suricata or Sagan.  If
the "email" JSON is present in the alert,  Meer will decode it and store its contents
in memory for later use.  This is not to be confused with ``smtp``.  The data from
``email`` will contain information like e-mail file attachments, carbon copies, etc.

json
~~~~

The ``json`` option tells Meer to store the original JSON/EVE event.  This is the 
raw event that Meer has read in.

fingerprint
~~~~~~~~~~~

The ``fingerprint`` option tells Meer to decode "fingerprint" rules and route the
data differently.  Fingerprint rules do not work like normal rules.  The data from
these rules is used to passively fingerprint systems for operating systems and types
(client/server).  This information can be valuable to determine if an attack might have
been successful or not.  Fingerprint rules are located at https://github.com/quadrantsec/fingerprint-rules.

fingerprint_log
~~~~~~~~~~~~~~~

When fingerprint rules fire,  this is the log file that is create and data sent to.  This 
log file format is an JSON (EVE) log file and is meant to be routed to a Elasticsearch back
end.  The idea is to store this information for historical purposes. 

dns
~~~

The ``dns`` option tells Meer to perform a DNS PTR (reverse) record lookup of the 
IP addresses involved in an alert.  This option is useful because it records the
DNS record at the time the event occurred. 

dns_cache
~~~~~~~~~

When ``dns`` is enabled,  Meer will internally cache records to avoid repetitive
lookups.  For example, if 1000 alerts come in from a single IP address,  Meer
will look up the DNS PTR record one time and use the cache for the other 999
times.   This saves on lookup time and extra stress on the internal DNS server.  If you
do not want Meer to cache DNS data,  simply set this option to 0.  The ``dns_cache``
time is in seconds.

health
~~~~~~

The ``health`` option is a set of signatures used to monitor the health of Meer and 
your Sagan or Suricata instances.  When enabled,  Meer will treat certain Sagan and
Suricata signatures as "health" indicators rather than normal alerts.   When a 
"health" signature occurs,  Meer updates the ``sensor`` table ``health`` column 
with the epoch time the health signature triggered.  This can be useful in quickly
determining if a sensor is down or behind (back logged) on alerts. 

health_signatures
~~~~~~~~~~~~~~~~~

When ``health`` is enabled,  this option supplies a list of signature IDs (sid) to 
Meer of Suricata or Sagan "health" signatures. 

waldo_file
~~~~~~~~~~

The ``waldo_file`` is a file that Meer uses to keep track of its last location within
a EVE/JSON file.  This keeps Meer from re-reading data in between stop/starts.  This
option is required.

lock_file
~~~~~~~~~

The ``lock_file`` is used to help avoid multiple Meer processes from processing the
same data.  The lock_file should be unique per Meer instance.   The lock file contains
the process ID (PID) of instance of Meer.  This option is required.

follow_eve
~~~~~~~~~~

The ``follow_eve`` option informs Meer what file to "follow" or "monitor" for new 
alerts.  You will want to point this to your Sagan or Suricata "alert" EVE output file. 
You can think of Meer "monitoring" this file similar to how "tail -f" operates. 
This option is required.

