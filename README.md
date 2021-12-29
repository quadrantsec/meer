<pre>
@@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    
@@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security
@!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com
!!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018-2021
:      :   : :: ::  : :: ::   :   : :
</pre>

# Join the Meer Discord channel

[![Discord](./screenshots/discord.png)](https://discord.gg/n6ReCZED)

# Meer Documentation

Meer "Read The Docs! https://meer.readthedocs.io

# What is “Meer”. 

<b>The quick explanation: </b> Have you ever worked with Barnyard2?  The idea behind Meer is very similar,  but rather than reading Snort’s “Unified2” files,  Meer reads Suricata and Sagan EVE JSON files. 

<b>The longer explanation: </b> “Meer” is a dedicated “spooler” for the Suricata IDS/IPS and Sagan log analysis engines.  This means that as Suricata or Sagan write alerts out to a file,  Meer can ‘follow’ that file and store the alert information into a database.  You can think of the “spool” file as a 'queuing' system for alerts from Suricata or Sagan.   Using a “spooling” system ensures the delivery of alerts to a back end database.  This task was traditionally accomplished by using a file format called "unified2" which was developed by the SourceFire/Snort team and a program called Barnyard2.  While unified2 has been useful,  its binary nature makes it difficult to work with and has not been extended in quite sometime.  Meer uses Suricata and Sagan's "EVE" output formats instead of unified2.  EVE is a text file that contains JSON which makes it more easy to work with.  The EVE output also contains valuable information that does not exist in unified2.

Meer is meant to be modular and simple. This project does not aim to replicate all features of Barnyard2.  The idea is to replicate the more useful features and abandon the "cruft".

# Output Plugins:

* Redis - Meer can write store data to a Redis database similar to Suricata (list/lpush, rpush, channel/publish or set).

* "elasticsearch" support - This allows Meer to write Sagan & Suricata EVE (JSON) data to Elasticseach search.

* "external" support - This allows you to call your own program.  When an event happens and if the signature specifies the option,  Meer will 'call' your program.  The EVE/JSON is handed to your program via stdin.  This can be useful to build custom firewall routines, customer reactions to events,  custom ways to store data, etc. 

* "pipe" support - This allows Meer to write EVE/JSON data to a Unix "named pipe" or FIFO.  Meer acts as a pipe "writer" and you can have a consumer (reader) on the other side of the "pipe".  For example,  you might use a program like "Sagan" (https://sagan.io) to analyze the data received via a named pipe.

# Current Features:

* Meer can "enrich" EVE/JSON data!  For example,  Meer can add DNS records,  do OUI (hardware manufacturer) on MAC addresses,  add GeoIP data and more!
* Meer is written in C and has a very small memory footprint (only several meg of RAM).  It also CPU efficient. 
* Fast startup times (under one second).  
* Simple command line and configuration syntax.  Meer uses a YAML configurations similar to Suricata and Sagan. 
* Out of the box IPv6 support. 
* Meer can do reverse DNS/PTR record lookups.   Meer has an internal DNS cache system so to not overburden DNS servers with repeated queries. 
* Supports "fingerprint" rule set.  These are special Suricata & Sagan signatures that allow you to collect data about devices in your network and store them in a Redis database.  See https://github.com/quadrantsec/fingerprint-rules for more information.
* Supports "client stats" for Meer when injecting Sagan EVE/JSON data.  This allows give you statistics about who and what is sending Sagan data within an environment. 

# Future "output" support: 

Meer is under development.  This is our brief "road-map" of what we would like to see Meer do.  If
you have any ideas or requests,  please let us know via our "issues" page (https://github.com/quadrantsec/meer/issues).

* Syslog support (JSON, decoded, etc). 
* PCAP support? 

# Support:

* Need help getting started or looking for documentation? Go to https://meer.readthedocs.org !

* Have a question or comment about Meer?  Please post to the Meer mailing at https://groups.google.com/forum/#!forum/meer-users. You can also visit the Sagan/Meer Discord channel by going to https://discord.gg/n6ReCZED

* If you need to report a bug,  please post that in our Github "issues" page.  That is at https://github.com/quadrantsec/meer/issues

