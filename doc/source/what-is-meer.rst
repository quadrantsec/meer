What is Meer
============

“Meer” is a dedicated “spooler” for the Suricata IDS/IPS and Sagan log analysis engines. This means that as `Suricata <https://suricata-ids.org>`_ or `Sagan <https://sagan.io/>`_ write alerts out to a file, Meer can ‘follow’ that file and store the alert information into a database. You can think of the “spool” file as a ‘queuing’ system for alerts from Suricata or Sagan. Using a “spooling” system ensures the delivery of alerts to a back end database. This task was traditionally accomplished by using a file format called “unified2” which was developed by the SourceFire/Snort team and a program called Barnyard2. While unified2 has been useful, its binary nature makes it difficult to work with and it has not been extended in quite some time. Instead of following "unified2" files, Meer follows Suricata and Sagan’s “EVE” (JSON) output format. Since the EVE output format is JSON,  it is easier to work with. The EVE output also contains valuable information that does not exist in "unified2".

Meer is meant to be modular and simple. This project does not aim to replicate all features of Barnyard2. The idea is to replicate the more useful features and abandon the “cruft”.

The primary Meer site is located at:

https://quadrantsec.com/meer


License
-------

Meer is licensed under the GNU/GPL version 2.

