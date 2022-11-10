What is Meer
============

"Meer" is a dedicated data broker for the `Suricata <https://suricata-ids.org>`_ IDS/IPS system and the `Sagan <https://sagan.io/>`_ log analysis engine. 

Meer takes EVE data (JSON) from Suricata or Sagan (via an ``input-plugin``),  augments it by enriching it 
with DNS, GeoIP, and other information (via the ``meer-core``),  and then pushes the data to a database (via a ``output-plugin``) of your choice. 

Meer is written in C which makes it fast and very light weight.  This makes is suitable for processing data on systems with limited resource. 

Meer ``input-plugins`` that are currently supported are Suricata/Sagan EVE ("spool") files and Redis. 

Meer ``output-plugins`` that are currently supported are Elasticsearch, Opensearch, Zincsearch 
(https://github.com/zinclabs/zinc), Redis, named pipes, files, and "external" programs.   Meer release 1.0.0 
supports SQL (MariaDB, MySQL and PostgreSQL) that is compatible with older "Barnyard2" systems.  Meer versions 
_after_ 1.0.0 do _not_ support SQL.

The primary Meer site is located at:

https://github.com/quadrantsec/meer


License
-------

Meer is licensed under the GNU/GPL version 2.

