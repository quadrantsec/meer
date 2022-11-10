Installation
============

Quick start from source
------------------------

Quick installation using common flags.  For more information on packages and flags,  skip to ``Required Prerequisites`` and ``Optional Prerequisites``.

::

    sudo apt-get install libjson-c-dev libyaml-dev libmaxminddb-dev libcurl4-openssl-dev libhiredis-dev libevent-dev
    git clone https://github.com/quadrantsec/meer
    cd meer
    ./autogen.sh
    ./configure --enable-redis --enable-elasticsearch --enable-geoip
    make
    sudo make install

By default, this will install Meer into the ``/usr/local/bin/`` directory with the default Meer configuration file in the ``/usr/local/etc/`` directory.  By default (without any flags), Meer will compile with only Redis support.


Required Prerequisites
----------------------

Meer uses a YAML configuration file.  This means that Meer will need libyaml installed on the system.  On Ubuntu/Debian systems,  this can be installed via:

.. option:: apt-get install libyaml-dev

Meer uses `JSON-C <https://github.com/json-c/json-c>`_ to parse JSON (EVE) output from Sagan and Suricata.  On Ubuntu/Debian systems, this prerequisite can be installed via:

.. option:: apt-get install libjson-c-dev

Optional Prerequisites
----------------------

Redis
~~~~~

If you would like to have Meer store data into Redis,  which is enabled by default during compile time,  you will need the "hiredis" library and development files.  You will also need ``libevent`` installed as well.  

On Ubuntu/Debian systems:

.. option:: sudo apt-get install libhiredis-dev libevent-dev


Elasticsearch
~~~~~~~~~~~~~

If you would like Meer to use the 'elasticsearch' output plugin,  then you'll need to install libcurl.  To do this on Ubuntu/Debian systems,  do the following:

.. option:: apt-get install libcurl4-openssl-dev

Maxmind (GeoIP support) 
~~~~~~~~~~~~~~~~~~~~~~~

If you would like Meer to add GeoIP data to Suricata/Sagan EVE data,  you'll want to install the Maxmind (https://maxmind.com) library.  To do this on Ubuntu/Debian systems,  do the following:

.. option:: apt-get install libmaxminddb-dev

JEMalloc
~~~~~~~~

For JEMalloc support,  on Debian/Ubuntu systems,  install the JEMalloc library:

.. option:: apt-get install libjemalloc-dev

TCMalloc
~~~~~~~~

For TCMalloc support,  on Debian/Ubuntu systems,  install the TCMalloc library:

.. option:: apt-get install libtcmalloc-minimal4


Quick start from source
------------------------

Installation of Meer using common configuration options.::

    sudo apt-get install libjson-c-dev libyaml-dev libmaxminddb-dev libcurl4-openssl-dev libhiredis-dev libevent-dev
    git clone https://github.com/quadrantsec/meer
    cd meer
    ./autogen.sh
    ./configure --enable-redis --enable-elasticsearch --enable-geoip
    make
    sudo make install

By default, this will install Meer into the ``/usr/local/bin/`` directory with the default Meer configuration file in the ``/usr/local/etc/`` directory.  By default (without any flags), Meer will compile with only Redis support.


Common configure options
^^^^^^^^^^^^^^^^^^^^^^^^

.. option:: --prefix=/usr/

    Installs the Meer binary in the /usr/bin. The default is ``/usr/local/bin``.

.. option:: --sysconfdir=/etc

    Installs the Meer configuration file (meer.yaml) in the /etc directory.  The default is ``/usr/local/etc/``.

.. option:: --with-libjsonc-libraries

   This option points Meer to where the json-c libraries reside.

.. option:: --with-libjsonc-includes

   This option points Meer to where the json-c header files reside.

.. option:: --with-libyaml_libraries

   This option points Meer to where the libyaml files reside.

.. option:: --with-libyaml-includes

   This option points Meer to where the libyaml header files reside.

.. option:: --enable-redis

   This option enables Redis output support.  It requires "hiredis" to be installedt.

.. option:: --enable-elastcisearch

   This option enables Elastcisearch support.  It requires "libcurl" to be installed. 

.. option:: --enable-geoip

   This option enables Maxmind's GeoIP support.  It requires "libmaxminddb" Maxmind library to be install.

.. option:: --enable-bluedot

   This optino allows Meer to write to a Bluedot "threat intel" database alert data via HTTP.  This 
   requres that "libcurl" be installed.  You probably don't want this. 

.. option:: --enable-tcmalloc

   This options enables support for Google's TCMalloc.  For more information, see https://github.com/google/tcmalloc

.. option:: --enable-jemalloc

   This options enables support for JEMalloc.  For more information, see https://jemalloc.net.


