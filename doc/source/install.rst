Installation
============

There are currently no binary packages of Meer available.  However,  installation from source is pretty straightforward.

Prerequisites
-------------

Before compiling and installing Meer,  you will need to determine where you want your data to reside.  Currently,  Meer supports MariaDB, 
MySQL and PostgreSQL.  In order to build Meer, you will need one or more of these installed with all development files.  For
example,  Ubuntu/Debian systems can install via:

.. option:: apt-get install mariadb-dev  # For MariaDB

.. option:: apt-get install libmysqlclient-dev # For MySQL 

.. option:: apt-get install libpq-dev # For PostgreSQL

Meer uses a YAML configuration file.  This means that Meer will need libyaml installed on the system.  On Ubuntu/Debian 
systems,  this can be installed via:

.. option:: apt-get install libyaml-dev

Meer uses `JSON-C <https://github.com/json-c/json-c>`_ to parse JSON output from Sagan and Suricata.   On Ubuntu/Debian 
systems, this prerequisite can be installed via:

.. option:: apt-get install libjson-c-dev


Source
------

Installation from source distributions files gives

Basic steps::

    git clone https://github.com/quadrantsec/meer
    cd meer
    ./autogen.sh
    ./configure
    make
    sudo make install

By default, this will install Meer into the ``/usr/local/bin/`` directory with the default Meer configuration file in the ``/usr/local/etc/`` directory.  By default, 
Meer will compile with MySQL/MariaDB support.

Common configure options
^^^^^^^^^^^^^^^^^^^^^^^^

.. option:: --prefix=/usr/

    Installs the Meer binary in the /usr/bin. The default is ``/usr/local/bin``.

.. option:: --sysconfdir=/etc

    Installs the Meer configuration file (meer.yaml) in the /etc directory.  The default is ``/usr/local/etc/``.

.. option:: --disable-mysql

    This flag disables MySQL or MariaDB support.  By default --enable-mysql is used.

.. option:: --enable-postgresql

    This flag enables PostgreSQL support.  By default --disable-postgresql is used.

.. option:: --with-libjsonc-libraries

   This option points Meer to where the json-c libraries reside.

.. option:: --with-libjsonc-includes

   This option points Meer to where the json-c header files reside.

.. option:: --with-libyaml_libraries

   This option points Meer to where the libyaml files reside.

.. option:: --with-libyaml-includes

   This option points Meer to where the libyaml header files reside.

.. option:: --enable-redis

   This option enables redis output support.  It requires "hiredis" to be installed on the target.


