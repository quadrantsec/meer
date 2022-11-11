Command Line Options
====================

The majority of controls for Meer are within the ``meer.yaml`` file.

.. option:: -d, --daemon 

   This option tells Meer to fork to the background.

.. option:: -c, --config

   This option tells what configuration file to use.  By default Meer uses ``/usr/local/etc/meer.yaml``.

.. option:: -h, --help

   The Meer help screen.

.. option:: -q, --quiet

   This option to tells Meer to not output to the console.  Logs are still sent to the /var/log/meer directory.

.. option:: -q, --file

   This option bypasses the meer.yaml 'input-type' option and reads in files from the command line.  Gzip compressed files can be read if Meer is compiled with GZIP support.  If specifying multiple files,  make sure to enclose your options with quotes (for example, --file "/var/log/suricata/*.gz") 

