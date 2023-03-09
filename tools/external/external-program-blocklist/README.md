# External

These are a set of simple routines that allow Meer to write out "block lists"
to a MySQL/MariaDB database.  The list can then be consumed by other devices
(firewalls for example) as a "block list".

## SQL

SQL database/table for routines to use.  To setup, do this:

$ mysqladmin -u root -p create blocklist
$ mysql -u root -p blocklist < blocklist.sql

## Inserting Into SQL

### external-program-sql-blocklist.j2

This is the routine that will be called by Meer's "external" processors.  This
needs to be fed "alert" data.

As provided, it is a Ansible J2 template.

The following need for it.

- BLOCKLISTER_USER
- BLOCKLISTER_PASS
- BLOCKLISTER_DB
- BLOCKLISTER_SERVER
- BLOCKLISTER_LOG
- BLOCKLISTER_IGNORE_PORTS

## Fetching

### blocklist.cgi

This is the web CGI that "sends" the block list to the "client".  As IP
addresses are sent,  they are removed.  This routines URL is where you would
configured you device to get blocklist.  For example:

http://10.10.10.10/cgi-bin/blocklist.cgi?apikey=yourkeyhere

The API key is set in the blocklist.cgi routine.  This prevents unauthorized
access to you block lists.

This script will also remove the entries when fetched.

Any subnets in `/usr/local/etc/blocklister_ignore_subnets` will be ignored.

### blocklister.j2

Generates a size limited list of IPs and subnets for use with like Fortigates.

Unlike blocklist.cgi, this script builds a list of nets to ignore. Where possible
if a set of IPs can be collapsed into a full subnet they will. Any subnets ending in
`/32` or `/128` have the netmask removed to save space as it is just a IP.

If the size execeds the max allowable size, the oldest entry will be removed and it
will try again. It will do this till it gets down to a max size.

As provided it is a Ansible J2 template. The following keys below are used.

- BLOCKLISTER_DB
- BLOCKLISTER_SERVER
- BLOCKLISTER_USER
- BLOCKLISTER_PASS
- BLOCKLISTER_MAX_SIZE
- BLOCKLISTER_MAX_AGE
- BLOCKLISTER_RM_OLD

## Cron

The example cron Ansible J2 template provides a example of running this and copying
it some place it can be fetched. Copied to a file name specied by `BLOCKLISTER_KEY` in
the default www on a basic Debian based systems.

## Template Variables

| Variable                  | Type   | Suggested Base Settings   | Description                                                 |
|---------------------------|--------|---------------------------|-------------------------------------------------------------|
| BLOCKLISTER_DB            | string | blocklist                 | The DB name to connect to.                                  |
| BLOCKLISTER_DB_ENABLE     | bool   | 0                         | Enable the DB related bits for Blocklister                  |
| BLOCKLISTER_ENABLE        | bool   | 0                         | Enables BLOCKLISTER_DB_ENABLE and BLOCKLISTER_SCRIPT_ENABLE |
| BLOCKLISTER_KEY           | string | undef                     | Access key/filename.                                        |
| BLOCKLISTER_MAX_AGE       | int    | 7776000                   | Max age in seconds. Default is 90 days.                     |
| BLOCKLISTER_MAX_SIZE      | int    | 10000000                  | Max size in bytes. The default is based on Fortigate.       |
| BLOCKLISTER_PASS          | string | undef                     | Password for the DB user.                                   |
| BLOCKLISTER_RM_OLD        | bool   | 0                         | Remove items that have a age older than the max age.        |
| BLOCKLISTER_SCRIPT_ENABLE | bool   | 0                         | Enable the script related bits for Blocklister.             |
| BLOCKLISTER_SERVER        | IP     | 127.0.0.1                 | IP to connect to.                                           |
| BLOCKLISTER_USER          | string | blocklister               | DB user                                                     |
| BLOCKLISTER_IGNORE_PORTS  | string |                           | A space seperated string of ports to ignore.                |
| BLOCKLISTER_LOG           | string | /var/log/meer/blocklister | Where to write the logs out to.                             |
