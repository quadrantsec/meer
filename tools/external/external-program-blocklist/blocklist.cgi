#!/usr/bin/perl

#############################################################################
# blocklist.cgi - Simple routine that reads data put into a table by 
# "external-program-blocklist" (called by Meer) and sends to to the caller. 
# As the data is being sent, it is removed from the SQL database to prevent
# repeatedly sending the same data over and over again.
# This can be useful for creating block lists for firewalls to read (Palo 
# Alto, Forigate, etc).
#
# Champ Clark III
# 20220908
#############################################################################

use DBI;
use CGI qw(:all); 

# Set this to your database credentials

my $my_username = "username";
my $my_password = "password";
my $my_host = "127.0.0.1";
my $my_database = "blocklist";

my $API_KEY = "1ee217b83185ffdceb1597994ce0e4c710577085";

my $api_key = &remove_unwanted(scalar param("apikey"));

#############################################################################
# Connect to SQL database!
#############################################################################

my $db = "DBI:MariaDB:database=$my_database;host=$my_host";
my $dbh = DBI->connect($db, $my_username, $my_password) || die "$DBI::errstr\n";

my $db2 = "DBI:MariaDB:database=$my_database;host=$my_host";
my $dbh2 = DBI->connect($db2, $my_username, $my_password) || die "$DBI::errstr\n";

my $sql;
my $sql2; 
my $sth;
my $sth2; 

print "Content-type: text/plain\n\n";

# Verify that the API key is valid! 

if ( $api_key ne $API_KEY )
	{
	print "Access Denied.\n";
	exit(0);
	}

# Pull list of active IP address that need to be sent (blocked)

$sql = "SELECT id,ip FROM drop_list"; 
$sth = $dbh->prepare( $sql );
$sth->execute || die "$DBI::errstr\n";

	while (my(@bl)=$sth->fetchrow_array)
		{

		my $id = $bl[0]; 
		my $ip = $bl[1];

		print "$ip\n";

		# Delete after sending.  Prevent resending data if interrupted

		$sql2 = "DELETE FROM drop_list WHERE id=$id";
		$sth2 = $dbh2->prepare( $sql2 );
		$sth2->execute || die "$DBI::errstr\n";

		}

exit 0; 

#############################################################################
# remove_unwanted - input validation
#############################################################################

sub remove_unwanted {
  our $s;
  local($s) = @_;
  $s =~ s/\.\.//g;
  $s =~ s/[^A-Za-z0-9\@\-\_\/:.]//g if defined $s;
  return $s;
  }


