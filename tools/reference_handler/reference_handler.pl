#!/usr/bin/perl -T

##############################################################################
#              
# Copyright (C) 2018-2019 Quadrant Information Security <quadrantsec.com>
# Copyright (C) 2018-2019 Champ Clark III <cclark@quadrantsec.com>
#          
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#                  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# 
##############################################################################

##############################################################################
# reference_handler.pl - Takes references out of rules in a directory and puts 
# them into a SQL database.  This allows use to keep one repo of rules and 
# there references. 
# 
# By Champ Clark III
#
# Version 1.0 - Initial Creation - 2017/05/26
#               Public Release   - 2018/04/23
##############################################################################

use strict; 

use Parse::Snort; 
use DBI;

my $rule_obj = Parse::Snort->new();

#######################
# Database credentials.
#######################

my $sql_username="USERNAME";		# Needs INSERT access.
my $sql_password="PASSWORD";
my $sql_host="127.0.0.1";
my $sql_database="MYDATABASE"; 

############################
# User configurtion options.
############################

#my $reference_file = "/usr/local/etc/reference_sources.conf";
my $reference_file = "./reference_sources.conf";

#my $rule_path = "/etc/suricata/rules";
my $rule_path = "/usr/local/etc/sagan-rules";

########################
# Variable declarations.
########################

my $i;
my $a;
my $db;
my $dbh;
my $ref;
my $url;
my @ref_list;
my @url_list;
my $ref_list_count;
my $filename;
my $sid;
my $references;
my $pp_count;
my $sql;
my $ref_output;
my $full_url;
my $flag;
my $bad_rule;
my $rule_count;
my $ref_count;

# Load referenes into two-dim array for later reference.

print "[*] Loading reference source data [$reference_file]\n"; 

if (!open(REF, "$reference_file")) { 
	print "[E] Can't reference data file \"$reference_file\" : $!\n";
	exit 1;
	}

while (<REF>) { 

	chomp; s/#.*//; s/^\s+//; s/\s+$//;
	next unless length;

	($ref, $url) = split('\|', $_); 

	$url =~ s/ //;

	push(@ref_list, "$ref"); 
	push(@url_list, "$url"); 

}

close(REF); 
$ref_list_count = scalar @ref_list; 

# Connect to MySQL database

$db  = "DBI:mysql:database=$sql_database;host=$sql_host";
$dbh = DBI -> connect($db, $sql_username, $sql_password) || die "[E] Cannot connect to the MySQL database!";

print "[*] Parsing rules in $rule_path.... Please wait.....\n"; 

# Start parsing rules....

opendir(DIRHANDLE, $rule_path) or die "couldn't open $rule_path : $!\n";
while ( defined ($filename = readdir(DIRHANDLE)) ) {

	if (!open(RULES, "$rule_path/$filename")) {
		print "Can't open file \"$rule_path/$filename\".\n";
		exit 1;
		}


	while (<RULES>) {
		
		chomp; s/^\s+//; s/\s+$//;
		next unless length;

		if ( $_ =~ /sid:/m  && $_ =~ /msg:/m && $_ =~ /rev:/m ) { 

			s/\#//;			# We process event commented rules...

			$rule_count++; 
			$rule_obj->parse($_);

			$sid = $rule_obj->sid();
			$references = $rule_obj->references(); 
			$ref_count = scalar @{ $references };

			# Some processor rules screw things up.  We want standard gid 1 rules. 
			# When Parse::Snort encounters a preprocessor/non gid 1 rule, it sets 
			# the sid to "0".  If we have a sid of 0,  we throw it away. 
			#
			if ( $sid == 0 ) { 

				$pp_count++; 

			} else { 

			for ( $i = 0; $i < $ref_count; $i++ ) { 

				$flag = 0; 	# Flag for good/bad rule.

				for ( $a = 0; $a < $ref_list_count; $a++ ) { 

					if ( $ref_list[$a] eq $references->[$i]->[0] ) { 

						$url = $references->[$i]->[1]; 
						$url =~ s/ //; 

						$full_url = "$url_list[$a]$url";

						$sql = "INSERT IGNORE INTO reference_data (sid, ref_type, ref_url) VALUES (?,?,?)";
						$ref_output = $dbh->prepare($sql);
						$ref_output->bind_param(1, $sid); 
						$ref_output->bind_param(2, $references->[$i]->[0]); 
						$ref_output->bind_param(3, $full_url); 
						$ref_output->execute || die "[E] SQL Error: $!\n"; 

						
								

						$flag = 1; 	# Parse a good rule, flag it.

					} # End if $ref_list[$a]

				} # End for $a
	

				# Last rule wasn't considered good and was dropped. 
				
				if ( $flag == 0 ) { 

					$bad_rule++; 

				}

			} # End for $i

		} # End else

	} # End of rule verification 

    } # End of while

} # End of directory loop


print "[*] Processed $rule_count. Got and skipped $bad_rule bad rules and $pp_count processors rules.\n"; 
print "[*] Done!\n"; 

