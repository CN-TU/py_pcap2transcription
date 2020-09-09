# Transforms flows into symbol trancriptions (little)
#
# July 2018, FIV

#!/usr/bin/env perl

use strict;
use POSIX;
#use Data::Dumper;

#my $start_run = time();

if ($#ARGV==-1) {
  print "\nusage: symboltran_lt.pl <csv_file> \n\n";
  exit;
}

my @field; #stores line
my $file=$ARGV[0];
open FILE, "<", $file or die $!;

#input vector structure:
#"timestamp","ip.proto","ip.src","ip.dst","tcp.flags","tcp.len"

$_=<FILE>; #header, ignore it

my $min_time=-1;
my $max_time=0;
my %out_vector;
my %out_timest;
my %out_object;

my @conthash;
my $indcont=-1;
my $currentt=0;
my $oldt=-1;

while (<FILE>) {
	my $line = $_;
	$line=~s/"//g;
	chomp($line);
	@field = split ",", $line;

	if ($field[1]==6) {
		my $IDobj =$field[2]."-".$field[3];
		my $IDobjI=$field[3]."-".$field[2];

		if ($min_time==-1){$min_time=floor($field[0]);} #first timestamp

		$currentt=floor($field[0])-$min_time;
		if ($currentt>$oldt){
			$indcont++;
			if ($indcont==60) {$indcont=0;}
			my $auxt=$min_time+$currentt;
			#print("\n $auxt, $currentt, $indcont\n");
			printout();# print out contents of elements of $conthash[$indcont] 
			deletecont();# delete contents of elements of $conthash[$indcont]
		}
		$oldt=$currentt;

		if (exists $out_object{$IDobj}) {
			my $timebetween = $field[0]-$out_timest{$IDobj};
			$timebetween = floor($timebetween/0.1); 
			for (my $i=0;$i<$timebetween;$i++) {
				$out_object{$IDobj}=$out_object{$IDobj}."-";
			}
			$out_timest{$IDobj}=$field[0];#-$min_time; #time

                        my $Lsymbol;
			#if ($field[5]==0) {$Lsymbol=0;} # no payload
			#elsif ($field[5]==1460) {$Lsymbol=2;} # maximum payload
			#else {$Lsymbol=1;} # intermediate payload
			$Lsymbol = int($field[5]/146);

                        my $symbol=chr($Lsymbol+65);

			$out_object{$IDobj}=$out_object{$IDobj}.$symbol; 
		}
		elsif (exists $out_object{$IDobjI}) {
			$IDobj=$IDobjI;
			my $timebetween = $field[0]-$out_timest{$IDobj};
			$timebetween = floor($timebetween/0.1); 
			for (my $i=0;$i<$timebetween;$i++) {
				$out_object{$IDobj}=$out_object{$IDobj}."-";
			}
			$out_timest{$IDobj}=$field[0];#-$min_time; #time

                        my $Lsymbol;
			#if ($field[5]==0) {$Lsymbol=0;} # no payload
			#elsif ($field[5]==1460) {$Lsymbol=2;} # maximum payload
			#else {$Lsymbol=1;} # intermediate payload
			$Lsymbol = int($field[5]/146);

                        my $symbol=chr($Lsymbol+97);

			$out_object{$IDobj}=$out_object{$IDobj}.$symbol; 
		}
		else {
			$conthash[$indcont]{$IDobj}=1;
			$out_timest{$IDobj}=$field[0];#-$min_time; #time

                        my $Lsymbol;
			#if ($field[5]==0) {$Lsymbol=0;} # no payload
			#elsif ($field[5]==1460) {$Lsymbol=2;} # maximum payload
			#else {$Lsymbol=1;} # intermediate payload
			$Lsymbol = int($field[5]/146);

                        my $symbol=chr($Lsymbol+65);

			if ($out_object{$IDobj}[-1]=="-") {
				$out_object{$IDobj}=$out_object{$IDobj}."|";
			}
			$out_object{$IDobj}=$symbol; 
		}
		$max_time=floor($field[0]);#last timestamp
	}
}
close(FILE);

sub printout 
{
	my $c=$indcont;
	my @name = keys %{$conthash[$c]};
	my @val = values %{$conthash[$c]};
	my $srcs = scalar keys %{$conthash[$c]};

	my @names;
	while ( my($name, $val) = each %{$conthash[$c]}) {
		print "$name: $out_object{$name}\n";
	}
}

sub deletecont 
{
	my $c=$indcont;
	my @name = keys %{$conthash[$c]};
	my @val = values %{$conthash[$c]};

	while ( my($name, $val) = each %{$conthash[$c]}) {
		delete $out_object{$name};
		delete $conthash[$c]{$name};
	}
}
