#!/usr/bin/perl

use strict;
use warnings;

use Math::BigInt;
use Data::Dumper;
use Pod::Usage;

$Data::Dumper::Indent=1;
use Getopt::Long;
use Module::Runtime 'use_module';


=head1 NAME

ias_log_ip_range_grouper.pl

=head1 SYNOPSIS

  	cat list_of_ips.txt | ./ias_log_ip_range_grouper.pl

Or

    ./ias_log_ip_range_grouper.pl file1 [file2 ...]

=head1 DESCRIPTION

Given a list of IP addresses, it groups them together in subnets.

=head1 OPTIONS

=over 4

=item * --test - run it with the test IPs in the script;

=item * --verbose - give some status info about processing (currently, not much)

=item * --dump-binary - give the binary hash

=item * --smallest-net-size - integer representing the smallest /NET you want to see.  Defaults to 24.  This only affects tabbed (pretty) output.

=item * --output-routine - Output in dumper (Data::Dumper), tabbed (pretty), or json.

=back

=head1 Yes.

The algorithm is silly:

=over 4

=item Convert a list of ip addresses to a binary string

=item Create a hash where the key is a bit

=item Condense the hash into contiguous bits

=item Convert the condensed hash to human readable format

=item Output

=back

I'm positive somebody out there will be upset that I convert String IPs to decimals then to
an array of 1's and 0's in char form, but hey!  It works.

=cut

my $OPTIONS_VALUES = {};
my $OPTIONS = [
	'test',
	'verbose',
	'dump-binary',
	'output-routine=s',
	'smallest-net-size=i',
];

my %OUTPUT_ROUTINES = (
	'dumper' => sub { print Data::Dumper($_[0]),$/},
	'tabbed' => \&tab_hash_output,
	'json' => \&json_hash_output,
);

GetOptions(
	$OPTIONS_VALUES,
	@$OPTIONS
) or pod2usage ( -message => "Bad options.", -exitval => 1);

$OPTIONS_VALUES->{'output-routine'} ||= 'tabbed';
$OPTIONS_VALUES->{'smallest-net-size'} ||= 24;
if (! $OUTPUT_ROUTINES{$OPTIONS_VALUES->{'output-routine'}})
{
	print STDERR "Bad output routine: ", $OPTIONS_VALUES->{'output-routine'},$/;
	print STDERR get_output_routines();
	exit 1;
}

sub json_hash_output
{
	use_module('JSON');
	my ($hr) = @_;
	
	my $json = JSON->new->allow_nonref;
	
	print $json->pretty->encode($hr),$/;
	
}

sub tab_hash_output
{
	my ($hr, $depth, $last_max_size) = @_;
	$depth ||= 0;
	$last_max_size ||= 32;
	
	my $largest_net_size = 32;
	foreach my $key (keys %$hr)
	{
		my $net_size;
		my $net;
		$key =~ m/(.+)\/(.+)/;
		$net=$1;
		$net_size = $2;
		
		$largest_net_size = $net_size
			if ($net_size <= $largest_net_size);
	}
	
	# print "Largest net size: $largest_net_size\n";
	foreach my $key (sort keys %$hr)
	{
		my $net_size;
		my $net;
		$key =~ m/(.+)\/(.+)/;
		$net=$1;
		$net_size = $2;

		my $padding = "\t" x $depth;
		
		if ($net_size == 32)
		{
			print $padding,$key,$/;
		}
		
		elsif ($largest_net_size <= $OPTIONS_VALUES->{'smallest-net-size'}
			|| $OPTIONS_VALUES->{'smallest-net-size'} > $last_max_size
		)
		{
			print $padding,$key,$/;
			tab_hash_output($hr->{$key}, $depth+1, $largest_net_size);
		}

		else
		{
			tab_hash_output($hr->{$key}, $depth, $largest_net_size);
		}
	}	
}

sub get_output_routines
{
	my $output = '';
	$output .= "Available output routines: ".$/;
	$output .= "\t".join("\n\t", keys %OUTPUT_ROUTINES).$/;
	return $output;
}

my @TEST_IPS = (
	'172.16.1.1',
	'172.16.1.2',
	'172.16.2.1',
	'192.168.1.252',
	'192.168.1.253',
);

my $SINGLE_TEST_IP = '172.16.1.1';
my $IP_BIT_LENGTH = 32;

my %IP_HASH;

# convert_ip_to_bits($SINGLE_TEST_IP);
# test_bit_back_to_dec();

if ($OPTIONS_VALUES->{'test'})
{
	test_convert_back_to_human();
	exit;
}

do_main_processing();

exit;

sub do_main_processing
{

	my $in_fh;
	my $bin_ip_hr = {};
	if (scalar @ARGV)
	{
		foreach my $file_name (@ARGV)
		{
			verbose("# Processing: $file_name",$/);
			open $in_fh, '<', $file_name
				or die "Can't open $file_name for reading: $!";		

			process_file($in_fh, $bin_ip_hr);
			$in_fh->close;
		}
	}
	else
	{
		$in_fh = \*STDIN;
		process_file($in_fh, $bin_ip_hr);
	}
	
	
	my $condensed = condense_bit_hr($bin_ip_hr);

	if ($OPTIONS_VALUES->{'dump-binary'})
	{
		print Dumper($condensed),$/;
		exit;
	}

	$OUTPUT_ROUTINES{$OPTIONS_VALUES->{'output-routine'}}->(
		convert_condensed_hr_to_decimal($condensed)
	);
	# print Dumper(convert_condensed_hr_to_decimal($condensed));

}

sub process_file
{
	my ($fh, $ip_hash) = @_;

	my $counter=0;
	
	my $line;
	
	while (defined ($line = <$fh>))
	{
		$counter++;
		
		next if ($line =~ m/^\s*$/);
		$line =~ s/#.*$//;
		$line =~ s/^\s+//;
		$line =~ s/\s+$//;
		my @parts = split('\s+', $line);
		
		# print "Parts:\n",
		# print Dumper(\@parts),$/;
		add_ips_to_hash($ip_hash, \@parts);

	}
}

sub test_bit_back_to_dec
{
	my $bit_ar = convert_ip_to_bits($SINGLE_TEST_IP);
	print dec2ip(bin_ar_to_dec_oct($bit_ar)),$/;
	
}

sub test_convert_back_to_human
{
	add_ips_to_hash(\%IP_HASH, \@TEST_IPS);
	my $condensed = condense_bit_hr(\%IP_HASH);
	
	print Dumper(convert_condensed_hr_to_decimal($condensed));
	
}

sub test_condense
{

	add_ips_to_hash(\%IP_HASH, \@TEST_IPS);

	print Dumper(condense_bit_hr(
		\%IP_HASH
	)),$/;
}

# print Dumper(\%IP_HASH);

exit;

sub convert_condensed_hr_to_decimal
{
	my ($hr) = @_;
	
	my $converted = {};
	convert_condensed_hr_to_decimal_recursive(
		$hr,
		[],
		$converted,
	);
	return $converted;
}

sub convert_condensed_hr_to_decimal_recursive
{
	my ($hr, $path_ar, $c_hr) = @_;
	
	# print "******************* RECURSION\n";
	
	foreach my $key (sort keys %$hr)
	{
		# print "Key: $key\n";
		# print "Path: ", join('',@$path_ar),$/;
		
		push @$path_ar, $key;
		my $full_bit_path = join('',@$path_ar);
		my $full_path_length = length($full_bit_path);
		# print "Full bit path:\t$full_bit_path\n";
		# print "Full path length:\t$full_path_length",$/;
		my $pad_zeros = '0' x ( $IP_BIT_LENGTH - length($full_bit_path));
		# print "Pad zeros: $pad_zeros\n";
		my $padded = $full_bit_path . $pad_zeros;
		# print "Padded:\t\t$padded\n";
		my $new_key_name = dec2ip(bin_to_dec_oct($padded)) . '/' . length($full_bit_path);
		
		# print "New key: $new_key_name\n";
		
		my $new_c_hr = {};
		$c_hr->{$new_key_name} = $new_c_hr;
		
		convert_condensed_hr_to_decimal_recursive(
			$hr->{$key},
			$path_ar,
			$new_c_hr,
		);
		# <STDIN>;
		pop @$path_ar;
	}
}

sub condense_bit_hr
{
	my ($hr) = @_;
	my $condensed_hr = {};
	
	condense_bit_hr_recursive(
		$hr,
		$condensed_hr,
		[]
	);
	return $condensed_hr;
}

sub condense_bit_hr_recursive
{
	# print "\n\n**********************************************\nRECURSION\n";
	my ($hr, $c_hr, $path_ar) = @_;
	$path_ar ||= [];

	# print "Hr: ", $/, Dumper($hr),$/;
	# print "Path ar: ", join('', @$path_ar),$/;
	# print "Condensed: ",$/;
	# print Dumper(
	#	$c_hr
	# );
	# <STDIN>;
	
	if (! scalar keys %$hr)
	{
		# print "=============== decision.\n";
		# print "End of the line.\n";
		$c_hr->{join('',@$path_ar)} = {};
		# print "Condensed: ",$/,Dumper($c_hr),$/;
		return;
	}
	
	if (scalar(keys %$hr) == 1)
	{

		my ($single) = keys %$hr;
		# print "decision.\n";
		# print "Singlet. $single\n";
		push @$path_ar, $single;
		# print "Pathar after: ", join('', @$path_ar),$/;
		my $new_hr = $hr->{$single};
		condense_bit_hr_recursive(
			$new_hr,
			$c_hr,
			$path_ar,
		);
		pop @$path_ar;
		return;
	}
	else
	{
		# print "decision.\n";
		# print "Doublet.\n";
		my $new_c_hr = $c_hr;
		
		if (scalar @$path_ar)
		{
			my $new_key = join('',@$path_ar);
			$c_hr->{$new_key} = {};
			$new_c_hr = $c_hr->{$new_key};
		}
				
		foreach my $bit (keys %$hr)
		{
			# print "------Processing bit: $bit\n";
			
			my $new_hr = $hr->{$bit};
			condense_bit_hr_recursive(
				$new_hr,
				$new_c_hr,
				[$bit]
			);
		}
		return;
	}
	
}

sub add_ips_to_hash
{
	my ($hr, $ip_ar) = @_;
	
	foreach my $ip (@$ip_ar)
	{
		my $bits_ar = convert_ip_to_bits($ip);
		add_bits_to_hash($hr, $bits_ar);
	}
}

sub add_bits_to_hash
{
	my ($hr, $bit_ar) = @_;

	my $current = $hr;
	foreach my $bit (@$bit_ar)
	{
		$current->{$bit} ||= {};
		$current = $current->{$bit};
	}
}

sub convert_ip_to_bits
{
	my ($ip) = @_;

	my $dec = ip2dec($ip);
	my @bits = @{dec_to_bit_array($dec)};

	return \@bits;
}

sub bin_ar_to_dec_oct
{
	bin_to_dec_oct(join('',@{$_[0]}));
}

sub bin_to_dec_oct
{
	my ($string) = @_;
	# print "String: $string\n";
	return oct("0b" . $_[0]);
}

# this sub converts a dotted IP to a decimal IP
sub ip2dec {
    unpack N => pack CCCC => split /\./ => shift;
}

sub dec_to_bit_array
{
	
	my $string = sprintf("%b", $_[0]);
	my $pad = '0' x ($IP_BIT_LENGTH - length($string));
	return [ split (//,$pad.$string)];
}

sub dec2ip {
    join '.', unpack 'C4', pack 'N', shift;
}

sub verbose
{
	my (@rest) = @_;
	
	if ($OPTIONS_VALUES->{'verbose'})
	{
		print STDERR @rest;
	}
}
