#!/usr/bin/perl -w

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname abs_path $0;
use SSLScan;
use JSON;

my @scans;
foreach(@ARGV) {
    my $scan = new SSLScan();
    $scan->readFromFile($_);
    push @scans, $scan;
}

my %vulnerabilities;
foreach $vname ('proto', 'weak_ciphers', 'anonymous_ciphers', 'scsv', 'rsa strength', 'signer', 'cert time', 'renegotiation', 'compression', 'heartbleed') {
    my @vulns;
    foreach(@scans) {
        if(exists $_->{'vulnerabilities'}->{$vname}) {
            print "$vname\n";
            push(@vulns, [
                    "Testing SSL server $_->{'host_ip'} on port $_->{'host_port'}",
                    $_->{'vulnerabilities'}->{$vname}
            ]);
        }
    }
    if(scalar(@vulns) > 0) {
        $vulnerabilities{$vname} = \@vulns;
    }
}

sub printIssues {
    my ($filename, $vname) = @_;
    return if not exists $vulnerabilities{$vname};
    my $dataref = $vulnerabilities{$vname};
    return if(scalar(@{$dataref}) == 0);
    open(my $fh, ">", "$filename")
        or die "Can't open $filename";
    foreach(@{$dataref}) {
        print $fh "\x1b[1;34m$_->[0]\x1b[0m\n";
        foreach $ln (@{$_->[1]}) {
            print $fh "$ln\n";
        }
        print $fh "\n\n";
    }
    close $fh;
}


printIssues("Vulnerable SSL Protocols.spl", 'proto');
printIssues("Weak SSL Ciphers.spl", 'weak_ciphers');
printIssues("Anonymous SSL Ciphers.spl", 'anonymous_ciphers');
printIssues("TLS Fallback SCSV Not Supported.spl", 'scsv');
printIssues("Weak RSA Certificate.spl", 'rsa strength');
printIssues("Self-signed Certificate.spl", 'signer');
printIssues("Expired Certificate.spl", 'cert time');
printIssues("TLS Compresssion is Enabled.spl", 'compression');
printIssues("TLS Renegotiation Not Supported.spl", 'renegotiation');
printIssues("Heartbleed Vulnerability.spl", 'heartbleed');
