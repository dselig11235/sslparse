#!/usr/bin/perl -w

# Used for debugging only
use Term::ANSIColor;
use JSON;

package SSLScan;
sub matchNonGreen {
    my $str = shift(@_);
    return $str if not $str;
    return $str =~ /\x1b\[([01];)?3[^2]m/;
}

sub strip_color {
    my $s = shift;
    $s =~ s/\x1b\[[0-9;]*m//g;
    return $s;
}


sub new {
    my $class = shift;
    return bless {}, $class;
}

sub readFromFile {
    my ($self, $filename) = (shift, shift);
    open(my $fh, "<", $filename)
        or die "Can't open $filename";
    $self->{'sslscan_version'} = <$fh>;
    $self->{'openssl_version'} = <$fh>;
    <$fh>;
    my $host = <$fh>;
    $host = strip_color($host);
    if($host =~ /(\S+) on port (\d+)/) {
        $self->{'host_ip'} = $1;
        $self->{'host_port'} = $2;
    } else {
        warn "can't find host information from '$host'";
    }
    my $section = "";
    while(<$fh>) {
        # Match bright blue text
        if(/\x1b\[1;34m/) {
            $section = strip_color($_);
            $section =~ s/^\s+//;
            $section =~ s/\s+$//;
            $section =~ s/://;
            $self->{$section} = [];
        } else {
            chomp;
            push @{$self->{$section}}, $_;
        }
    }
    close $fh;
    $self->{'vulnerabilities'} = {};
    $self->getCipherIssues();
    $self->getSCSVIssues();
    $self->getCertIssues();
}


sub printAllData {
    my $self = shift;
    my %data = %{$self};
    foreach $key (keys %data) {
        print "\x1b[1;34m$key\x1b[0m\n";
        foreach (@{$data{$key}}) {
            print "$_\n";
        }
        print "\n";
    }
}

sub getCipherIssues {
    my $self = shift;
    return if not exists $self->{'Supported Server Cipher(s)'};
    my @ciphers = @{$self->{'Supported Server Cipher(s)'}};
    my @vulnerable_protocols = ();
    my @weak_ciphers = ();
    my @anonymous_ciphers = ();
    foreach $cipher (@ciphers) {
        if( $cipher =~ /^(\S+\s+)(\S+)(\s+)(\S+)( bits\s+)(\S+)(\s+.*)/) {
            #              NA, proto, NA, bits, NA, cipher, rest
            my @matches = ($1, $2,    $3, $4,   $5, $6,     $7);
            my ($proto, $bits, $cipher) = ($matches[1], strip_color($matches[3]), $matches[5]);
            if($bits == 112) {
                $matches[3] = "\x1b[33m$bits";
                $matches[4].= "\x1b[0m";
            } elsif($bits < 112) {
                $matches[3] = "\x1b[31m$bits";
                $matches[4].= "\x1b[0m";
            }
            my $out = join('', @matches);
            if($proto =~ /\x1b\[([01];)?(3[^2])m/) {
                push(@vulnerable_protocols, $out);
            }
            if($cipher =~ /\x1b\[([01];)?(35)m/) {
                push(@anonymous_ciphers, $out);
            } elsif($cipher =~ /RC4|MD5/ || $bits < 128) {
                push(@weak_ciphers, $out);
            }
        }
    }
    $self->{'vulnerabilities'}->{'proto'} = \@vulnerable_protocols if(scalar(@vulnerable_protocols) != 0);
    $self->{'vulnerabilities'}->{'weak_ciphers'} = \@weak_ciphers if(scalar(@weak_ciphers) != 0);
    $self->{'vulnerabilities'}->{'anonymous_ciphers'} = \@anonymous_ciphers if(scalar(@anonymous_ciphers) != 0);
}

sub getSCSVIssues {
    my $self = shift;
    my @scsv_issues = ();
    return if not exists $self->{'TLS Fallback SCSV'};
    if(strip_color($self->{'TLS Fallback SCSV'}[0]) =~ /Server does not support TLS Fallback SCSV/) {
        push(@scsv_issues, $self->{'TLS Fallback SCSV'}[0]);
        #$self->{'vulnerabilities'}->{'scsv'} = [$data{'TLS Fallback SCSV'}[0]];
    }
    $self->{'vulnerabilities'}->{'scsv'} = \@scsv_issues if(scalar(@scsv_issues) != 0);
}

sub getCertIssues {
    my $self = shift;
    return if not exists $self->{'SSL Certificate'};
    my %certdata;
    my @certissues = ();
    my @signerissues = ();
    my @timeissues = ();
    foreach(@{$self->{'SSL Certificate'}}) {
        if(/([^:]+): (.*)/) {
            $certdata{$1} = $2;
        }
    }

    if(matchNonGreen($certdata{'Signature Algorithm'}) || 
       matchNonGreen($certdata{'RSA Key Strength'})) {
        @certissues = (
                "Signature Algorithm: $certdata{'Signature Algorithm'}",
                "RSA Key Strength: $certdata{'RSA Key Strength'}"
            )
    }
    if(matchNonGreen($certdata{'Subject'}) ||
         matchNonGreen($certdata{'Altnames'}) ||
         matchNonGreen($certdata{'Issuer'})) {
         @signerissues = (
             "Subject: $certdata{'Subject'}",
             "Altnames: $certdata{'Altnames'}",
             "Issuer: $certdata{'Issuer'}"
         );
     }
     if(matchNonGreen($certdata{'Not valid before'}) ||
         matchNonGreen($certdata{'Not valid after'})) {
         @timeissues = (
             "Not valid before: $certdata{'Not valid before'}",
             "Not valid after: $certdata{'Not valid after'}"
         );
     }
    $self->{'vulnerabilities'}->{'rsa strength'} = \@certissues if(scalar(@certissues) != 0);
    $self->{'vulnerabilities'}->{'signer'} = \@signerissues if(scalar(@signerissues) != 0);
    $self->{'vulnerabilities'}->{'cert time'} = \@timeissues if(scalar(@timeissues) != 0);
}

1;
