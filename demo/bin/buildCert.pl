#!/opt/perl/bin/perl
#
# File:  buildCert.pl
# Desc:  Create and self-sign a set of SSL server certificate files
# Note:  For details on this, refer to the following URLs.
#        http://www.apache-ssl.org/
#        http://www.openssl.org/support/faq.html#USER1
#        
use Cwd;
BEGIN {  # Script is relocatable. See http://ccobb.net/ptools/
  my $cwd = $1 if ( $0 =~ m#^(.*/)?.*# );  chdir( "$cwd/.." );
  my($top,$app)=($1,$2) if ( getcwd() =~ m#^(.*)(?=/)/?(.*)#);
  $ENV{'PTOOLS_TOPDIR'} = $top;  $ENV{'PTOOLS_APPDIR'} = $app;
} #-----------------------------------------------------------
use PTools::Local;          # PTools local/global vars/methods
use PTools::String;         # includes user 'prompt()' method

my $Local       = "PTools::Local";
my $String      = "PTools::String";
my $Basename    = $Local->getBasename();
my $Hostname    = $Local->getHostname();
my $OpenSSL     = &findOpenSSL;        # attempt to locate OpenSSL binary
my $UseRandFile = 0;                   # will use /dev/random, if available
my $RandFile    = "rand.dat";          # will create rand data if necessary

my $ServerCert  = $Local->path('app_datdir', "ssl/$Hostname.cert.cert");
my $ServerCsr   = $Local->path('app_datdir', "ssl/$Hostname.cert.csr" );
my $ServerKey   = $Local->path('app_datdir', "ssl/$Hostname.cert.key" );
my $PrivateKey  = $Local->path('app_datdir', "ssl/$Hostname.priv.pem" );
my $ClientCert  = $Local->path('app_datdir', "ssl/client.cert.cert"   );
my $ClientCsr   = $Local->path('app_datdir', "ssl/client.cert.csr"    );
my $ClientPrvKey= $Local->path('app_datdir', "ssl/client.priv.pem"    );


&main();
exit(0);


# warn PTools::Local->dump('incpath');
# warn PTools::Local->dump('inclib');
# warn PTools::Local->dump('vars');


sub main
{   my($arg) = @_;

    if ($ARGV[0] and $ARGV[0] =~ /^-h|--help/) {
	&helpMe();
	exit(0);
    }

    &promptUser();
    
    &createRandFile();     # if no /dev/random or /dev/urandom
    &createTestCert();

    ## &createClientCert();
    &deleteRandFile();     # if a 'rand file' was created here

    &showCertFileNames();
    return;
}

sub findOpenSSL
{   my($arg) = @_;
    return "/opt/openssl/bin/openssl" if (-x "/opt/openssl/bin/openssl"); 
    return "/usr/bin/openssl"         if (-x "/usr/bin/openssl"); 
    die "$Basename: Unable to locate 'openssl' command";
}

sub promptUser
{   my($arg) = @_;

    &showCertFileNames();
    print "This script will create the above certificate files\n";
    my $response = $String->prompt( 
	"\nContinue? (y/n): ", "^([YyNn])", "\n Expecting one of 'y' or 'n'\n\n"
    );
    exit(0) unless ($response =~ /^Y/i);

    return;
}

sub showCertFileNames
{   my($arg) = @_;

    print "-" x 72 ."\n";
    print "Server Cert: $ServerCert\n";
    print "Server Csr:  $ServerCsr\n";
    print "Server Key:  $ServerKey\n";
    print "Private Key: $PrivateKey\n";
    print "-" x 72 ."\n";

    return;
}

sub createRandFile
{   my($arg) = @_;
    #
    # This first bit is a workaround when no "randomness device" exists.
    # Since the openssl "rand" subcommand itself needs random input we
    # first create "somewhat-random" data and use that to generate
    # a "more-psudo-random" file. The resulting random file can then
    #  .  get moved to "$HOME/.rnd" (a default location), or
    #  .  pointed to via the $RANDFILE environment variable.
    #  .  used with the Apache "mod_ssl" package to allow the
    #     Webserver to successfully initialize during startup
    #     e.g., in ...apache/conf/httpd.conf:
    #       SSLRandomSeed startup builtin
    #       SSLRandomSeed startup file:conf/rand.dat 1024
    #       SSLRandomSeed connect builtin
    #       SSLRandomSeed connect file:conf/rand.dat 1024
    #
    # Unfortunately, not all of the "openssl" subcommands recognize
    # the "-rand <randfile>" option. Fortunately "rand" itself does.
    # After we create the file, we set the RANDFILE EnvVar to this,
    # and set a flag to indicates in this script we are using a file.
    #

    return
        if (! $UseRandFile and ((-r "/dev/urandom") or (-r "/dev/urandom")) );
    #--------------------------------------------------------

    print "-" x 72 ."\n";
    print "Create random number seed file\n";
    print "------------------------------\n";
    my @args;

    $RandFile = "./rand.dat";
    my $randTmp  = "./rand.tmp";
    delete $ENV{RANDFILE};

    `/bin/rm -f $randTmp $RandFile`;

    #-----------------------------------------
    # Generate psudo-random noise to help make random seed unique.
    #
    my($psudoRandom,@asciiChars);
    foreach (32 .. 126) { push @asciiChars, chr($_); }
    foreach ( 1 .. 120) { $psudoRandom .= $asciiChars[rand @asciiChars]; }
    #-----------------------------------------

    local(*OUT);
    open( OUT, ">$randTmp")  || die "$Basename: Error: Can't open $randTmp";
    print OUT $psudoRandom   || die "$Basename: Error: Can't write $randTmp";
    close(OUT)               || die "$Basename: Error: Can't close $randTmp"; 

    `$OpenSSL rand -rand rand.tmp -out $RandFile 2048`;
    $? and die "$Basename: Error: $OpenSSL rand failed";

    print "2048 random bytes generated\n";
    `/bin/rm -f $randTmp`;

    $ENV{RANDFILE} = $RandFile;
    $UseRandFile   = "true";
    return;
}

sub createTestCert
{   my($arg) = @_;

    print "-" x 72 ."\n";
    print "Create a Test Certificate\n";
    print "------------------------------\n";
    my @args;

    if ( $UseRandFile ) {
        print "Using random number seed file: $RandFile\n";
	@args = ( "req","-rand","$RandFile","-new","-keyout","$PrivateKey");
    } else {
	@args = ( "req","-new","-keyout","$PrivateKey");
    }
    #-----------------------------------------------------
    # Here is where the certificate is generated.
    # Be prepared for a lot of prompts here...
    #
    my $newCert = `$OpenSSL @args`;
    $? and die "$Basename: Error: $OpenSSL req failed";
    #-----------------------------------------------------

    my $newCsr = $ServerCsr;
    local(*OUT);
    open( OUT, ">$newCsr") || die "$Basename: Error: Can't open $newCsr";
    print OUT $newCert     || die "$Basename: Error: Can't write $newCsr";
    close(OUT)             || die "$Basename: Error: Can't close $newCsr"; 

    #
    # WARN: this following step is noted as optional in URL
    # "http://www.apache-ssl.org/" with the notation
    # "Step two - remove the passphrase from the key (optional)"
    #
    # WARN: as noted in the following URL, you DON'T want to do this.
    # http://www.openssl.org/support/faq.html#USER9
    # "9. How can I remove the passphrase on a private key?"
    # "...Leaving a private key unencrypted is a major security risk."
    #
    # That said, the reason for doing so is to avoid having to enter
    # the SSL private key password on the system console each and every
    # time the system reboots or the Web server process is restarted.
    #
    print "------------------------------\n";

    `$OpenSSL rsa -in $PrivateKey -out $ServerKey`;
    $? and die "$base: Error: $OpenSSL rsa failed";

    print "------------------------------\n";

    @args = ("x509","-in","$ServerCsr","-out","$ServerCert","-req","-signkey","$ServerKey","-days","365");
    `$OpenSSL @args`;
    $? and die "$base: Error: $OpenSSL x509 failed";

    `/bin/ls -l $ServerCert`;

    return;
}

sub createClientCert
{   my($arg) = @_;

    print "-" x 72 ."\n";
    print "Create a Client Certificate\n";
    print "------------------------------\n";
    my @args;

    @args = ("req","-new","-keyout","$ClientPrivKey");
    my $cliCert = `$OpenSSL @args`;
    $? and die "$base: Error: $OpenSSL req failed";

    my $cliCsr = $ClientCsr;
    local(*OUT);
    open( OUT, ">$cliCsr") || die "$Basename: Error: Can't open $cliCsr";
    print OUT $cliCert     || die "$Basename: Error: Can't write $cliCsr";
    close(OUT)             || die "$Basename: Error: Can't close $cliCsr"; 

    @args = ("x509","-req","-in","$ClientCsr","-out","$ClientCert","-signkey","$ServerKey","-CA","$ServerCert","-CAkey","$ServerKey","-CAcreateserial","-days","36500");
    `$OpenSSL, @args`;
    $? and die "$base: Error: $OpenSSL x509 failed";
    
    `bin/ls -l $ClientCert`;

    return;
}

sub deleteRandFile
{   my($arg) = @_;

    return unless $UseRandFile;

    print "-" x 72 ."\n";
    print "Delete random number seed file\n";
    `/bin/rm -f $RandFile`;
    print "Done.\n";

    return;
}

sub helpMe
{   my($arg) = @_;

print <<"__EndOfText__";

 -----------------------------------------------------------------
 Enter PEM pass phrase:                <----- note 'PEM pass phrase'
 Verifying - Enter PEM pass phrase:
 -----
 You are about to be asked to enter information that 
 will be incorporated into your certificate request. 
 What you are about to enter is what is called a 
 Distinguished Name or a DN.  There are quite a few 
 fields but you can leave some blank For some fields 
 there will be a default value, If you enter '.', the 
 field will be left blank.
 -----
 Country Name (2 letter code) [AU]:
 State or Province Name (full name) [Some-State]:
 Locality Name (eg, city) []:
 Organization Name (eg, company) [Internet Widgits Pty Ltd]:
 Organizational Unit Name (eg, section) []:
 Common Name (eg, YOUR name) []:       <----- your COMPUTER'S name
 Email Address []:
 
 Please enter the following 'extra' attributes
 to be sent with your certificate request
 A challenge password []:
 An optional company name []:
 ------------------------------
 Enter pass phrase for <KeyFile>:      <----- use 'PEM pass phrase'

 -----------------------------------------------------------------
 This script runs the OpenSSL tool to generate certificate files.
 It will prompt you for information necessary to create a set of
 certificate files. The important prompts have callouts, above.
 Warning: The cert files created are not intended for production.
 -----------------------------------------------------------------

__EndOfText__
    return;
}

__END__

=head1 NAME

buildCert.pl - Create and self-sign a set of SSL server cert files

=head1 SYNOPSIS

 % buildCert.pl

 Enter PEM pass phrase:                <----- note 'PEM pass phrase'
 Verifying - Enter PEM pass phrase:
 -----
 You are about to be asked to enter information that 
 will be incorporated into your certificate request. 
 What you are about to enter is what is called a 
 Distinguished Name or a DN.  There are quite a few 
 fields but you can leave some blank For some fields 
 there will be a default value, If you enter '.', the 
 field will be left blank.
 -----
 Country Name (2 letter code) [AU]:
 State or Province Name (full name) [Some-State]:
 Locality Name (eg, city) []:
 Organization Name (eg, company) [Internet Widgits Pty Ltd]:
 Organizational Unit Name (eg, section) []:
 Common Name (eg, YOUR name) []:       <----- your COMPUTER'S name
 Email Address []:

 Please enter the following 'extra' attributes
 to be sent with your certificate request
 A challenge password []:
 An optional company name []:
 ------------------------------
 Enter pass phrase for <KeyFile>:      <----- use 'PEM pass phrase'


=head1 DESCRIPTION

This script runs the OpenSSL tool to generate certificates,
which prompts for information necessary to create a set of
certificate files, as shown in the L<Synopsis|"SYNOPSIS">
section, above.

The interesting prompts that you need to know about (at
least to get started) are the following.

 Common Name (eg, YOUR name) []:

 An optional company name []:

For B<Common Name>, enter the name of the computer for which
this certificate set will be generated. Enter it exactly how
users will enter it in their browser. Users will be prompted
by their browser to view the certificate if it differs from 
the name their browser expects.

For B<An optional company name> enter the name that yo uwant
to show up as I<having signed> your certificate. This may
or may not be important, depending on who accesses your site.

Also remember the phrase you enter at the first prompt to 
B<Enter PEM pass phrase:> as you will need to enter the same 
phrase at the last B<Enter pass phrase for ...> prompt.

=head1 SEE ALSO

 http://www.apache-ssl.org/

 http://www.openssl.org/support/faq.html#USER1

=head1 WARNINGS

B<This script is intended for test use only.> This script
allows you to behave in ways that are known not to be secure.

On a production system you should I<always> consider carefully
before adding the 'pass phrase' into a certificate, and you
should fully understand the ramifications of doing so.

On a production system you should I<never> allow the private
key to be available to anyone other than the designated
security administrator.

Before using generating certificates for a production 
environment, read the documents at the above URLs.


=head1 AUTHOR

Chris Cobb, E<lt>nospamplease@ccobb.netE<gt>

=head1 COPYRIGHT

Copyright (c) 2003-2007 by Chris Cobb. All rights reserved.
This module is free software; you can redistribute it and/or 
modify it under the same terms as Perl itself.

=cut
