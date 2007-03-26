# -*- Perl -*-
#
# File:  POE/Component/PSD/Client.pm
# Desc:  A client for script access to a PSD Web server
# Stat:  Prototype, Experimental
#
# Synopsis:
#        TBD
#
# Dependencies:
#        A running Persistent Session Daemon process
#        .  a valid SSL client certificate
#           - a script to create and self-sign certs is included w/PSD app
#           - OpenSSL is required to run the certificate generator script
#        .  Also required: several 'PerlTools' global modules
#           -  PTools::Date::Format
#           -  PTools::Passwd
#
package POE::Component::PSD::Client;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.01';
our @ISA     = qw( );

my $LoginClass   = "POE::Component::PSD::Client::Login";
my $ConfigClass  = "POE::Component::PSD::Client::Config";

my $BaseName     = ( $0 =~ m#^(?:.*/)?(.*)#);
my $EnvPath      = "/usr/bin:/usr/sbin";
my($ConfigFile,$Config,$Opts,$Debug,$Verbose);

sub new    { bless {}, ref($_[0])||$_[0]  }   # $self is a simple hash ref.
sub set    { $_[0]->{$_[1]}=$_[2]         }   # Note that the 'param' method
sub get    { return( $_[0]->{$_[1]}||"" ) }   #    combines 'set' and 'get'
sub param  { $_[2] ? $_[0]->{$_[1]}=$_[2] : return( $_[0]->{$_[1]}||"" )  }
sub setErr { return( $_[0]->{STATUS}=$_[1]||0, $_[0]->{ERROR}=$_[2]||"" ) }
sub status { return( $_[0]->{STATUS}||0, $_[0]->{ERROR}||"" )             }
sub stat   { ( wantarray ? ($_[0]->{ERROR}||"") : ($_[0]->{STATUS} ||0) ) }
sub err    { return($_[0]->{ERROR}||"")                                   }


sub run
{   my($class, $configFile ) = @_;

    print "Not much happens here yet.\n";

 ## $configFile or die "$BaseName: Error: No config file found here.";

    $ENV{PATH} = $EnvPath;              # untaint since running "-T"

  # $class->validateOptions( $configFile );    # parse @ARGV
  # $configFile = $Opts->get('configFile');    # was "-c <cfgfile>" used?

  # my $config = $ConfigClass->new( $configFile )
  #	or die $ConfigClass->error();

    return 0;
}
#_________________________
1; # Required by require()
