# -*- Perl -*-
#
# File:  POE/Component/PSD/Client/Login.pm
# Desc:  Client script login facility
# Date:  Sun Mar 25 19:47:39 2007
# Stat:  Prototype, Experimental
#
package POE::Component::PSD::Client::Login;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.01';
our @ISA     = qw( LWP::UserAgent );

use PTools::Local;
use PTools::Date::Format;
use LWP::UserAgent;

my $DFM = "PTools::Date::Format";


sub login
{   my($self, $logLevel) = @_;

    $self = $Global::GLOBAL_LOGOBJ;
    return $self if $self;         # is a "singleton class"

    $Global::GLOBAL_LOGOBJ   = $self;
    $Global::GLOBAL_LOGLEVEL = $logLevel ||3;

    $|= 1;  ##  if ( PTools::Local->param('nph') );

    ## autoflush STDOUT 1;
    ## autoflush STDERR 1;

    return $self;                 # return "$class" here, NOT "$self"
}
#_________________________
1; # Required by require()

#  $DateFmt = "%c";                        # 12/21/05 09:05:39
#  $DateFmt = "%a, %d-%b-%Y %I:%M:%S %p";  # Wed, 21-Dec-2005 09:05:39 pm
#  $DateFmt = "%d-%b-%Y %H:%M:%S";         # 21-Dec-2005 21:05:39
#  $DateFmt = "%Y%m%d %H:%M:%S";           # 20051221 21:05:39

# Use "SCMlog" date format here? 
# (It's neither "parsable" nor "sortable" without prior reformatting)
#  $DateFmt = "%d-%b-%Y.%H:%M:%S:%Z";      # 21-Dec-2005.21:05:39:PST

my $DateFmt = "%Y%m%d %H:%M:%S";           # 20051221 21:05:39

sub formatDate   { $DFM->time2str( $DateFmt, time() ) }
### formatDate   { time() }          # allows for simple subclassing.
sub getLogLevel  { $Global::GLOBAL_LOGLEVEL }
sub setLogLevel  { $Global::GLOBAL_LOGLEVEL  = ($_[1] ||3) }
sub incrLogLevel { $Global::GLOBAL_LOGLEVEL += ($_[1] ||3) }
sub decrLogLevel { $Global::GLOBAL_LOGLEVEL -= ($_[1] ||3) }

