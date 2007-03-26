# -*- Perl -*-
#
# File:  POE/Component/PSD/Server/Log.pm
# Desc:  Generic logging facility
# Date:  Wed Feb 02 17:03:35 2005
# Stat:  Prototype, Experimental
#
package POE::Component::PSD::Server::Log;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.01';
#our @ISA    = qw( );

use PTools::Date::Format;

my $DFM = "PTools::Date::Format";


*new = \&spawn;

sub spawn
{   my($class, $logLevel) = @_;

    my $self = $Global::GLOBAL_LOGOBJ;
    return $self if $self;         # is a "singleton class"

    $Global::GLOBAL_LOGOBJ   = $class;
    $Global::GLOBAL_LOGLEVEL = $logLevel ||3;

    $|= 1;

    $class->write(4, "spawning Log service");

    ## autoflush STDOUT 1;
    ## autoflush STDERR 1;

    return $class;                 # return "$class" here, NOT "$self"
}

*log      = \&writeLog;
*write    = \&writeLog;
*writelog = \&writeLog;

sub writeLog
{   my($self,$verbose,$logMsg) = @_;

    # Since the REAL server runs as a daemon proc, it has already 
    # redirected STDOUT and STDERR to the log file. All we need to 
    # do here is format a time string and simply print the message.

    return if $verbose > $Global::GLOBAL_LOGLEVEL;

    print $self->formatDate();
    print " $logMsg\n";

    return;
}

*error     = \&writeWarn;
*warn      = \&writeWarn;
*writewarn = \&writeWarn;

sub writeWarn
{   my($self,$verbose,$warnMsg) = @_;

    # This method is intended for use within a child process run 
    # by the "POE::Component::GCS::Server::Queue" class. Child 
    # processes so run should NOT write ANY output to STDOUT and, 
    # instead, send any message to STDERR. This provides a method
    # similar to the "writeLog()" method used "everywhere else".

    return if $verbose > $Global::GLOBAL_LOGLEVEL;

    warn "$warnMsg\n";
    return;
}


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
#_________________________
1; # Required by require()
