# -*- Perl -*-
#
# File:  POE/Component/PSD/Server/SessionEntry.pm
# Desc:  A user's session data
# Date:  Sat Jun 10 21:16:15 2006
# Stat:  Prototype, Experimental
#

package POE::Component::PSD::Server::SessionEntry;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.01';
our @ISA     = qw( );

my $StateName = {
      "" => "*Error: Undefined*",
    "00" => "Logged Out",
    "01" => "Active Session",
    "02" => "Timedout Session",
    "03" => "Terminated Session",
    "98" => "Failed Session",
    "99" => "Uninitialized Session",
};
my $State = { reverse %$StateName };

my $InitialState = 99;

sub LOGGED_OUT { $State->{"Logged Out"}         }
sub ACTIVE     { $State->{"Active Session"}     }
sub TIMEDOUT   { $State->{"Timedout Session"}   }
sub TERMINATED { $State->{"Terminated Session"} }
sub FAILED     { $State->{"Failed Session"}     }
sub stateName  { $StateName->{ $_[0]->state() } }

sub new
{   my($class, $uname, $login, $sessionId) = @_;

    bless my $self = {

	  uname => $uname,            # user's Unix uname
	  login => $login,            # user's Login name
	session => $sessionId,        # process SessionId

	  state => $InitialState,     # session state
	started => time(),            # session start time
	  ended => "",                # session end time
       accessed => 0,                 # last accessed time
          count => 0,                 # access count
        bytesIn => 0,                 # nbr bytes in
       bytesOut => 0,                 # nbr bytes out
      restarted => 0,                 # nbr times restarted
    
    }, ref($class)||$class;

    $self->setErr(0,"");
    return $self;
}

sub set    { $_[0]->{$_[1]}=$_[2]         }   # Note that the 'param' method
sub get    { return( $_[0]->{$_[1]}||"" ) }   #    combines 'set' and 'get'
sub param  { $_[2] ? $_[0]->{$_[1]}=$_[2] : return( $_[0]->{$_[1]}||"" )  }
sub setErr { return( $_[0]->{STATUS}=$_[1]||0, $_[0]->{ERROR}=$_[2]||"" ) }
sub status { return( $_[0]->{STATUS}||0, $_[0]->{ERROR}||"" )             }
sub stat   { ( wantarray ? ($_[0]->{ERROR}||"") : ($_[0]->{STATUS} ||0) ) }
sub err    { return($_[0]->{ERROR}||"")                                   }

sub uname     { $_[0]->get('uname')    }             # read only
sub login     { $_[0]->get('login')    }             # read only
sub sessionId { $_[0]->get('session')  }             # read only
sub started   { $_[0]->get('started')  }             # read/write
sub bytesIn   { $_[0]->get('bytesIn')  }             # see "incrBytesIn()"
sub bytesOut  { $_[0]->get('bytesOut') }             # see "incrBytesOut()"
sub accessed  { $_[0]->get('accessed') }             # see "setAccessTime()"
sub count     { $_[0]->get('count')    }             # see "incrCount()"
sub restarted { $_[0]->get('restarted')}             # see "incrRestarted()"

sub ended     { $_[0]->param('ended',    $_[1]) }    # read/write
sub state     { $_[0]->param('state',    $_[1]) }    # read/write

*setEnded  = \&ended;
*setState  = \&state;

sub isActive     { $_[0]->get('state') eq ACTIVE     }
sub isLoggedOut  { $_[0]->get('state') eq LOGGED_OUT }
sub isTimedOut   { $_[0]->get('state') eq TIMEDOUT   }
sub isTerminated { $_[0]->get('state') eq TERMINATED }
sub isFailed     { $_[0]->get('state') eq FAILED     }

sub incrBytesIn
{   my($self, $num) = @_;
    return unless $num =~ /^\d+$/;
    $self->{'bytesIn'} += $num;
}

sub incrBytesOut
{   my($self, $num) = @_;
    return unless $num =~ /^\d+$/;
    $self->{'bytesOut'} += $num;
}

*resetAccessTime = \&setAccessTime;

sub setAccessTime
{   my($self, $time) = @_;
    if ( $time ) {
        return unless ($time =~ /^\d+/);
    }
    $self->{'accessed'} = ($time || time() );
}

*incrAccessCount = \&incrCount;

sub incrCount
{   my($self) = @_;
    $self->{'count'}++;
}

*incrRestartCount = \&incrRestarted;

sub incrRestarted
{   my($self) = @_;
    $self->{'restarted'}++;
}

sub dump {
    my($self)= @_;
    my($pack,$file,$line)=caller();
    my $text  = "DEBUG: ($PACK\:\:dump)\n  self='$self'\n";
       $text .= "CALLER $pack at line $line\n  ($file)\n";
    #
    # The following assumes that the current object 
    # is a simple hash ref ... modify as necessary.
    #
    my $value;
    foreach my $param (sort keys %$self) {
	$value = $self->{$param};
	$value = $self->zeroStr( $value, "" );  # handles value of "0"
	$text .= " $param = $value\n";
    }
    $text .= "_" x 25 ."\n";
    return($text);
}

sub zeroStr
{   my($self,$value,$undef) = @_;
    return $undef unless defined $value;
    return "0"    if (length($value) and ! $value);
    return $value;
}
#_________________________
1; # Required by require()
