# -*- Perl -*-
#
# File:  POE/Component/PSD/Server/Session.pm
# Desc:  Generic process handler service
# Date:  Wed Sep 22 14:01:28 2004
# Stat:  Prototype, Experimental
#

package POE::Component::PSD::Server::Session;
use 5.006;
use strict;
use warnings;

our $PACK = __PACKAGE__;
our $VERSION = '0.01';
our @ISA     = qw( );

use PTools::Local;
use POE;
use POE::Wheel::Run;
use POE::Filter::Stream;
use POE::Filter::Line;
use POE::Driver::SysRW;
#use POE::Filter::HTTPD;
use POE::Component::PSD::Server::Log;

my $Local     = "PTools::Local";
my $LogClass  = "POE::Component::PSD::Server::Log";
my $Log       = $LogClass->new();

#-----------------------------------------------------------------------
# Still in parent session context
#-----------------------------------------------------------------------

sub spawn
{   my($class, $login, $userSession, $request) = @_;

    # Note: The events generated here are handled in the Control session, 
    # and that's where the handler methods are defined. This provides the 
    # communication path from child to parent.
    #
    #  $login       = <user's login name>
    #  $userSession = <user's session ID>
    #  $uriPath     = session/foo
    #  $realm       = foo
    #  $prog        = /some/path/to/cgi-bin/session/foo.pl
    #
    my($uriPath) = $request->uri->path() =~ m#/(.*)/?#;       # session/foo
    my($realm)   = $uriPath =~ m#[^/]*/([^\s\$]*)#;           # foo
    my $prog     = $Local->path('app_cgidir', "$uriPath.pl"); # session/foo.pl
    my(@execList)= ( $prog, $login, $userSession, $realm );   # passed to exec
    my($uid,$gid)= ( getpwnam( $login ) )[2,3];               # array "slice"

    if (! (defined $uid and defined $gid) ) {
	$uid ||="";
	$gid ||="";
	$Log and $Log->write(1, "can't get uid/gid for $login: ($uid:$gid)");
	return;
    }
    $Log and $Log->write(1, "spawn user session (user='$login')($uid:$gid)");
    $Log and $Log->write(5, "run '@execList' (user='$login')");

    my $wheel = POE::Wheel::Run->new
    (   Program      => \@execList,

      # User         => $uid,                 # Adjust UID. Need to be root.
      # Group        => $gid,                 # Adjust GID. Need to be root.

      # FIX: allow for read/write of large data chunks here. Also, can
      # we 'glue' response stream directly back to requesting socket??
      # Might be able to do this in the Manager class.
      # StdinFilter  => POE::Filter::HTTPD->new(),   # uncomment 'use', above

        StdinFilter  => POE::Filter::Stream->new(),     # Stream
        StdoutFilter => POE::Filter::Stream->new(),     # Stream
        StderrFilter => POE::Filter::Stream->new(),     # Stream

        StdinDriver  => POE::Driver::SysRW->new( BlockSize => 131070 ),
        StdoutDriver => POE::Driver::SysRW->new( BlockSize => 131070 ),
        StderrDriver => POE::Driver::SysRW->new( BlockSize => 131070 ),

        StdinEvent   => "wheel_stdin",
        StdoutEvent  => "wheel_stdout",    # event renamed in Manager class
        StderrEvent  => "wheel_stderr",    # event renamed in Manager class
        CloseEvent   => "wheel_done",      # event renamed in Manager class
	ErrorEvent   => "wheel_ERROR",     # event renamed in Manager class
    );

    return $wheel;     # return wheel so Manager class can track everything
}
#_________________________
1; # Required by require()
