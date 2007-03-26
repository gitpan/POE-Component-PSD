# -*- Perl -*-
#
# File:  POE/Component/PSD/Server/Manager.pm
# Desc:  Session management service for "user command daemon"
# Date:  Tue Oct 11 10:22:41 2005
# Stat:  Prototype, Experimental
#
# Service Alias:  SESSION
# Public Events:  RUN ( $runArgsHashRef )
#
# Usage:
#        $kernel->post('SESSION' => "RUN", $runArgsHashRef );
#
# Note:  The "runArgsHashRef" is expected to contain the following params.
#        .  uname       - user's login user name
#        .  realm       - user's login "realm"
#        .  sessionId   - user's
#        .  request     - HTTP request  / message object
#        .  response    - HTTP response / message object
#        .  querystring - HTTP 'QUERY_STRING' data
#        .  pathinfo    - HTTP 'PATH_INFO' string
#        .
# Note:  The "$request" (task to run) is expected to be an object
#        of the "HTTP::Request" class, and the $response is a
#        "POE::Component::Server::SimpleHTTP::Response" object.
#
# Note:  This class emulates the Web server/CGI process environment,
#        including the following components.
#        . a two-stage session timeout is used:
#           -  when session starts, set an nnnn-second timer
#               (based on the SessionTimeout config value)
#           -  when nnnn-second timer trips, send child a SIGTERM
#           -  set a three-second timer for the same session
#           -  if child exits, cancel the three-second timer
#           -  if three-second timer trips, send child a SIGKILL
#        .  a set of environment variables is made available
#           during each "HTTP request cycle", including those
#           needed by the original CGI.pm CPAN module.
#
package POE::Component::PSD::Server::Manager;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.02';
#our @ISA    = qw( );

use POE;
use POE::Session;
use POE::Component::PSD::Server::Config;
use POE::Component::PSD::Server::CGI;
use POE::Component::PSD::Server::Log;
use POE::Component::PSD::Server::Session;
use POE::Component::PSD::Server::SessionEntry;
use POSIX qw( errno_h );         # defines EPERM, ESRCH
### PTools::Date::Format;

my $CGIClass       = "POE::Component::PSD::Server::CGI";
my $LogClass       = "POE::Component::PSD::Server::Log";
my $SessionClass   = "POE::Component::PSD::Server::Session";
my $SessEntryClass = "POE::Component::PSD::Server::SessionEntry";
my $ManagerSessId  = undef;
my $ActiveSessions = 0;
my $MaxSessions    = 99;         # 99 child processes maximum?
my $SessTimeout    = 14400;      # 60*60*4 = 14400 = 4 hours
my $SessionHeap    = {};         # cache of '$heap's for 'sessionId's
my $SessionMap     = {};         # cache of 'SessionEntries'
my $Config;
my $Log;

#________________________________________________________________
# Here it's possible to define a 'queue is full' condition.
# Some experimenting may be necessary to determine a good value.

sub new
{   my($class, $config) = @_;
    #------------------
    # implemented as a "singleton" object. Upon first call to
    # this method will instantiate a data base object. Any
    # subsequent calls here will return the original object.

    my $self = $Global::GLOBAL_VIEWPOOLOBJ;
    return $self if (ref $self);
    #------------------

    if ( ! ref($config) ) {
	my($pack,$file,$line) = caller();
	warn "\nError: 'new' method was called without a 'config' param in '$PACK'\n";
	warn "Trace: caller='$pack'\n";
	warn "Trace:   file='$file'\n";
	warn "Trace:   line='$line'\n";
	die "Aborting server startup due to prior error.";
    }
    $Config = $config;

    $MaxSessions = $config->globalDirective('SessionsLimit', "sansQuotes");
    $MaxSessions = 99 unless ($MaxSessions =~ /^\d+$/ and $MaxSessions < 100);

    $SessTimeout = $config->globalDirective('SessionTimeout', "sansQuotes");
    $SessTimeout = 14400 unless ($SessTimeout =~ /^\d+$/);
    $CGIClass->untaint( $SessTimeout );

    $self = bless {}, ref($class)||$class;
    $Global::GLOBAL_VIEWPOOLOBJ = $self;
    return $self;
}

sub ACTIVE_SESSIONS { $ActiveSessions }
sub MAX_SESSIONS    { $MaxSessions    }
sub SESSION_TIMEOUT { $SessTimeout    }
sub tooManySessions { $ActiveSessions >= $MaxSessions }

sub listSessions               # DEBUG stuff
{   my($class) = @_; 

    my(@realms) = (sort keys %$SessionMap);
    if (! @realms) {
	return "DEBUG: == SESSION MGR: NO ACTIVE SESSIONS\n";
    }

    my $text;
    foreach my $realm (@realms) {
	my(@tokens) = (sort keys %{ $SessionMap->{$realm} });

	foreach my $token (@tokens) {
	    my $entry = $SessionMap->{$realm}->{$token};
	    if (! $entry) {
		$text .= "DEBUG: == SESSION MGR: token='$token' entry = ''\n";
		next;
	    }
	    warn "DEBUG: entry='$entry'\n";
	    my $uname = $entry->uname();
	    my $sesId = $entry->sessionId();
	    $text .= "DEBUG: =SESSION= $realm: $uname = $sesId\n";
	}
    }
    return $text;
}

*maxSessions    = \&MAX_SESSIONS;
*activeSessions = \&ACTIVE_SESSIONS;

sub createSessionEntry
{   my($class, $uname, $login, $realm, $sessionToken, $sessionId) = @_;
    my $entry = $class->getSessionEntry4Realm( $realm, $sessionToken );
    if (! $entry) {
	$entry = $SessEntryClass->new( $uname, $login, $sessionId );
	$class->mapSessionEntry2Realm( $realm, $sessionToken, $entry );
    }
    return $entry;
}

*mapEntry2Realm = \&mapSessionEntry2Realm;

sub mapSessionEntry2Realm
{   my($class, $realm, $sessionToken, $sessionEntry) = @_;
    return undef unless ($realm and $sessionToken);
    ## warn "DEBUG: mapEntry2Realm: $realm $sessionToken = $sessionEntry\n";
    return $SessionMap->{$realm}->{$sessionToken} = $sessionEntry;
}

*getEntry4Realm = \&getSessionEntry4Realm;

sub getSessionEntry4Realm
{   my($class, $realm, $sessionToken) = @_;
    return undef unless ($realm and $sessionToken);
    return undef unless (defined $SessionMap->{$realm});
    return $SessionMap->{$realm}->{$sessionToken};
}

#________________________________________________________________

sub spawn
{   my($class,$config) = @_;

    my $self = $class->new( $config );

    $Log = $LogClass->new;
    $Log->write(0, "spawning session manager service");

    my $session = POE::Session->create             # Manager Session
    ( object_states =>
	[ $self => {
	      _start => '_start_manager',
	         RUN => 'run_command',
	         run => 'run_command',
	    dispatch => 'run_command',             # hand input to child proc
     session_timeout => 'handle_session_timeout',  # session timer tripped
         set_timeout => 'handle_set_timeout',      # set a session timer
         del_timeout => 'handle_del_timeout',      # set a session timer
	            }
	],

	## heap => { },          # Note: $self is used insted of "heap" 
    );

    $ManagerSessId = $session->ID();       # Session timer hack. yuck.
    return;
}

sub _start_manager
{   my($self, $kernel) = @_[ OBJECT, KERNEL ];

    # Allow other sessions to post events to us:
    $kernel->alias_set("SESSION");
    $kernel->alias_set("session_manager");

    $Log->write(5, "initializing session manager service" );

 ## # Set up signal handlers to allow clean interrupts
 ## # print "    configuring signal watcher ...\n";
 ## $kernel->sig( "HUP",  "caught_signal" );
 ## $kernel->sig( "INT",  "caught_signal" );
 ## $kernel->sig( "TERM", "caught_signal" );

    return;
}

my($CR,$LF,$CRLF) = ("\015","\012","\015\012");    # socket protocol
my $EOD = ":HTTP_PSD_EOD:";                        # PSD protocol

my $Wheel = "";

sub run_command
{   my($self,  $kernel, $runArgs) = @_[ OBJECT, KERNEL, ARG0 ];

    # Note: $runArgs is originally created by the
    # 'Config' class, as called by the Auth class.
    #
    my $uname      = $runArgs->{uname};
    my $login      = $runArgs->{login};
    my $realm      = $runArgs->{realm};
    my $token      = $runArgs->{token};
    my $sessionId  = $runArgs->{sessionId};
    my $request    = $runArgs->{request};
    my $response   = $runArgs->{response};

    $Log->write(5, "DEBUG:    uname='$uname'" );
    $Log->write(7, "DEBUG:  request='$request'" );
    $Log->write(7, "DEBUG: response='$response'" );

    my $heap  = $SessionHeap->{$sessionId};
    my $entry = $self->getSessionEntry4Realm( $realm, $token );

    # FIX: clean this UP!! make it clearer, simpler.
    if (! $entry) {
	$entry = $SessEntryClass->new( $uname, $login, $sessionId );
	$self->mapSessionEntry2Realm( $realm, $token, $entry );
    }

    if ($heap) {                          # 'heap' for a running session
	$heap->{response} = $response;                # RESET responder!!
	$heap->{errorMessages}   = "";

	## warn "DEBUG:--------------------------------\n";

	# Create CGI-BIN EV Header strings
	my $evHeader = $self->buildEvHeader( $request, $runArgs );

	my $len = length( $request->content() );
	$Log->write(1, "SID($heap->{wid}): CMD (sending $len bytes to child)" );

	if (ref $entry) {
	    $entry->incrBytesIn( $len );
	    $entry->setAccessTime();
	    $entry->incrCount();
	}

	$heap->{wheel}->put( $evHeader . $request->content() );


	$Log->write(9, "SID($heap->{wid}): CMD (user=$heap->{uid})(pid=$heap->{pid})" );

	# FIX: confirm reset 'long' works for this session
	#
	## warn "DEBUG ========== CALL RESET TIMEOUT (2) ================\n";
	$heap->{alarmId} = $self->resetTimeout( $heap );

    } elsif ( $self->tooManySessions() ) {
	$entry->setState( FAIL $entry );
	$entry->setErr( -1, 'Too many sessions' );

	$response->content( "Unable to create session for this request (01)" );
	$kernel->post( 'HTTPD', 'DONE', $response );
	$Log->write(1, "Error: Session failed: too many sessions ($ActiveSessions) (uname=$uname)" );
	return;

    } else {                              # create a new session
	# $self->run_wheel( $uname, $sessionId, $request, $response );
	$self->run_wheel( $runArgs );
    }
    return;
}

#-----------------------------------------------------------------------
#   Individual Wheel methods
#-----------------------------------------------------------------------

sub run_wheel                  # NOTE: Method not called by POE here.
{   my($self, $runArgs) = @_;

    # Here we define the handlers for events generated by the
    # child co-process as configured in the "Session" class.
    # There is one session created for each wheel that is run
    # which simplifies collecting the results from the wheel.

    $Log->write(5, "starting task process" );

    my $session = POE::Session->create              # CHILD Process session
    ( object_states =>
	[ $self => {
	      _start => '_start_wheel',
	wheel_stdout => 'handle_session_stdout',    # a child's stdout (Wheel)
	wheel_stderr => 'handle_session_stderr',    # a child's stderr (Wheel)
	  wheel_done => 'handle_session_done',      # a child is done  (Wheel)
       	 wheel_ERROR => 'handle_session_ERROR',     # a child's ERROR  (Wheel)
	            }
	],

	## args passed to "_start_wheel" method:
	#
	# args => [ $uname, $sessionId, $request, $response ],
	  args => [ $runArgs ],

	## heap => {},
    );
    ## warn "DEBUG ========== CALL RESET TIMEOUT (1) ================\n";

    my $heap = $session->get_heap();
    $heap->{timeout} = $SessTimeout;  # SET BEFORE calling 'resetTimeout'
    $heap->{alarmId} = $self->resetTimeout( $heap );

    return;
}

sub _start_wheel
{   my($self, $kernel, $heap, $session, $runArgs) =
    @_[ OBJECT, KERNEL,  HEAP,  SESSION,  ARG0 ];

    # Note: $runArgs is originally created by the
    # 'Config' class, as called by the Auth class.
    #
    my $uname      = $runArgs->{uname};
    my $sessionId  = $runArgs->{sessionId};
    my $request    = $runArgs->{request};
    my $response   = $runArgs->{response};

    #---------------------------------------------------------------
    # FINALLY. Here's where we actually start a wheel (co-process).
    # Start this wheel within the context of a Child Process session,
    # w/one child process per session to simplify process management.
    #
    my $wheel = $SessionClass->spawn( $uname, $sessionId, $request );

    my $realm = $runArgs->{realm};
    my $token = $runArgs->{token};
    my $entry = $self->getSessionEntry4Realm( $realm, $token );
    #---------------------------------------------------------------

    if ( ! $wheel) {
	$response->content( "Unable to create session for this request (02)" );
	$kernel->post( 'HTTPD', 'DONE', $response );

	$Log->write(1, "Error: Session failed: fork failed (uname=$uname)" );

	$entry->state( FAILED $entry );
	$entry->setErr( -1, "Session failed to fork" );

	return;
    }
    $SessionHeap->{$sessionId} = $heap;

    $entry->state( ACTIVE $entry );

    my $wheelId  = $wheel->ID();
    my $wheelPid = $wheel->PID();

    # Warn: this syntax ASSUMES current session only controls ONE wheel!
    # Warn: Don't set a timer in this 'Wheel' context. Set/reset/delete
    # all session timers in the 'Manager session' context. :-(
    #
    $heap->{wheel}    = $wheel;        # MUST cache to keep session "alive"
    $heap->{pid}      = $wheelPid;     # child process ID  - for convenience
    $heap->{uid}      = $uname;        # user's uname name
    $heap->{wid}      = $wheelId;      # wheel's uneque ID - for convenience
    $heap->{userSess} = $sessionId;    # from HTTP PsdSession cookie
    $heap->{entry}    = $entry;        # cache 'SessionEntry' object
    #---------------------------------------------------------------

    # FIX: create a timer for this session here.

    $ActiveSessions++;
    $Log->write(1, "SID($wheelId): RUN (user=$uname)(pid=$wheelPid)(active sessions: $ActiveSessions)" );

    $Log->write(7, "DEBUG(1): response='$response'" );
    $Log->write(7, "DEBUG(1):     heap='$heap'" );

    $heap->{response} = $response;     # HTTP response object

    ## $wheel->put( $request->content() );
    ## $heap->{wheel}->put( $request->uri() );

    ## $len = length( $request->content() . "\n$EOD" );
    my $len = length( $request->content() );
    $Log->write(5, "SID($heap->{wid}): CMD (sending $len bytes to child)" );

    # Create CGI-BIN EV Header strings
    my $evHeader = $self->buildEvHeader( $request, $runArgs );

    $heap->{wheel}->put( $evHeader . $request->content() );

    return;
}

sub handle_session_stdout
{   my($heap, $kernel, $message, $wheelId) = @_[ HEAP, KERNEL, ARG0..ARG1 ];

    die "Logic Error: wheelId='$wheelId' (expecting wheelId='$heap->{wid})"
	unless ( $wheelId == $heap->{wid} );

    $message ||="";

    #-------------------------------------------------------------------
    # First we need to collect the "standard" HTTP headers.
    #
    # WARN: Notice the "minimal match" performed here:  (.+?)
    # This is necessary as we need to plan for receiving rather large 
    # chunks of data with each entry into this method and, by default, 
    # Perl's regex parser is very "greedy". (Also, this method may be 
    # invoked multiple times for a given response before we see the 
    # $EOD marker.)
    #
    # WARN: Note the inclusion of the double CRLF as an alternate
    # match pattern for plain newlines. This is necessary because
    # CGI.pm's header() method adds these chars. Without including 
    # them in the match, we grab too much of the string as "headers".
    #
    # WARN: This method does not currently handle the case where a
    # header block exceeds one buffer full (32KB), meaning that the
    # "\n\n" (or CRLFCRLF) header terminator would not be found in
    # one single method invocation. Hopefully this isn't a problem!
    #
    ## my $substr = substr( $message, 0, 400 );
    ## warn "DEBUG: MESSAGE: $message\n";
    ## warn "DEBUG: SUBSTR: $substr\n";

    my $minimalMatch = "^(.+?)(\\n|$CRLF){2}";    # match to first double \n

    if (! $heap->{ParsedHeaders} ) {
	my($headers);
	if ( $headers = ($message =~ s/$minimalMatch//s) ) {

	    ## warn "\nDEBUG: HEADERS: $headers\n";
	    my $self = $_[ OBJECT ];

	    $self->parseHeaders( $heap, \$headers );    # pass by REF here
	}
    }
    #-------------------------------------------------------------------
    #
    ## warn "DEBUG(PARENT: MESSAGE): $message\n";

    if ($message !~ /\n?$EOD$/) {                  # watch for terminator
	$heap->{_message} .= $message;
	my $len = length( $message ) + ( $heap->{HeaderLength1} || 0 );
	$heap->{HeaderLength1} = 0;
	$Log->write(1, "SID($heap->{wid}): CMD (receive $len bytes fr Child)" );
	return;

    } else {
	$message =~ s/\n?$EOD$//;                  # strip the terminator
	chomp($message);
	my $len = length $message;

	# NOTE: the number of bytes received from the Child process
	# will be (length $EOD) bytes longer then we actually send 
	# back to the HTTP client/browser...
	#
	## $Log->write(1, "SID($heap->{wid}): CMD (receive $len bytes fr Child)" );
    }
    #-------------------------------------------------------------------
    # Once we have the complete output stream for the current response,
    # package it up and send it on to the client/browser.

    $message = (delete $heap->{_message} ||"") . $message;

    my $len = length( $message ) + ( $heap->{HeaderLength2} || 0 );

    # NOTE: the number of bytes received from the Child process
    # will be (length $EOD) bytes longer then we actually send 
    # back to the HTTP client/browser...
    #
    $Log->write(1, "SID($heap->{wid}): CMD (return $len bytes via HTTP)" );

    $heap->{entry}->incrBytesOut( $len )  if (defined $heap->{entry});

    ## $Log->write(7, "SID($wheelId) OUT: $message" );  # WAY too verbose!
    ## $Log->write(7, "DEBUG(2): heap='$heap'" );

    #-------------------------------------------------------------------
    # If we DON'T have a '$response' object here, something's wrong.
    # Just fall through here and let the '_session_stderr' and/or
    # '_session_done' handlers have a go.
    #
    my $response = delete $heap->{response};

    if ($response) {
	$response->code( 200 )  unless $heap->{HaveResponseCode};
	$response->content( $message );
	$kernel->post( 'HTTPD', 'DONE', $response );

	$heap->{errorMessages} = "";            # reset error string, if any
    }
    $heap->{ParsedHeaders}    = 0;
    $heap->{HaveResponseCode} = 0;
    $heap->{HeaderLength1}    = 0;
    $heap->{HeaderLength2}    = 0;

    return;
}

sub handle_session_stderr
{   my($heap, $kernel, $message, $wheelId) = @_[ HEAP, KERNEL, ARG0..ARG1 ];

    die "Logic Error: wheelId=$wheelId (expecting wheelId=$heap->{wid})"
   	unless $wheelId == $heap->{wid};

    $message ||="";
    chomp($message);
    $Log->write(1, "SID($wheelId) Child: $message" );

    # Here we collect any STDERR output from the child. At this
    # point, we will both write an error to the Session Daemon
    # log AND hold on on to the text. If, for some reason, the
    # child process dies, we will send the last set of errors
    # out to the client to help diagnose the problem.
    # 
    $heap->{errorMessages} .= $message;

    return;
}

sub handle_session_done
{   my($self, $heap, $kernel, $wheelId ) = @_[ OBJECT, HEAP, KERNEL, ARG0 ];

    die "Logic Error: wheelId='$wheelId' (expecting wheelId='$heap->{wid})"
   	unless $wheelId == $heap->{wid};

    # If we get here, it means the child process has terminated.
    # If we still have a '$response' object, it means that a
    # browser/client is waiting for a response. Send an error
    # message. (Send an HTTP error code, or not? Not, for now.)
    #
    my $response = delete $heap->{response} ||"";

    if ( $response ) {
	my $errors   = $heap->{errorMessages} ||"No details are available.";
	my $message  = "<http><body><p><b>Error: Session has Terminated:</b>\n";
	   $message .= "<pre>$errors<pre>\n";
	   $message .= "<hr></body></html>\n";

	$response->code( 200 );
	$response->content_type( 'text/html' );
	$response->content( $message );
	$kernel->post( 'HTTPD', 'DONE', $response );
    }

    my $pid = delete $heap->{pid};
    my $wid = delete $heap->{wid};
    my $uid = delete $heap->{uid};
    my $sessionId = delete $heap->{userSess};
    my $entry     = delete $heap->{entry};  # MUST uncache...
    my $alarmId   = delete $heap->{alarmId};

    ## warn "DEBUG ========== SESSION IS DONE  ====================\n";
    ## warn "DEBUG ========== CALL DEL TIMEOUT (2) ================\n";
    $self->delTimeout( $alarmId ) if $alarmId;

    # FIX: do not REMOVE this entry now... just flag it as done.
    $entry->state( TERMINATED $entry );

    ## warn $entry->dump();   # DEBUG

    delete $heap->{wheel};             # MUST uncache to allow POE's cleanup!
    delete $SessionHeap->{$sessionId}; # MUST uncache...

    $ActiveSessions--;
    $Log->write(1, "SID($wheelId): END (user=$uid)(pid=$pid)(active sessions: $ActiveSessions)" );

    return;
}

sub handle_session_ERROR
{   my($self, $kernel, @args) = @_[ HEAP, KERNEL, ARG0..$#_ ];

    return unless $args[1];  # no errro? no message.

    my $text;
    $text .= "OUCH: enter 'handle_session_ERROR'...\n";
 ## $text .= "=" x 45 ."\n";
    $text .= "OUCH: ERROR syscall='". ($args[0] ||"") ."'\n";
    $text .= "OUCH: ERROR   errno='". ($args[1] ||"") ."'\n"   if $args[1];
    $text .= "OUCH: ERROR   error='". ($args[2] ||"") ."'\n"   if $args[2];
    $text .= "OUCH: ERROR wheelId='". ($args[3] ||"") ."'\n";
    $text .= "OUCH: ERROR  handle='". ($args[4] ||"") ."'\n";
    $text .= "=" x 45 ."\n";

    warn $text;
    return;
}

#-----------------------------------------------------------------------
# Various text parsing and response generator methods follow.
#-----------------------------------------------------------------------

sub buildEvHeader            # create header to send to child/session/wheel 
{   my($self, $request, $runArgs ) = @_;

    my $ref = $request->referer() ||"";
    my $sec = ( $ref =~ /^https/ ? "on" : "" );

 ## my $typ1= $request->content_type()         ||"";    # WARN: CAN'T USE THIS
    my $typ = $request->header('content_type') ||"";    # WARN: MUST USE THIS!
    my $qst = $request->header('query_string') ||"";    # ????: WILL this work?
    my $le2 = $request->content_length()       ||"";    # used by CGI.pm
    my $mth = $request->method()               ||"";    # GET, POST, etc.

    # Note: $runArgs is originally created by the
    # 'Config' class, as called by the Auth class.
    #
    my $rco = $runArgs->{rawCookie}            ||"";    # raw "Cookie: ..."
    my $pth = $runArgs->{pathinfo}             ||"";    # "extra" path entries
    $qst ||= $runArgs->{querystring}           ||"";    # ????: will THIS work?

    my($ev_length,$evHeader);
    $evHeader .= "EV:CONTENT_LENGTH=$le2\n";    # length of HTTP headers/body
    $evHeader .= "EV:CONTENT_TYPE=$typ\n";      # MIME type
    $evHeader .= "EV:HTTPS=$sec\n";             # secure request via SSL?
    $evHeader .= "EV:REQUEST_METHOD=$mth\n";    # GET / POST / etc...
    $evHeader .= "EV:QUERY_STRING=$qst\n";      # now parsed by Config class
    $evHeader .= "EV:PATH_INFO=$pth\n";         # now parsed by Config class

    if ($rco) {
	$rco =~ s/^Cookie: //;
	$evHeader .= "EV:HTTP_COOKIE=$rco\n";
    }

    my $evLength = sprintf("%6.6d", length( $evHeader ) + 1 );

    $evHeader = "$evLength\n$evHeader";           # NOTE the extra byte!

    if (0) {
	warn "DEBUG(1):--------------------------------\n";
	warn $evHeader;
	warn "DEBUG(1):--------------------------------\n";
    }
    return $evHeader;
}

sub parseHeaders             # Parse headers returned from child/sess/wheel
{   my($class, $heap, $header ) = @_;    # <<-- $$header passed by REF -<<

    my(@headers) = split("\n", $$header );

    $heap->{HeaderLength1} = length( $1 ) + 2;    # add two for "\n\n"
    $heap->{HeaderLength2} = $heap->{HeaderLength1};
    $heap->{ParsedHeaders} = 1;
    ## warn "DEBUG: headers='@headers'\n";

    my($response, $headerObj);
    $response  = $heap->{response};
    $headerObj = $response->headers()  if $response;

    if ($headerObj) {
	my($key,$val);
	foreach my $header (@headers) {
	    ## warn "DEBUG: Header: $header\n";
	    
	    # Handle NPH-style header, too
	    #
	    if ($header =~ m#^(HTTP/[\S]*) (\d+) (\S+)#) {
		my $protocol     = $1;
		my $responseCode = $2;
		## $responseText = $3;

		$response->protocol( $protocol );
		$response->code( $responseCode );
		$heap->{HaveResponseCode} = 1;
		## warn "DEBUG: Header: $header\n";

	    } else {
		($key,$val) = split(": ", $header);
		if (! $key and $val) {
		    warn "WARN: Header IGNORED: $header\n";
		    next;
		}

		# Don't allow a client to reset PSD 'Session' Cookie
		# FIX: don't hard-code the cookie name here!
		#
		if ($key =~ /^Set-cookie$/i and $val =~ /^PsdSession/) {
		    warn "WARN: Header IGNORED: $header\n";
		    next;

		# Handle the alternate style 'Status:' header
		#
		} elsif ($key =~ /^Status$/i) {
		    $response->code( $val );
		    $heap->{HaveResponseCode} = 1;
		}
		$headerObj->header( $key => $val );
		## warn "DEBUG: Header: $key => $val\n";
	    }
	}
    }
    return;
}

#-----------------------------------------------------------------------
# Create and remove session timeout events
#-----------------------------------------------------------------------

# Handle child process cleanup using the typical Web server
# CGI signaling procedures. In addition, maintain an N-sec
# sesison timer used to force the cleanup process.
# .  set n-second timer as a session timeout
# .  when child exits, unset any pending timer
# .  SIGHUP child process, if it's running
# .  set 3-second timer
# .  SIGKILL child, if it's running

sub resetTimeout
{   my($self, $heap) = @_;

    my $alarmId = $heap->{alarmId} ||"";
    my $timeout = $heap->{timeout} ||"";

    $self->delTimeout( $alarmId )  if $alarmId;

    return undef unless $timeout;
    return $self->setTimeout( $timeout, $heap );   # return alarmId here!
}

sub handle_set_timeout                           # Session context hack.
{   my($self, $delay, $heap) = @_[ OBJECT, ARG0, ARG1 ];
    # Sometimes POE is a real pain in the *Q!@#$*
    # We have to set all timers in "Manager" session context :-(
    return $self->setTimeout( $delay, $heap );
}

sub setTimeout
{   my($self, $delay, $heap) = @_;

    return unless $heap;
    return unless defined $delay;
    return unless $delay =~ /^\d+$/;

    my $pid   = $heap->{pid} ||'(n/a)';
    my $event = "session_timeout";

    ##### $delay = 5  if ($delay > 5);  ## DEBUG

    # Here's yet another VERY strange POE Delay issue.
    # If we DON'T detaint $delay here, the timer will
    # trip IMMEDIATELY, and we get no warning from POE.
    # Detainting the '$SessTimeout' doesn't help :-(
    # FIX: figure this one out, and figure out why the
    # 'isTainted' method doesn't detect any problem.
    #
    # die "DEBUG: ==== setTimeout: WARNING: 'delay' IS TAINTED\n"
    #	if ( $CGIClass->isTainted( $delay ) );

    $delay = $CGIClass->untaint( $delay );

  # my $expected  = PTools::Date::Format->time2str( "%H:%M:%S", time()+$delay );
  # my $poeSessId = $poe_kernel->get_active_session()->ID();
  # warn "DEBUG: !!!! setTimeout: POE $poeSessId: delay='$delay' TO TRIP AT: $expected !!!\n";

  # $Log->write(1,"Manager(A): setDelay: call '$event'");
  # $Log->write(1,"Manager(B): setDelay: in $delay secs");
  # $Log->write(1,"Manager(C): setDelay: PID: $pid");

    $Log->write(9,"Manager: setDelay: call '$event' in $delay secs PID: $pid");

    # Set a delay for the named $event. This will cause the
    # "$heap" to get passed to that event after the delay.

    # The '$poe_kernel' variable is defined via 'use POE'.
    # The 'delay_set()' method will wait $delay secs and
    # then call the '$event' method, passing '$heap' as
    # an argument. WARN: if the timer trips *immediately*
    # you aren't going crazy. There is some problem w/POE.
    # Make sure to 'detaint' the '$delay' variable here.
    #      
    my $alarmId = $poe_kernel->delay_set( $event, $delay, $heap );
  # my $alarmId = $poe_kernel->delay_set( $event, 10, $heap );

    if (! $alarmId ) {
	my $err = "Failed to set alarm";
        warn "ERROR: error in 'setTimeout' method of '$PACK': $!\n";
	return undef;
    }

    $Log->write(9,"Manager: setDelay: set alarmId $alarmId for '$event' for PID: $pid");

    # Note: Don't cache this here... let the calling method do this!
    # (it may help with readability). Just make sure it does get
    # cached, or it will not be possible to delete the alarm later.
    #
    ## $heap->{alarmId} = $alarmId;      # cache this so we can delete it!

    return $alarmId;
}

sub handle_del_timeout                           # Session context hack.
{   my($self, $alarmId) = @_[ OBJECT, ARG0 ];
    # Sometimes POE is a real pain in the *Q!@#$*
    # We have to set all timers in "Manager" session context :-(
    return $self->delTimeout( $alarmId );
}

sub delTimeout
{   my($self, $alarmId) = @_;

    return undef unless $alarmId;

    $Log->write(9,"Manager: delTimeout: remove alarm '$alarmId'");

    # The '$poe_kernel' variable is defined via 'use POE'
    # OH MAN, does this suck. We must remove an alarm in
    # the "session context" in which it was created. :-(
    # What an ugly hack this turned out to be...
    #
    # When the 'Manager' session started we collected it's
    # POE session ID. When we get here, if we are in a
    # 'Wheel' session, we MUST use a POE event to FORCE
    # this into the Manager session context. So check the
    # session ID and, if we need to, invoke a "call" BACK
    # TO THIS SAME METHOD, but in the right session context.
    # Did I mention that this sucks?!
    #      
    my $poeSessId = $poe_kernel->get_active_session()->ID();

    if ($poeSessId == $ManagerSessId) {
	# OKAY, WE'RE IN THE 'Manager Session' context
	## warn "DEBUG: !!!! delTimeout: POE $poeSessId: for alarm='$alarmId' !!!\n";
    } else {
	# OUCH, WE'RE IN a 'Wheel Session' context
	# Reroute this request BACK TO THIS SAME METHOD, but 
	# in the 'Manager Session' context...
	## warn "DEBUG: **** del_timeout: POE $poeSessId: for alarm='$alarmId' ***\n";
	$poe_kernel->call("session_manager", "del_timeout", $alarmId);
	return;
    }
    my $alarmRef = $poe_kernel->alarm_remove( $alarmId );

    # FIX: do we need to remove the "alarmId" from the heap??
    # If so, it means keeping a map of "$alarmId" -> "$heap"
    # perhaps this is not necessary... I hope so...

    if (! $alarmRef ) {
	my $poeSessId = $poe_kernel->get_active_session()->ID();
	my $err = "No Alarm Ref returned";

	# FIX: figure out why this sometimes doesn't work!
	# After "session timeout", during "session done"
	#
	die "Manager: delTimeout: alarm '$alarmId' not found for poe_session='$poeSessId'";

	$Log->write(5,"Manager: delTimeout: alarm '$alarmId' not found for poe_session='$poeSessId'");
    }
    return $alarmRef;
}

sub handle_session_timeout
{   my($self, $heap) = @_[ OBJECT, ARG0 ];

    return undef unless (ref $heap and $heap =~ /HASH/);

    my $alarmId = $heap->{alarmId};

    ## warn "DEBUG: ==== SESSION TIMEOUT ===== alarmId='$alarmId'\n";

    $Log->write(9,"Manager: session_timeout: heap='$heap'");
    ##warn "DEBUG: Manager 'timeout': stateArgs='@{ $stateArgs }'\n";

    my $entry = $heap->{entry}   if (defined $heap->{entry});
    return undef unless ($entry);

    $Log->write(9,"Manager: session_timeout: entry='$entry'");

    # 1st TIME HERE: send a SIGHUP and set a 3-sec timer
    # 2nd TIME HERE: send a SIGKILL
    #
    my $pid = $heap->{pid};
    return undef unless ($pid);

    $Log->write(0,"Manager: session_timeout: pid='$pid'");

    if (! defined $heap->{signalSent}) {
	$self->signalChildProc( $pid, "HUP" );
	$heap->{signalSent} = "HUP";
	## warn "DEBUG ========== CALL SET TIMEOUT (2) ================\n";

	# WARN: THIS CALL MUST HAPPEN IN the "Manager" session
	# context, NOT IN THE "Wheel" sesion context! Drag :-(
	#
	$heap->{alarmId} = $self->setTimeout( 3, $heap )

    } else {
	$self->signalChildProc( $pid, "KILL" );
	$heap->{signalSent} = "KILL";
    }
    return;
}

sub signalChildProc
{   my($self, $pid, $sig) = @_;

    # FIX: Since this will be running as root, add some
    # checks here to ENSURE that we kill the right proc!!

    my $sigOkay = CORE::kill( $sig, $pid );

    if ($sigOkay) {
	$Log->write(0,"Manager: signaled child: 'SIG$sig' to PID $pid");
    } else {
	$Log->write(0,"Manager: Error: signal failed: 'SIG$sig' to PID $pid");
    }
    return;
}
#_________________________
1; # Required by require()
