# -*- Perl -*-
#
# File:  POE/Component/PSD/Server/Auth.pm
# Desc:  Generic login facility
# Date:  Sat Jun 10 21:16:15 2006
# Stat:  Prototype, Experimental
#
# Abstract:
#        Processing includes:
#        .  Generate a login form for Persistent Session Daemon 
#        .  Validate userid/password using a Unix-style login
#
#        Unix login is just a uname and password pair, while an
#        LDAP Directory check might use something like the:
#        .  Email Address and password on an LDAP server
#        .  Employee number or other type of identification data
#
# Note:  To switch from SSL to "vanilla" connection
#        .  change proxy config in httpd.conf (no longer necessary!)
#        .  ensure that daemon starts as SSL/non-ssl in Server.pm
#        .  ensure URLs in 'session' scripts are all relative
#        .  make SURE to disallow using passwords w/o SSL!!
#           (create 'anonymous' user sessions in this case!)
#

package POE::Component::PSD::Server::Auth;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.03';
#our @ISA    = qw( );

use POE::Component::PSD::Server::Config;    # config file parser
use POE::Component::PSD::Server::Log;       # simple logging module
use POE::Component::PSD::Server::Manager;   # manage user's sessions
use POE::Component::PSD::Server::HTTP;      # server class

use PTools::Passwd;                         # user password validation
use Digest::MD5;                            # create checksums
use Time::HiRes;                            # helpful for crypto stuff
use Socket;                                 # defines 'AF_INET' const

my $DefaultRealm    = "demo",               # "psudo" Web-access realm
my $LogClass        = "POE::Component::PSD::Server::Log";
my $SessionMgrClass = "POE::Component::PSD::Server::Manager";
my $ServerClass     = "POE::Component::PSD::Server::HTTP";
my $AuthLdapClass   = "";        # not used here

my $Log;            # simple log mechanism
my $SessionMgr;     # "user process" session mgr
my $Config;         # Config object
my $HostName;       # Either config file 'ServerName' or `hostname`

#-----------------------------------------------------------------------
# FIX: move the following to the 'Manager' class.

#my $UserMap    = {};              # map uname to TOKEN value via 'realm'
#my $SessionMap = {};              # map TOKEN to sessionId via 'realm'

#-----------------------------------------------------------------------

my $DefaultFormTitle  = "User Session";
my $DefaultFormAction = "/session/demo";
my $ActionCancel      = "/session/";

sub new
{   my($class, $config, @args) = @_;
    return $class unless ref $config;
    $Config = $config;

    # Must do this here,  not above. Wait until
    # the "$SessionMgrClass" has been initialized
    # in the PSD class. Setting these when this
    # class is 'used' is too soon. 
    #
    $Log        = $LogClass->new();         # simple log mechanism
    $SessionMgr = $SessionMgrClass->new();  # "user process" session mgr

    $HostName = $config->globalDirective('ServerName', "sansQuotes");
    if (! $HostName) {
	$HostName = `/usr/bin/hostname`;
	chomp($HostName);
    }
    return $class;
}

sub authenticateLogin
{   my($class, $login, $pass, $realm) = @_;

    # Here we will translate the 'login' received via the PSD
    # login Web form into a Unix-style 'unmae', AND validate
    # that the user is indeed who s/he says. The resulting 
    # 'uname' will be a Unix user name:
    # . for Unix-style logins, $login and $uname will be the same
    # . for LDAP-style logins they may be different
    #
    # If the "verify()" method here returns a uname here,
    # then we can TRUST that $login and $pass are OKAY!
    # . for Unix-style logins: the cleartext password here
    #     was compared with a passwd file (or NIS map) entry
    # . for LDAP-style logins:
    #   ======== TBD, but something like this =======
    #   -  an anonymous (Non-SSL) LDAP bind operation is done
    #   -  some user attributes are collected, including the
    #        user's primary "uid" attribute and their empnum
    #   -  a secure (SSL) LDAP bind operation is done
    #        using the user's LDAP "uid" and the cleartext
    #        password here that the user provided via the Web 
    #        form (this MUST be via an SSL connection to the
    #        Web server to prevent eavesdropping the passwd).
    #   -  if the secure bind fails, the login is NOT valid
    #   -  if the login IS valid, for example...
    #      -  the user's empnum was collected from LDAP server
    #      -  the empnum is converted into a login ID (somehow)
    #      -  a check is done (somehow) to ensure that this
    #            user's account was still "active"
    #   =============================================
    #
    # This will AUTHENTICATE the user (but not AUTHORIZE them --
    # tests are still run to check the PSD server's config file).
    #
    my($uname,$error);

 ## if ($AuthLdapClass) {
 ##	($uname,$error) = $AuthLdapClass->authLogin( $login, $pass );
 ## } else {
	($uname,$error) = ($login, "" );
 ## }
    $Log->write(0, "authUser: login='$login' uname='$uname' err='$error'\n");

    return( $uname );
}

#-----------------------------------------------------------------------
# MAIN LOGIC for this Auth class
#-----------------------------------------------------------------------

sub authenticate
{   my($class, $kernel, $state, $request, $response, $dirmatch ) = @_;

    #-------------------------------------------------------------------
    # Start by collecting the 'realm' from the URI string
    #
    my $uri    = $request->uri()->as_string();
    my($realm) = $uri =~ m#(/session/[^?/\$]*)#;
    $realm ||= "";

    my( $sessionToken, $sessionId, $sessionUser, $rawCookie);

    foreach my $line (split("\n", $request->headers()->as_string())) {
   	next unless ($line =~ /^Cookie: (.*)$/);
   	if ($line =~ /Cookie: PsdSession=([^;]*)/) {
   	    $sessionToken = $1;
	    $rawCookie = $line;
   	}
    }
    $sessionToken ||= "";

    #-------------------------------------------------------------------
    # Debug stuff
  # warn "DEBUG: SESSIONS: ----------------------\n";
  # warn $SessionMgrClass->listSessions();
  # warn "DEBUG: END of SESSIONS. ---------------\n";
    #-------------------------------------------------------------------


    #-------------------------------------------------------------------
    # ALL 'Protected Requests' come through here... 
    # Decide what to do for this user's 'mouseclick':
    #
    # FIX: handle case of user deleting cookie (or browser
    # set to not accept cookies, etc).
    #
    #-------------------------------------------------------------------
    # If ANY credentials are missing (login OR sessionToken), then
    # we will force a login popup dialog box in the browser here.
    # If no "SessionToken" was passed, create a temporary token so
    # we will ensure that sufficient credentials are returned after
    # the user enters their user/pass in the browser's dialog box.
    #
    # Note: may not always have a login here, so allow for this.
    # May have '$sessionToken' w/o active session
    # May have password w/o $sessionToken
    #
    my $reqContent = $request->content();
    my($login)    = ( $reqContent =~ /user=([^\&]*)/ );
    my($password) = ( $reqContent =~ /pass=([^\&]*)/ );
    my($button)   = ( $reqContent =~ /[Bb]utton=([^\&]*)/ );


    #### ($login,$password) = ("cobb","DEBUG");   # DEBUG!!! REMOVE THIS


    my $runArgs = 
	$Config->translateByRule( $request, $response, $realm, $login );

    if ( $sessionToken ) {

	my $sessEntry = $SessionMgr->getEntry4Realm( $realm, $sessionToken );
	my $sessionId = ( $sessEntry ? $sessEntry->sessionId() ||"" : "" );
	my $uname     = ( $sessEntry ? $sessEntry->uname()     ||"" : "" );

	if ( ! $sessEntry and ($login and $password) ) {

	    $class->attemptLogin( 
		$realm, $login, $password, $sessionId, $request, $response,
		$rawCookie, $kernel, $sessionToken, $runArgs,
	    );

	} elsif (! $sessEntry ) {
	    $Log->write(1, "NEED_AUTH (with TOKEN) realm='$realm'");

	    $response->code( 200 );
	    $response->content( $class->form( undef, $realm ) );
	    $kernel->post( 'HTTPD', 'DONE', $response );
	    
	} elsif ( $sessEntry->isActive() ) {

	    $Log->write(5, "HAVE_AUTH (user=$uname)");

	    ##my $string = $request->as_string();
	    ##warn "DEBUG: REQUEST='$string'";

	    # Forward request on to .... <wherever>
	    #
	    ### my(@runArgs) = ( $uname, $sessionId, $request, $response );

	    $runArgs->{uname}     = $uname;
	    $runArgs->{token}     = $sessionToken;
	    $runArgs->{sessionId} = $sessionId;
	    $runArgs->{request}   = $request;
	    $runArgs->{response}  = $response;
	    $runArgs->{rawCookie} = $rawCookie;

	    $kernel->post('SESSION', 'RUN', $runArgs );
	    return;

	} else {
	    my $sessionState = $sessEntry->stateName();

	    $Log->write(5, "$sessionState (user=$uname realm=$realm sesId=$sessionId)");
	    my $secure = $ServerClass->runViaSSL ? "secure" : "";
	    my $cookie = "PsdSession=; path=$realm; $secure";

	    ## Cancel the sessionToken (Browser Cookie) here.

	    $response->code( 200 );
   	    $response->headers()->header( "Set-Cookie" => "$cookie" );
	    $response->content( $class->form( $uname, $realm ) );

	    $kernel->post( 'HTTPD', 'DONE', $response );
	}

    } elsif ( ! $sessionToken ) {

	if ( $login and $password ) {

	    $class->attemptLogin(
		$realm, $login, $password, $sessionId, $request, $response,
		$rawCookie, $kernel, $sessionToken, $runArgs,
	    );

	} else {
	    $Log->write(1, "NEED_AUTH (w/o TOKEN) realm='$realm'");

	    $response->code( 200 );
	    $response->content( $class->form( undef, $realm ) );
	    $kernel->post( 'HTTPD', 'DONE', $response );
	}

    }
    #-------------------------------------------------------------------
    # And weeee'rrrreee outta here!

    return;
}

sub attemptLogin
{   my($class, $realm, $login, $password, $sessionId, $request, $response,
	$rawCookie, $kernel, $sessionToken, $runArgs, ) = @_;

    $Log->write(5, "VERIFY_USER (login='$login' realm='$realm')");

    # TRANSLATE $login TO $uname
    # Note that the resulting '$uname' MAY BE DIFFERENT
    # here than the passed '$login' name. This will be 
    # the same for Unix-style logins. It may be different 
    # when using LDAP-style logins as this type of login 
    # may get translated during the authentication phase.
    # Also, "URL decode" (unescape) these entries as they
    # may contain "URL encoded" characters ( %20, etc...)
    # 
    $login    = $class->unescape( $login );
    $password = $class->unescape( $password );

    my $uname = $class->authenticateLogin( $login, $password, $realm );
    #### my $uname = "cobb";                  # DEBUG!!! REMOVE THIS TOO

    if ( $uname ) {

	$Log->write(5, "VERIFY_USER (OKAY for '$uname')");

	($sessionToken, $sessionId) = $class->createTokens(
	    $realm, $request, $response, $uname, $password
	);

	$runArgs->{uname}     = $uname;
	$runArgs->{token}     = $sessionToken;
	$runArgs->{sessionId} = $sessionId;
	$runArgs->{request}   = $request;
	$runArgs->{response}  = $response;
	$runArgs->{rawCookie} = $rawCookie;

	$kernel->post('SESSION', 'RUN', $runArgs );

	$Log->write(5, "START_UP! (user=$uname sess=$sessionId)");
	return;

    } else {
	$Log->write(1, "VERIFY_USER (FAILED for '$login')");

	my $err = "Error: Login failed";
	$response->code( 200 );
	$response->content( $class->form( $login, $realm, $err ) );

	$kernel->post( 'HTTPD', 'DONE', $response );
	return;
    }
}

#-----------------------------------------------------------------------

sub createTokens
{   my($class, $realm, $request, $response, $uname, $password ) = @_;

    # After authentication, create some tokens
    # . a Session Cookie - sent back to the Web client 
    # . a sessionId      - used to map Cookie to session
    #
    # Currently the Session Cookie is "realm-specific"
    # but this may not be the optimal solution. Should
    # there be ONLY ONE cookie which is then mapped
    # to a "realm / sessionId" pair? Time will tell.
    #
    $Log->write(5, "AUTH_USER (uname=$uname realm='$realm')");
    my $sessionToken = $class->createToken( $uname );

    my $path   = $realm;
    my $secure = $ServerClass->runViaSSL ? "secure" : "";
    my $cookie = "PsdSession=$sessionToken; path=$path; $secure";
    my $sessionId = $class->createToken( $uname );

    $response->code( 200 );
    $response->headers()->header( "Set-Cookie" => "$cookie" );

    $Log->write(5, "AUTH_OKAY (uname=$uname  realm='$realm')");
    $Log->write(5, "AUTH_OKAY (sessionToken=$sessionToken path='$path')");

    return( $sessionToken, $sessionId );
}

sub createToken
{   my($class, $uname) = @_;

    my($secs,$msecs) = Time::HiRes::gettimeofday();
    my $psudoRandom  = $class->createNoise();
    my $ctx          = Digest::MD5->new();
    my $moreNoise    = "";   ###  $class->createNoise( 64 );   # FIX: uncomment

    $ctx->add( "$HostName:$secs:$msecs:$uname:$psudoRandom" );

    # The following return equivalent values in various formats.
    # Note that an "MD5 Summary" is equivalent to a checksum as
    # there is nothing that can be decrypted here.
    # .  hexidecimal digest      (32 chars)
    # .  base-64 encoded digest  (22 chars)
    # .  binary digest           (16 bytes)
    #
    return $ctx->hexdigest() . $moreNoise;    # 32 digest + 64 noise
  # return $ctx->b64digest() . $moreNoise;    # 22 digest + 64 noise;
  # return $ctx->digest()    . $moreNoise;    # 16 digest + 64 noise;
}

my(@AsciiChars);                     # printable ascii characters

sub createNoise
{   my($class, $len) = @_;

    # Generate psudo-random noise to help make MD5 summary unique.
    #
    $len ||= 120;
    my($noise);

    # Initialize list of chars the 1st time through
    if (!@AsciiChars) { foreach (32 .. 126) { push @AsciiChars, chr($_); } }
    
    # generate a "random" string
    foreach (1 .. $len) { $noise .= $AsciiChars[rand @AsciiChars]; }

    return $noise;
}

sub denyAccess_NOT_IN_USE             # force login popup in browser
{   my($class, $realm, $response, $dirmatch, $resetCookie) = @_;

    # Set the authorization parameters and error message.
    # Reset the Cookie if session has timed-out.
    #
  # my $string = "Private_Pages_${realm}_Login";
  # my $string = "Private%20Pages:%20${realm}%20Login";
    my $string = "Private Pages: ${realm} Login";

    $Log->write(1, "DENY_ACCESS: Realm='$string' ");

    $response->code( 401 );
    $response->header( 'WWW-Authenticate' => "Basic realm=\"$string\"" );
    $response->content( 
	"<h2> Authorization Required </h2>" .
	"This server could not verify that you are authorized to "   .
	"access the document requested. Either you supplied the "    .
	"wrong credentials (e.g., bad password), or your browser "   .
	"doesn't understand how to supply the credentials required." .
	"\n<hr>\n"
    );

  # warn "DEBUG: response='$response'\n";
  # warn "DEBUG: header='", $response->headers()->as_string(), "'\n";
    return;
}

#-----------------------------------------------------------------------
# unencode URL-encoded data          (copied shamelessly from L.Stein's CGI.pm)
#
sub unescape {
    my($self,$todecode) = @_;
    $todecode =~ tr/+/ /;                                   # plusses to spaces
    $todecode =~ s/%([0-9a-fA-F]{2})/pack("c",hex($1))/ge;
    return $todecode;
}

# URL-encode data                    (copied shamelessly from L.Stein's CGI.pm)
sub escape {
    my($self,$toencode) = @_;
    $toencode=~s/([^a-zA-Z0-9_\-.])/uc sprintf("%%%02x",ord($1))/eg;
    return $toencode;
}


#-----------------------------------------------------------------------

*form = \&genForm;

sub genForm
{   my($class, $user, $realm, $notice, @args) = @_;

    $user   ||= "";
    $realm  ||= "demo";
    $notice ||= "";

    ## warn "DEBUG: user='$user' realm='$realm'  in '$PACK'\n";

    # The rest of these can be passed in "@args", but it would
    # be simpler for callers if the above hash refs were just 
    # updated to include a lookup based on an arbitrary "realm". 
    # (This is a psudo Web access realm, not necessarialy from 
    # an actual ".htaccess" file.)
    #
    my $cancel   = $ActionCancel;

    my $title2   = $args[1];
       $title2 ||= $Config->locationDirective($realm, 'AuthName', "sansQuotes");
       $title2 ||= $DefaultFormTitle;

    my $action   = $args[2];
       $action ||= $realm;                  # "/session/<something>"
       $action ||= $DefaultFormAction;

    my $title1   = $args[3] || "Session Login";

    my $focus;   # define initial field 'focus' depending on user field
    $user and ($focus = 'pass');
    $user  or ($focus = 'user');

    #<!-- ---------------------------------------------------- -->
    #<!-- Variable elements              Variable name         -->
    #<!-- . form title                   - title1              -->
    #<!-- . focus field                  - focus               -->
    #<!--   - user  (when form empty)                          -->
    #<!--   - pass  (when user known)                          -->
    #<!-- . form post action             - action              -->
    #<!-- . login realm description      - title2              -->
    #<!-- . error / note text  (if any)  - notice              -->
    #<!--   - 'Error: Login failed'                            -->
    #<!--   - 'Session timed out'                              -->
    #<!-- . user name (when known)       - user                -->
    #<!-- . login realm (hidden field)   - realm               -->
    #<!-- . cancel uri  (hidden field)   - cancel              -->
    #<!-- ---------------------------------------------------- -->

    return <<"    __EndOfForm";
<html>
<head>
<title> $title1 </title>
</head>
<body onload='document.forms[0].${focus}.focus();'>
    <font face='Arial'>
    <ul> <ul>
    <p><br>
    <form method='POST' action='$action'>

    <table width='400' cellpadding='0' cellspacing='0' border='2'>
    <tr><td>

	<table width='100%' bgcolor='#e9e9e9' cellpadding='5' 
		 cellspacing='0' border='0'>
	<tr>
	    <td></td>
	    <td align='left'> 
		<font face='Arial' size='-1'>
		<b>$title1</b> 

		<br>$title2
		</font>

		<br> <font color='red' size='-1'>
		<b>$notice</b>
		<font>

	    </td>
	<tr>
	<tr>
	    <td align='right'>
		<font face='Arial' size='-1'>
		<b>User&nbsp;Name:</b>
		</font>
	    </td>
	    <td align='left'> 
		<input type='field' name='user' value='$user'>
	    </td>
	<tr>
	</tr>
	    <td align='right'>
		<font face='Arial' size='-1'>
		<b>Password:</b> 
		</font>
	    </td>
	    <td align='left'> <input type='password' name='pass'> </td>
	</tr>
	<tr>
	    <td></td>
	    <td align='left'>
		<font face='Arial' size='-1'>
		<input type='submit' name='button' value='Login'>
		&nbsp;&nbsp;&nbsp;
		<a href='$cancel'>Cancel</a>
		</font>
		<input type='hidden' name='realm'  value='$realm'>
	    </td>
	</tr>
	</table>

    </td></tr>
    </table>

    </form>
    </ul> </ul>
    </font>
</body>
</html>
    __EndOfForm
}
#_________________________
1; # Required by require()

