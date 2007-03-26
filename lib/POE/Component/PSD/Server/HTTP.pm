# -*- Perl -*-
#
# File:  POE/Component/Server/PSD/Server.pm
# Desc:  Network HTTP/HTTPS service as front-end to Process Sessions
# Date:  Fri May 26 13:09:14 2006
# Stat:  Prototype, Experimental
#
# Desc:  Start HTTP/HTTPS daemon process and wait for user requests.
#        Validate each user and create a persistent child process
#        that runs as the user (uid/gid) and responds to requests.
#        Timeout the user sessions and terminate the child process
#        after some period of inactivity. Use 'Basic Authentication'
#        to verify the users against the local system password file.
#
# ToDo:  Handle auth when cookie deleted/not accepted  (this class)
#        add support for Web-form based user logins    (this class)
#        add support for Digital Badge cert logins     (this class)
#        add support for timeouts of user sessions     (Manager.pm)
#        add support for setuid/setgid in child proc   (Session.pm)
#        add 'daemonizer' and Debug to main module     (PSD.pm)
#
package POE::Component::PSD::Server::HTTP;
use warnings;
use strict;

our $PACK    = __PACKAGE__;
our $VERSION = '0.02';
our @ISA     = qw( );

# Uncomment the following to enable debug traces.
## sub POE::Component::Server::SimpleHTTP::DEBUG { 1 };

# Note: The "POE::Component::SSLify" class is automatically used
# if valid SSL key and cert file paths are passed by the caller.

use POE;                                   # Use POE!
use POE::Component::Server::SimpleHTTP;    # POE add-on for HTTP daemon
### POE::Component::SSLify;                # used automatically as needed

use POE::Component::PSD::Server::Auth;     # authentication / authorization
use POE::Component::PSD::Server::Log;      # simple logging module
use POE::Component::PSD::Server::Manager;  # manage user's sessions

use FileHandle;
autoflush STDOUT 1;
autoflush STDERR 1;

my $AuthClass       = "POE::Component::PSD::Server::Auth";
my $SessionClass    = "POE::Component::PSD::Server::Manager";
my $LogClass        = "POE::Component::PSD::Server::Log";

my $BaseName = ( $0 =~ m#^(?:.*/)?(.*)#);
my $Session; ##  = $SessionClass->new();    # user session manager
my $Log;     ##  = $LogClass->new();        # simple log mechanism
my $ViaSSL   = 0;
my $LdapCertFile= "";
my $Cat = "/bin/cat";

#-----------------------------------------------------------------------
# Emulate http.config, for now.
#
my $DocumentRoot;

## $ServerRoot   = "/opt/tools/ptools/pens";
## $ServerRoot   = "/nethome/cobb/source/perl/tools/psd";
## $DocumentRoot = "$ServerRoot/webdoc";
## $Cgi_Bin_Root = "$ServerRoot/webcgi";
my(@Alias) = (
  ##"/tools"    => "/opt/tools/webdoc",
    "/tools"    => "/nethome/cobb/misc/ptools/webdoc",
    "/tooltest" => "/nethome/cobb/misc/ptools/webdoc",
);
my(@ScriptAlias) = (
  ##"/cgi-bin/tools"    => "/opt/tools/webcgi",
    "/cgi-bin/tools"    => "/nethome/cobb/misc/ptools/webcgi",
    "/cgi-bin/tooltest" => "/nethome/cobb/misc/ptools/webcgi",
);
#-----------------------------------------------------------------------

sub ldapCert  { return( $LdapCertFile ) }
sub runViaSSL { return( $ViaSSL       ) }

sub spawn
{   my($class, $config) = @_;    

    $DocumentRoot = $config->globalDirective('DocumentRoot', "sansQuotes")
	or die "$BaseName: Error: No DocumentRoot found here";

    $Session  = $SessionClass->new();    # user session manager
    $Log      = $LogClass->new();        # simple log mechanism

    my $listen  = $config->globalDirective('Listen',     "sansQuotes");
    my $server  = $config->globalDirective('ServerName', "sansQuotes");
    my($hostAddr,$portNum) = $listen =~ /^([^:]+):(\d+)$/;
    my($hostName)          = $server =~ /^([^:]+):/;

    $portNum  || die "$BaseName: Error: No portnum found here";
    $hostAddr || die "$BaseName: Error: No hostaddr found here";
    $hostName || die "$BaseName: Error: No hostname found here";

    if (0) {
	warn "DEBUG:  DocRoot='$DocumentRoot'\n";
	warn "DEBUG:   listen='$listen'\n";
	warn "DEBUG:   server='$server'\n";
	warn "DEBUG: hostAddr='$hostAddr'\n";
	warn "DEBUG: hostName='$hostName'\n";
    }
    #-------------------------------------------------------------------
    # Note that '$key' and '$cert' are THIS server's certificate files
    # while '$LdapCertFile' is the used for secure LDAP lookups.
    # (LDAP authentication is not yet implemented here.)
    #
    my($key, $cert);
    my $sslEngine = $config->globalDirective('SSLEngine', "sansQuotes");
    if ($sslEngine =~ /^(1|On|True)$/i) { 
	my $root = $config->globDir( 'ServerRoot', "sans" );

	$cert = $config->globalDirective('SSLCertificateFile',   "sansQuotes");
	$key  = $config->globalDirective('SSLCertificateKeyFile',"sansQuotes");

	$cert = "$root/$cert"  unless ($cert =~ m#^/#);
	$key  = "$root/$key"   unless ($key  =~ m#^/#);
    }

    ##warn "DEBUG: attempt to read crtfile='$cert'\n";
    ##warn "DEBUG: attempt to read keyfile='$key'\n";

    if (($key and -r $key) and ($cert and -r $cert)) {
	$ViaSSL = 1;

	## # Hack, for now....
	## my($certDir)  = ( $cert =~ m#^(.*)/#);
	## $LdapCertFile = $certDir ."/some-ldap-cert.pem";

    } else {
	warn "DEBUG: can't read crtfile='$cert'\n"  if $cert;
	warn "DEBUG: can't read keyfile='$key'\n"   if $key;

	($key,$cert,$LdapCertFile) = (undef,undef,undef);
    }

    # DEBUG:  Disable SSLified daemon startup
    #($ViaSSL, $key,$cert) = (undef,undef,undef);

    my $protocol = (defined $key ? "HTTPS" : "HTTP" );
    $Log->write(0, "spawning $protocol service (port=$portNum)(pid=$$)");

 ## if ($class->runViaSSL() and ! -r $LdapCertFile) {
 ##	$Log->write(0, "warning LDAP lookups require an LDAP certificate");
 ##	$Log->write(0, "(can't read '". ($LdapCertFile||"") ."'");
 ## }
    #-------------------------------------------------------------------

    ## return if $NO_SERVER;   ## DEBUG
    warn "\n";   ## DEBUG

    # First, create a PO::Co::Server::SimpleHTTP server.
    # If the '$key' value is
    #
    POE::Component::Server::SimpleHTTP->new
    (
        'ALIAS'    => 'HTTPD',
        'ADDRESS'  => $hostAddr,
        'PORT'     => $portNum,
        'HOSTNAME' => $hostName,
        'HEADERS'  => {},          # default 'response' header
        'HANDLERS' => [
            { 'DIR'     => '^/session/$',
              'SESSION' => 'HTTP_INPUT',
              'EVENT'   => 'GOT_MAIN',
            },
            { 'DIR'     => '/session.*',
              'SESSION' => 'HTTP_INPUT',
              'EVENT'   => 'GOT_Session_Input',
            },
          # },
          # { 'DIR'     => '/request.*',
          #   'SESSION' => 'HTTP_INPUT',
          #   'EVENT'   => 'GOT_PROTECTED',
          # },
          # { 'DIR'     => '^/foo/.*',
          #   'SESSION' => 'HTTP_INPUT',
          #   'EVENT'   => 'GOT_NULL',
          # },
            { 'DIR'     => '^(/|/index.html?|/favicon.ico)$',
              'SESSION' => 'HTTP_INPUT',
              'EVENT'   => 'GOT_MAIN',
            },
            { 'DIR'     => '(\.js)$',
              'SESSION' => 'HTTP_INPUT',
              'EVENT'   => 'GOT_MAIN',
            },
            { 'DIR'     => '.*',
              'SESSION' => 'HTTP_INPUT',
              'EVENT'   => 'GOT_ERROR',
            },
        ],

	## So very simple to get SSL working here: just pass a
	## readable key_file and cert_file path to this method.
	##
        #'SSLKEYCERT'  => [ 'public-key.pem', 'public-cert.pem' ],
         'SSLKEYCERT'  => [ $key, $cert ],

    ) or die 'Unable to create the HTTP Server';

    # Next, create an 'HTTP_INPUT' session that will receive events from 
    # the PO::Co::Server::SimpleHTTP server that we just created.
    #
    POE::Session->create
    (
        package_states => [
	   $PACK => {
	       '_start'       => "start_http_handler",
	       'GOT_MAIN'     => "GOT_REQ",
	       'GOT_ERROR'    => "GOT_ERR",
	       'GOT_NULL'     => "GOT_NULL",
	       'GOT_HANDLERS' => "GOT_HANDLERS",
	       'GOT_PROTECTED'=> "Need_Basic_Auth",
              'GOT_PROT_Unix' => "Need_Basic_Auth",
              'GOT_PROT_Ldap' => "Need_Basic_Auth",
          'GOT_Session_Input' => "Need_Basic_Auth",
          'GOT_PROT_Htaccess' => "Need_Basic_Auth",
	   },
        ],
    );

    return;
}

sub start_http_handler        # HTTP_INPUT session for current HANDLER list
{ 
    ###warn "DEBUG: starting HTTP session (alias 'HTTP_INPUT')";

    $_[KERNEL]->alias_set( 'HTTP_INPUT' );
    $_[KERNEL]->post( 'HTTPD', 'GETHANDLERS', $_[SESSION], 'GOT_HANDLERS' );
}

sub GOT_HANDLERS 
{   my $handlers = $_[ ARG0 ];
    # ARG0 = HANDLERS array

    # Move the first handler to the last one
    # (This was in orig code... WHY????!)
    ### push( @$handlers, shift( @$handlers ) );

    # Send it off!
    $_[KERNEL]->post( 'HTTPD', 'SETHANDLERS', $handlers );
}

sub GOT_NULL
{   my($class, $request, $response, $dirmatch ) = @_[ OBJECT, ARG0 .. ARG2 ];
    # ARG0 = HTTP::Request object,
    # ARG1 = HTTP::Response object,
    # ARG2 = the DIR that matched

    ###warn "DEBUG: GOT_NULL: dirmatch='$dirmatch'\n";
    # Send a null response!
    $_[KERNEL]->post( 'HTTPD', 'CLOSE', $response );
}

sub GOT_REQ
{   my($class, $request, $response, $dirmatch ) = @_[ OBJECT, ARG0 .. ARG2 ];
    # ARG0 = HTTP::Request object,
    # ARG1 = HTTP::Response object,
    # ARG2 = the DIR that matched

    # Do our stuff to HTTP::Response
    $response->code( 200 );
  # $response->content_type( 'text/html' );

    my $requestPath = $request->uri->path();
    $Log->write(1, "GOT_REQ(0): $requestPath");

    if (0) {
	my $reqUri     = $request->uri();
	my $reqRequest = $request->as_string();
	my $reqContent = $request->content();
	my $reqHeaders = $request->headers_as_string();
	$reqHeaders =~ s/^(Cookie: [^\$]*)$//mg;

	warn "DE(1): REQ Request='$reqRequest'\n";
	#warn "DEBUG: REQ Uri    ='$reqUri'\n";
	#warn "DEBUG: REQ Content='$reqContent'\n";
	#warn "DEBUG: REQ Headers='$reqHeaders'\n";
    }

  # if ( $requestPath =~ m#^(/session/)*$# ) {
    if ( $requestPath =~ m#^(/|/index.html?|/session/)\s*$# ) {
	$Log->write(1, "GOT_REQ(1): look for $DocumentRoot/index.html");
	if (-r "$DocumentRoot/index.html") {
	    my $content = `$Cat "$DocumentRoot/index.html"`;
	    chomp($content);
	    $response->content( $content );
	} else {
	    $response->code( 404 );
	    $response->content( "<h2>File Not Found</h2>" );
	    $Log->write(1, "GOT_REQ: NOT: $DocumentRoot/index.html");
	}

    } elsif ($requestPath =~ m#/favicon.ico#) {
	$Log->write(1, "GOT_REQ(2): look for $DocumentRoot/favicon.ico");
	if (-r "$DocumentRoot/favicon.ico") {
	    my $content = `$Cat "$DocumentRoot/favicon.ico"`;
	    chomp($content);
	    $response->content_type( 'image/x-icon' );
	    $response->content( $content );
	} else {
	    $response->code( 404 );
	    $response->content( "<h2>File Not Found</h2>" );
	    $Log->write(1, "GOT_REQ: NOT: $DocumentRoot/favicon.ico");
	}

  # } elsif ($requestPath =~ m#/([^\.]*)\.js$#) {

    } elsif ($requestPath =~ m#^(?:.+/)?(.+)\.js$#) { 
	my $lookupPath = "$DocumentRoot/js/${1}.js";
	$Log->write(1, "GOT_REQ(2): look for $lookupPath");
	if (-r "$lookupPath") {
	    my $content = `$Cat "$lookupPath"`;
	    chomp($content);
	    # WIP:
	    $response->content_type( 'text/javascript' );
	    $response->content( $content );
	} else {
	    $response->code( 404 );
	    $response->content( "<h2>File Not Found</h2>" );
	}

    } else {
	$Log->write(1, "GOT_REQ(Err): uri: $requestPath");
	$response->content( "Got_Req: funky request: path='$requestPath'" );
    }

    ###warn "DEBUG: GOT_REQ: dirmatch='$dirmatch'\n";
    # We are done!
    # For speed, you could use $_[KERNEL]->call( ... )
    $_[KERNEL]->post( 'HTTPD', 'DONE', $response );
}

sub GOT_ERR
{   my($class, $request, $response, $dirmatch ) = @_[ OBJECT, ARG0 .. ARG2 ];
    # ARG0 = HTTP::Request object,
    # ARG1 = HTTP::Response object,
    # ARG2 = the DIR that matched

    # Check for errors
    if ( ! defined $request ) {
        $_[KERNEL]->post( 'HTTPD', 'DONE', $response );
        return;
    }
    my $requestPath = $request->uri->path();
    $Log->write(1, "GOT_ERR: $requestPath");

 ## warn "DEBUG: GOT_ERR: dirmatch='$dirmatch'\n";

    # Do our stuff to HTTP::Response
    $response->code( 404 );
    $response->content(
	"<h2>Not Available</h2>" . 
	"The requested URL '" . 
	$request->uri->path() . 
	"' is not available from this server." .
	"<hr>\n"
    );

    # We are done!
    $_[KERNEL]->post( 'HTTPD', 'DONE', $response );
}

sub Need_Basic_Auth 
{   my($class, $kernel, $state, $request, $response, $dirmatch ) =
    @_[ OBJECT, KERNEL,  STATE,  ARG0,     ARG1,      ARG2 ];

    return $AuthClass->authenticate(
	$kernel, $state, $request, $response, $dirmatch 
    );
}
#_________________________
1; # Required by require()
