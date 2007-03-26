# -*- Perl -*-
#
# File:  POE/Component/PSD/Server/Config.pm
# Desc:  Patch Tools User Command Daemon config file parser
# Date:  Tue Jul 18 21:41:01 2006
#
package POE::Component::PSD::Server::Config;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.01';
our @ISA     = qw( Apache::Admin::Config );

use Apache::Admin::Config;         # include parent class
use Socket;                        # defines 'AF_INET'

my $Location = {};                 # <Location> sections
my $Alias    = {};                 # Alias directives
my $ScriptAlias  = {};             # ScriptAlias directives
my $PostLoadDone = 0;
my $Debug = 0;

sub alias       { $Alias->{ $_[1] }       }
sub scriptAlias { $ScriptAlias->{ $_[1] } }
sub location    { $Location->{ $_[1] }    }
sub configFile  { $_[0]->{tree}->{htaccess} ||"" }  # Hack, yuck! Fix parent!!

sub postLoadProcess
{   my($self) = @_;

    #-------------------------------------------------------------------
    # Pre-parse some info from the current config settings
    # Note the following behavior of the parent class:
    # .  directives and sections are parsed into "tree nodes"
    # .  the "node" objects are overloaded so can be accessed
    #      using OO syntax or just in a 'print' statement
    #      (which means you can't just 'print' the object
    #      to find out it's class name or memory address)
    #
    # FIX: add support for <VirtualHost> sections in config file

  # $Debug and warn "-" x 72 ."\n";
  # $Debug and warn "Parse config directives:\n";

    my $aliasMatch = "\"?([^\"\\s]*)\"?\\s+\"?([^\"\\s]*)\"";

    foreach my $directive ( $self->directive() ) {
	# Here is an example of using a '$directive'
	# node as both an object and a string value:
	#
        my $name = $directive->name() ||"";                 # as object
	next unless ( $name =~ /^(Alias|ScriptAlias)$/ );
	my($source,$target) = $directive =~ /$aliasMatch/;  # as string

	if (0) {
	    warn "  ". $name  ."\t  $directive\n";
	    warn "  $name\t  src='$source' trg='$target'\n";
	}

	if ($name =~ /^(Alias)$/) {
	    $Alias->{ $source } = $target;
	} else {
	    $ScriptAlias->{ $source } = $target;
	}
    }

  # $Debug and warn "-" x 72 ."\n";
  # $Debug and warn "Parse config <Location> sections:\n";

    foreach my $loc ( $self->section(-name => 'Location') ) {
	# Here we cache the entire sub-tree node for 
	# easy access later on.
	#
      # $Debug and warn "       Location: $loc\n";
	$Location->{ $loc } = $loc;

      # my $sethandler = $loc->directive('sethandler') ||"";
      # if ($sethandler) {
      #     print "  SetHandler(1): ". $sethandler->value() ."\n";
      #
      #     $sethandler = $loc->directive('sethandler') ||"";
      #     print "  SetHandler(2): $sethandler \n";
      # }

        ## warn $loc->dump_raw();
    }

    $PostLoadDone = 1;
    return;
}

# Work-around for broken error handling in parent class.
sub error { $Apache::Admin::Config::ERROR }

# Provide easy access to a global directives
#
*globDir = \&globalDirective;

sub globalDirective
{   my($self, $directive, $sansQuotes) = @_;
    return undef unless ($directive);
    $directive = $self->directive( $directive );
    $directive =~ s/"//g  if ($directive and $sansQuotes);   # strip quotes?
    return $directive;
}

# Provide easy access to <Location> sections and the
# directives contained therein.
#
*locDir = \&locationDirective;

sub locationDirective
{   my($self, $location, $directive, $sansQuotes) = @_;
    return undef unless ($location and defined $Location->{$location});

    # If we have no 'directive' argument return
    # the tree node object containing <Location /whatever>
    #
    return $Location->{$directive} unless $directive;

    # Otherwise, just return the requested directive
    # (and strip any quotation marks, if requested)
    #
    $directive = $Location->{$location}->directive( $directive );
    $directive =~ s/"//g  if ($directive and $sansQuotes);   # strip quotes?
    return $directive;
}

sub translateByRule
{   my($self,$request,$response,$realm,$login) = @_;
    
    # Each and every server request gets parsed in this method.
    # Here we do some authentication and some translation on
    # the requested URI, based on configuration rules. The
    # return value will be <nul> when not authorized, or a
    # hashRef with the following components from the URI.
    # .  a fully-qualified path to a script
    # .  a 'query string' value, if any
    # .  a 'path info' value, if any
    # These wlll then get passed to the Session Manager.
    #
    # A login will NOT necessarialy be available in the request.
    # If we have one, validate it as appropriate, if not, skip it.
    #
    # FIX: Or... wait until we have a login to validate? If not,
    # then we need a secondary, quick, validation for logins.
    # Either way is okay. The allow/deny stuff will be a bit
    # tricky to code so it's in a separate method.
    #
    # Also FIX: if we have a cookie for an active process, can 
    # we be less rigorous with security checks here?
    #
    $login ||= "";

    #-------------------------------------------------------------------
    # Make sure that the postLoad processing was run. For some
    # reason the parent class does not work well when a 'new()'
    # method is added here (gives errors on 'destroy'). Sigh.
    #
    $PostLoadDone or $self->postLoadProcess();

    #-------------------------------------------------------------------
    # Collect some info from the current request/response objects
    #
    my $remoteIp    = $response->connection()->remote_ip();
    my $remoteAddr  = $response->connection()->remote_addr();
    my $remoteHost  = gethostbyaddr( $remoteAddr, AF_INET );
    my $method      = $request->method();
    my $uri         = $request->uri()->as_string();
    my $scriptAlias = $ScriptAlias->{ $realm } ||"";

    if (0) {
	warn "-" x 72 ."\n";
	warn "DEBUG:        realm='$realm'\n";
	warn "DEBUG:        login='$login'\n";
	warn "DEBUG:    remote ip='$remoteIp'\n";
	warn "DEBUG:  remote host='$remoteHost'\n";
	warn "DEBUG:  request uri='$uri'\n";
	warn "DEBUG:  http method='$method'\n";
	warn "DEBUG: script alias='$scriptAlias'\n";
    }
    #-------------------------------------------------------------------
    # Compare the current request with any pertinent config rules
    # The '$loc' var here is a parsed "<Location>" section contained
    # packaged as a 'tree node', and cached by the associated 'realm' 
    # in the 'postLoadProcess()' method. Ensure that 'postLoadProcess()'
    # method is called after the 'new()' method, and before any lookups.

    my $loc = $Location->{ $realm };
    return undef unless $loc;             # Error: unknown location/realm

    ## warn "DEBUG: ". $loc->dump_raw()   if $loc;

    my $authName = $self->locationDirective( $realm, 'AuthName', "sans" );
    my $authOrder= $self->locationDirective( $realm, 'Order',    "sans" );
    $authOrder ||= $self->locationDirective( "/",    'Order',    "sans" );

    $Debug and warn "DEBUG:     AuthName='$authName'\n";
    $Debug and warn "DEBUG:    AuthOrder='$authOrder'\n";

    return undef unless $self->methodIsAllowed( $realm, $method, $authOrder );
    return undef unless $self->loginIsAllowed ( $realm, $login,  $authOrder );

    # Create a uri with both pathinfo and querystring
    # $uri = $uri ."/foo/bar/xyzzy?abc=def";   # DEBUG:

    # Here we are a bit bogus with regard to the PATH_INFO
    # part. We are not actually looking through directory
    # paths for an executable but are relying entirely on
    # the ScriptAlias directive in the conf file to identify
    # the actual script "leaf filename".
    #
    my($pathInfo,$queryString) = $uri =~ /$realm([^?]+)?(\?.+)?/;
    $pathInfo    ||= "";
    $queryString ||= "";
    $queryString =~ s/^[?]//  if $queryString;

    my $serverRoot = $self->globDir( 'ServerRoot', "sans" );
    my $scriptPath = ( 
	( $scriptAlias =~ m#^/# )
        ? $scriptAlias
	: "$serverRoot/$scriptAlias"
    );

    $Debug and warn "DEBUG:         URI ='$uri'\n";
    $Debug and warn "DEBUG: SCRIPT ALIAS='$scriptAlias'\n";
    $Debug and warn "DEBUG: SCRIPT PATH ='$scriptPath'\n";
    $Debug and warn "DEBUG:    PATH_INFO='$pathInfo'\n";
    $Debug and warn "DEBUG: QUERY_STRING='$queryString'\n";

    return({ 
	      realm => $realm,
	      login => $login,
	 scriptpath => $scriptPath,
	querystring => $queryString,
	   pathinfo => $pathInfo,
    });
}

#-----------------------------------------------------------------------
# Notes regarding the "Allow" and "Deny" directives. For details see
# http://apache.org/apache/mod/mod_access.html#deny
#
# The Order directive controls the default access state and the order
# in which Allow and Deny directives are evaluated. Ordering is one of
#
# o  Deny,Allow
#    The Deny directives are evaluated before the Allow directives.
#    Access is allowed by default. Any client which does NOT match
#    a Deny directive -or- DOES match an Allow directive will be
#    allowed access to the server.
#
# o  Allow,Deny
#    The Allow directives are evaluated before the Deny directives.
#    Access is denied by default. Any client which does NOT match
#    an Allow directive -or- DOES match a Deny directive will be
#    denied access to the server.
#
# Q: Aren't the second parts of these evaluations redundant?
# A: Nope. Don't forget the "Deny from all" and "Allow from all"
#    forms of these directives. They can modify the "default"
#    result from within each "default" setting (so to speak).
#
#-----------------------------------------------------------------------

sub methodIsAllowed
{   my($self,$realm,$method,$authOrder) = @_;
    return 0 unless ($realm and $method);
    $authOrder ||= "allow,deny";

    if ($authOrder =~ /^allow/) {
    } else {
    }
    return 1;
    return 0;
}

sub loginIsAllowed
{   my($self,$realm,$login,$authOrder) = @_;

    return 1;  # DEBUG:


    return 0 unless ($realm and $login);
    $authOrder ||= "allow,deny";

    my $allow   = $self->locDir( $realm, 'allow',   "sans" ) ||"";
    my $deny    = $self->locDir( $realm, 'deny',    "sans" ) ||"";
    my $require = $self->locDir( $realm, 'require', "sans" ) ||"";

    $Debug and warn "DEBUG:        allow='$allow'\n";
    $Debug and warn "DEBUG:         deny='$deny'\n";
    $Debug and warn "DEBUG:      require='$require'\n";

    if ($authOrder =~ /^allow/) {
    } else {
    }
    return 1;
    return 0;
}
#_________________________
1; # Required by require()


__END__

#-----------------------------------------------------------------------
# Sample of the config file expected by this class;
# this format should look familiar to Apache admins.
# Note that not all of the directives shown in this
# example are supported by the Config class yet.
#-----------------------------------------------------------------------

# File:  psd.conf 
# Desc:  Configuration file for the Persistent Session Daemon
#
# This is the main PSD server configuration file. It contains the
# configuration directives that give the server its instructions.
# This file uses directives that are identical to the Apache Web
# server's httpd.conf file with the following modifications.
#
# .  SessionPersist { True | False | On | Off | 1 | 0 }
# .  SessionTimeout { seconds }
# .  SessionsLimit  { number }
#
# The SessionsLimit directive may only be set globally, while the
# SessionPersist and SessionTimeout directives can be set either
# globally or within a <Location> section. 
#
# This also allows RELATIVE paths in various directives. This syntax
# is not valid in an Apache config file, but it *always* bugged me 
# that the Apache server does not support this.
# .  Log Files     - relative to ServerRoot
# .  ScriptAlias   - relative to ServerRoot
# .  AuthUserFile  - relative to ServerRoot
# .  AuthGroupFile - relative to ServerRoot
# .  Alias         - relative to DocumentRoot  (document URL aliasing)
# 
# Not all of the directives in this file are supported yet, but
# the ones included here seem to be a nice subset of things to
# plan on supporting, eventually. A nice place to start would be
# with <VirtualHost> as this would allow running both a plain
# vanilla server and an SSL server from the same daemon process.
#
# See the Apache Web server documentation for details about the other 
# directives used in this file. A full manual with a User's guide,
# reference material and tutorials can be found at the following URL.
# http://apache.org/apache/

### Section 1: Global Environment
#
#ServerRoot "/opt/tools/psd"
ServerRoot "/home/cobb/misc/psd"
PidFile    "data/ucd/ucd.pid"

Listen 192.168.0.101:19665

#-----------------------------------------------------------------------
# SSL Protocol Switch:
# Enable/Disable SSL for this PSD server daemon.
SSLEngine on

# Server Certificate:
# Point SSLCertificateFile at a PEM encoded certificate.  If
# the certificate is encrypted, then you will be prompted for a
# pass phrase.  Note that a kill -HUP will prompt again.
SSLCertificateFile /opt/tools/psd/data/ssl/barre_server.cert

# Server Private Key:
# If the key is not combined with the certificate, use this
# directive to point at the key file.
SSLCertificateKeyFile /opt/tools/psd/data/ssl/barre_server.key

#-----------------------------------------------------------------------

### Section 2: 'Main' server configuration
#
User cobb
Group uxdev

ServerAdmin admin@host.domain
ServerName host.domain:19665

DocumentRoot "/opt/tools/psd/webdoc"

# ErrorLog: The location of the error log file.
# If you do not specify an ErrorLog directive within a <VirtualHost>
# container, error messages relating to that virtual host will be
# logged here.  If you *do* define an error logfile for a <VirtualHost>
# container, that host's errors will be logged there and not here.
#
ErrorLog data/psd/error_log

# LogLevel: Control the number of messages logged to the error_log.
# Possible values include: debug, info, notice, warn, error, crit,
# alert, emerg.
#
LogLevel warn

# The location and format of the access logfile (Common Logfile Format).
# If you do not define any access logfiles within a <VirtualHost>
# container, they will be logged here.  Contrariwise, if you *do*
# define per-<VirtualHost> access logfiles, transactions will be
# logged therein and *not* in this file.
#
#CustomLog logs/access_log common

# If you prefer a single logfile with access, agent, and referer information
# (Combined Logfile Format) you can use the following directive.
#
CustomLog logs/access_log combined

# Aliases: Add here as many aliases as you need (with no limit). The format is 
# Alias fakename realname
#
# Note that if you include a trailing / on fakename then the server will
# require it to be present in the URL.  So "/icons" isn't aliased in this
# example, only "/icons/".  If the fakename is slash-terminated, then the 
# realname must also be slash terminated, and if the fakename omits the 
# trailing slash, the realname must also omit it.
#
# We include the /icons/ alias for FancyIndexed directory listings.  If you
# do not use FancyIndexing, you may comment this out.
#
#Alias /icons/ "/opt/tools/apache/icons/"
Alias /tools/ "/opt/tools/webdoc/"
Alias /tooltest/ "/opt/tools/ptools/webdoc/"

<Directory "/opt/tools/apache/icons">
    Options Indexes MultiViews
    AllowOverride None
    Order allow,deny
    Allow from all
</Directory>

# ScriptAlias: This controls which directories contain server scripts.
# ScriptAliases are essentially the same as Aliases, except that
# documents in the realname directory are treated as applications and
# run by the server when requested rather than as documents sent to the client.
# The same rules about trailing "/" apply to ScriptAlias directives as to
# Alias.
#
# Typical for "plain" CGI mode             (Non-ModPerl mode)
ScriptAlias /cgi-bin/tooltest/ "/nethome/cobb/misc/ptools/webcgi/"
ScriptAlias /cgi-bin/tools/ "/opt/tools/webcgi/"
ScriptAlias /cgi-bin/cia/   "/opt/tools/webcgi/cia/"
ScriptAlias /cgi-bin/       "/opt/tools/apache/cgi-bin/"

# Allow server status reports 
# with the URL of http://servername/server-status
#
<Location /server-status>
    SetHandler server-status
    Order allow,deny
    Allow from all
    #Allow from host1.domain,host2.domain
    Deny from all
</Location>

# Allow remote server configuration reports, with the URL of
#  http://servername/server-info
#
<Location /server-info>
    SetHandler server-info
    Order allow,deny
    #Allow from host1.domain,host2.domain
    Deny from all
</Location>

#-----------------------------------------------------------------------
# Configure persistent sessions for URLs that start with /session
#-----------------------------------------------------------------------

SessionPersist True
SessionTimeout 300
SessionsLimit  99

ScriptAlias /session/admin "webcgi/session/admin.pl"
ScriptAlias /session/demo  "webcgi/session/demo.pl"

<Location /session/admin>
    AuthUserFile  data/acl/passwd
    AuthGroupFile /dev/null
    AuthType Basic
    AuthName "Administrator Session"

    SetHandler cgi-script
    CustomLog  data/psd/admin-log
    #CustomLog data/psd/admin-access_log
    #ErrorLog  data/psd/admin-error_log

    Order allow,deny
    Deny from all
    # require user admin webmaster root cobb
    require valid-user

    <LimitExcept POST GET>
    </LimitExcept>
</Location>

<Location /session/demo>
    #AuthUserFile  data/acl/passwd
    #AuthGroupFile /dev/null
    AuthType Custom
    AuthName "Demonstration Session"

    SetHandler cgi-script
    CustomLog  data/psd/demo-%user%-log
    #CustomLog data/psd/demo-%user%-access_log
    #ErrorLog  data/psd/demo-%user%-error_log

    Order allow,deny
    Deny from all
    # require user train admin webmaster root cobb
    require valid-user

    <LimitExcept POST GET>
	Deny from all
    </LimitExcept>
</Location>

### Section 3: Virtual Hosts
###
###  [ not yet supported ]
###


__END__

our @ISA     = qw( Apache::Admin::Config );
use Apache::Admin::Config;

# our @ISA     = qw( Config::General );
# use Config::General;
# *getConfig   = \&Config::General::getall;

#-----------------------------------------------------------------------
# Both of these parsers do a great job of parsing Apache-style config 
# files, but each one definitely has strengths and weaknesses.
#
#     Apache::Admin::Config             Config::General
#   -----------------------------     -------------------------------
#   . limited parsing controls        . many cool parsing controls
#   . parser is somewhat limited      . has a better parser
#     (doesn't follow includes)         (include files, interpolation)
#   . much better OO approach         . *very* weak OO implementation
#     (sections are object nodes)       (returns a hash, uses Exporter)
#   . retains comment lines           . ignores comment lines
#   . customizable "write" filters    . can't customize output
#   . easy to add new sections, etc   . must manipulate hash directly
# 
# While Config::General has the more powerful and flexible parser,
# the additional parsing power (interpolation, here documents) would
# only be good for config files that aren't "valid" httpd.conf format.
# In addition, it returns a plain hash that callers must then peruse.
# It's a shame there is no OO interface to access the parsed content!!
# Also, ignoring comments in config files that so obviously need a
# whole lot of in-line documentation is a strange decision indeed.
# What's the use of a 'save' method here if you loose the comments?!
#
# Looks like Apache::Admin::Config is the better choice to start with.
# ToDo: Investigate adding support for include files and interpolated
# variable handling later on. This *might* be pretty easy...check the
# existing code that allows customizing the various "write" methods!
#
#-----------------------------------------------------------------------
# A note on the Config::Auto module (with a prereq of Config::IniFiles).
# This class sounds "too good to be true," and it is. This doesn't
# handle Apache-style config files at all, and there's no OO interface.
#
# our @ISA     = qw( Config::Auto );
# use Config::Auto;
# sub new 
# {   my($class,$file,$type) = @_;
#     bless my $self = Config::Auto::parse( $file, format => $type ),
# 	ref($class)||$class;
# }

#_________________________
1; # Required by require()


