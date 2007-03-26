# -*- Perl -*-
#
# File:  POE/Component/PSD/Server.pm
# Desc:  An HTTP/HTTPS daemon that manages persistent user sessions.
# Stat:  Prototype, Experimental
#
# Synopsis:
#        Create a small script that runs this module as shown here.
#        The 'configFile' is expected to be in Apache-style format
#        with a couple of extensions defined for the PSD daemon.
#        Using SSL is optional with this daemon but, without SSL,
#        be very sure to NOT use any user authentication that
#        requires transmitting passwords to the server! For an
#        example of the expected config file, see comments after
#        the 'END' of "POE/Component/Server/PSD/Config.pm"
#
#        #!/opt/perl/bin/perl -T
#        use 5.006;
#        use strict;
#        use warnings;
#        use PTools::Local;
#        my $configFile = PTools::Local->path('app_cfgdir', "psd.conf");
#
#        use POE::Component::PSD::Server;
#        run POE::Component::PSD::Server( $configFile );
#        exit(0);
#
# Dependencies:
#        Yeah, a bunch, including the following.
#        .  a valid SSL server certificate
#           - a script to create and self-sign certs is included w/PSD app
#           - OpenSSL is required to run the certificate generator script
#        .  POE - the set of basic classes, plus:
#           -  POE::Component::Server::SimpleHTTP
#           -  POE::Component::SSLify
#        .  Apache::Admin::Config
#        .  Digest::MD5
#        .  Time::HiRes
#        .  Also required: several 'PerlTools' global modules
#           -  PTools::Date::Format
#           -  PTools::Passwd
#           -  PTools::Proc::Daemonize
#        .  Optional: additional PSD utility module
#           -  Apache::UriProxy  (Apache server plug-in to proxy requests)
#        .  Optional: additional 'PerlTools' global modules
#
# PSD Components:
#        Apache/UriProxy.pm         - Apache mod_perl 1.x plug-in to proxy requests
#        Apache2/UriProxy.pm        - Apache mod_perl 2.x (1.99) plug-in for proxy 
#
#        PoCo/PSD/Client.pm         - example of scripts accessing a PSD server
#        PoCo/PSD/Client/Login.pm   - login to a PSD server and maintain cookie(s)
#
#        PoCo/PSD/Server.pm         - parse options, daemonize process
#        PoCo/PSD/Server/Auth.pm    - authentication and authorization
#        PoCo/PSD/Server/Config.pm  - configuration file parser class
#        PoCo/PSD/Server/CGI.pm     - wrapper for ubiquitous CGI.pm class
#        PoCo/PSD/Server/HTTP.pm    - HTTP/SSL network connection service
#        PoCo/PSD/Server/Log.pm     - system logging
#        PoCo/PSD/Server/Manager.pm - user session manager
#        PoCo/PSD/Server/Session.pm - user session (runs session scripts)
#

package POE::Component::PSD::Server;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.02';
our @ISA     = qw( );

use POE;
use POE::Component::PSD::Server::Auth;
use POE::Component::PSD::Server::Config;
use POE::Component::PSD::Server::HTTP;
use POE::Component::PSD::Server::Log;
use POE::Component::PSD::Server::Manager;
use POSIX qw( errno_h );              # Defines CORE::kill errors
use PTools::Proc::Daemonize;          # Turn script into a daemon process
use PTools::Options;                  # Cmd-line options parser
use PTools::Debug;
use PTools::Verbose;

my $AuthClass    = "POE::Component::PSD::Server::Auth";
my $ConfigClass  = "POE::Component::PSD::Server::Config";
my $LogClass     = "POE::Component::PSD::Server::Log";
my $ManagerClass = "POE::Component::PSD::Server::Manager";
my $HttpClass    = "POE::Component::PSD::Server::HTTP";

my($BaseName)    = ( $0 =~ m#^(?:.*/)?(.*)#);
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

    $configFile or die "$BaseName: Error: No config file found";

    $ENV{PATH} = $EnvPath;              # untaint since running "-T"

    $class->validateOptions( $configFile );    # parse @ARGV
    $configFile = $Opts->get('configFile');    # was "-c <cfgfile>" used?

    my $config = $ConfigClass->new( $configFile )
	or die $ConfigClass->error();
    $config->postLoadProcess();         # do a little set up...

    $class->daemonizeProcess( $config );

    my $debugLevel = $Opts->debug->getLevel();

    # WARN: Order is important here! Start the
    # Logger first, then spawn the Manager service!
    #
    $LogClass->spawn( $config );
    $ManagerClass->spawn( $config );
    $AuthClass->new( $config );
    $HttpClass->spawn( $config );

    $poe_kernel->run();
    return 0;
}

sub daemonizeProcess
{   my($class, $config ) = @_;

    # Turn the current process into a background daemon process,
    # including verify user configuration and untaint PATH, EVs,
    # redirecting standard IO, and detaching the session from any
    # controlling terminal. Note that both 'IO redirection' and
    # 'session detach' are skipped when Debug flag is non-zero.
    # See the PTools::Proc::Daemonize man page for the details.

    my $rootDir    = $config->globalDirective('ServerRoot', "sansQuotes");
    my $configFile = $config->configFile() || "((Unknown config file name))";
    if (! $rootDir) {
	warn "$BaseName: Error: No 'ServerRoot' found";
	warn "\nMake sure to edit the server config file found at\n";
	die "$configFile\n\n";
    } elsif (! -d $rootDir) {
	warn "$BaseName: Error: 'ServerRoot' is not a directory at";
	warn "\nServerRoot: $rootDir\n";
	die "ConfigFile: $configFile\n\n";
    } elsif (! -w $rootDir) {
	warn "$BaseName: Error: 'ServerRoot' is not writable at";
	warn "\nServerRoot: $rootDir\n";
	die "ConfigFile: $configFile\n\n";
    }

    my $logFile  = $config->globalDirective('ErrorLog',   "sansQuotes")
	or die "$BaseName: Error: No 'ErrorLog' found";
    $logFile = "$rootDir/$logFile" 
	unless ($logFile =~ m#^/#);

    my $pidFile  = $config->globalDirective('PidFile',    "sansQuotes")
	or die "$BaseName: Error: No 'PidFile' found";
    $pidFile = "$rootDir/$pidFile" 
	unless ($pidFile =~ m#^/#);

    my $user  = $config->globalDirective('User',  "sansQuotes")
	or die "$BaseName: Error: No 'User' found";
    my $group = $config->globalDirective('Group', "sansQuotes")
	or die "$BaseName: Error: No 'Group' found";

    my $uid = ( $user  =~ /^\d+$/ ? $user  : getpwnam($user) );
    $uid or die "$BaseName: Error: Invalid uid";

    my $gid = ( $group =~ /^\d+$/ ? $group : getgrnam($group) );
    $gid or die "$BaseName: Error: Invalid gid";

    my $umask = 022; ##   unless ( defined($umask) and length($umask) );

    $uid = 1  unless ( defined($uid)   and length($uid)   );
    $gid = 5  unless ( defined($gid)   and length($uid)   );

    my $daemon      = new PTools::Proc::Daemonize;
    my $workingDir  = "/tmp";
    my $evListRef   = [ "TZ" ];

    my(@daemonArgs) = ( $uid,$gid, $workingDir, $umask,   $evListRef,
                        $EnvPath,  $logFile,    $pidFile );

    $daemon->runAs( $Debug->isSet(), @daemonArgs );

    my($stat,$err) = $daemon->status();
    $stat and die "Error: $err\n";

    return;
}

sub validateOptions
{   my($class, $defaultConfigFile ) = @_;

    my $usage = <<"__EndOfUsage__";

 Usage: $BaseName <options>

    where <options> to start a server daemon include:
	-h                   -  display usage and exit
	-D [<debug_level>]   -  set debug flag w/optional level
	-c <config_file>     -  specify alternate config file
	-l <log_level>       -  specify starting logging level
	-m <max_views>       -  specify 'hard' max View limit

    additional <options> can be used to signal a running server:
	-logincr             -  increment current logging level
	-logdecr             -  decrement current logging level
	-logreset            -  reset to starting logging level
	-reconfig            -  reconfigure a running daemon
	-restart             -  completely restart running daemon
	-shutdown            -  initiate graceful daemon shutdown
	-stop (or -quit)     -  'hard' abort (try -shutdown 1st)
	-kill                -  kill the daemon (final resort)

__EndOfUsage__
    
    my(@optArgs) = (
	      "help|?|h",             # help    flag
       "debug|Debug|D|d:i",           # debug   flag:  -d [n] | -debug [n]
             "verbose|v+",            # verbose flag:  -v [-v...]

      "configFile|cfg|c=s",           # config file
            "logLevel|l=i",           # initial logging verbosity level
	    "maxViews|m=i",           # maximum number of Views on server

	     "restart",               # completely restart daemon proc

	# Signal handling switches. Each is mutually exculsive with 
	# any other option. Note that SIGTERM is "15" while Ctrl+\
	# is "3" (SIGQUIT). Both are supported by the PSD server and
	# are used to initiate a "graceful" shutdown of the daemon.
	# These are options to the "ztmpvwmgr" command, but they are
	# only effective if the PSD server is already running AND if
	# a user running the command has permission to sig the proc.

	    "SIGHUP|sighup|hup|HUP|reconfig",     # sig  1
	    "SIGINT|sigint|int|INT|logreset",     # sig  2 (or Ctrl+c)
	"SIGQUIT|sigquit|quit|QUIT|quit",         # sig  3 (or Ctrl+\)
	     "SIGKILL|sigkill|KILL|kill",         # sig  9
	"SIGPIPE|sigpipe|pipe|PIPE|stop",         # sig 13
	"SIGTERM|sigterm|term|TERM|shutdown",     # sig 15
	"SIGUSR1|sigusr1|usr1|USR1|logincr",      # sig 16
	"SIGUSR2|sigusr2|usr2|USR2|logdecr",      # sig 17
    );

    # Configure Getopt::Long, then collect and parse the ARGV array.
    # NOTE: If we will have "long options with a single dash" ("-debug"),
    # we must configure for either "no_bundling" or "bundling_override".

    $Opts = new PTools::Options();             # delay parsing @ARGV

  # $Opts->config( "posix_default" );          # as if EV "POSIXLY_CORRECT" set
  # $Opts->config( "no_bundling" );            # disable bundling entirely
    $Opts->config( "bundling_override" );      # allow bundling AND long opts

    $Opts->parse( $usage, @optArgs );          # parse @ARGV via Getopt::Long
    
    $Opts->abortOnError();                     # abort if any parsing errors

    #-----------------------------------------------------------------------
    # Verify/validate the various possible option/argument combinations
    # Was "-d/-debug" and/or "-v/-verbose" used this time 'round? 
    #
    $Opts->exitWithUsage() if $Opts->help();   # exit if "-h" or "-help" used

    $Debug   = new PTools::Debug  ( $Opts->get('debug')   );
    $Verbose = new PTools::Verbose( $Opts->get('verbose') );

    $Opts->set('debug',   $Debug  );           # turn attribute into an object
    $Opts->set('verbose', $Verbose);           # turn attribute into an object

    #-----------------------------------------------------------------------
    # Config file prescidence:
    # 1)  user entered option (-c filename)
    # 2)  application default config file
    #
    $Opts->set('configFile', $defaultConfigFile)
	unless ( $Opts->get('configFile') );   # set from option, or default

    $ConfigFile = $Opts->get('configFile');    # cache it for access later
    #-----------------------------------------------------------------------
    # ToDo: complete validation steps, implement "-l" switch
    #
    die "$BaseName: Error: -l switch not implemented"  if $Opts->logLevel();

    $class->validateSigOpts();

    #-----------------------------------------------------------------------
    # warn $Opts->dump();           # show contents of $opts object(s)
    # warn $Debug->dump()           if $Debug->isSet();
    # warn $Verbose->dump()         if $Verbose->isSet();

    return;
}

sub validateSigOpts
{   my($class) = @_;

    #-------------------------------------------------------------------
    # Do a special check to handle restart processing

    if ( $Opts->restart() ) {
	$class->signalServerPid( "TERM" );
	sleep 1;
	warn "$BaseName: restarting server process\n";
	return;
    }

    #-------------------------------------------------------------------
    my $optRef = $Opts->opts();      # collect user-entered options
    my($sigCount, $optCount, $signal) = (0,0,"");

    foreach my $opt ( @$optRef ) {
	if ( $opt =~ /^SIG(\w+)/ ) {
	    $signal = $1;
	    $sigCount++;
	} else {
	    $optCount++;
	}
    }
    return unless ($sigCount);       # no signal opts? we're outta here.

    #-------------------------------------------------------------------
    # WARN: We have a signal option. All further logic in this
    # method will result in either a clean exit or an abort.
    # Nothing else returns from here to the end of this subroutine.
    #-------------------------------------------------------------------

    if ( ($optCount) or ($sigCount > 1) ) {
	warn "$BaseName: Error: signal options are mutually exclusive.\n";
	$Opts->abortWithUsage();
    }

    # Okay, we have one signal opt. Let's figure out where to send it.
    # FIX: add nice helpful messages if no pid, signal fails, etc.

    $class->signalServerPid( $signal );

    exit( 0 );   ### if $sigOkay;         # signal sent! Just exit here.
}

sub signalServerPid
{   my($class, $signal, $processId) = @_;

    $processId ||= $class->getServerPid();

    ## warn "DEBUG: attempting to send 'SIG$signal' to PID '$processId'\n";

    my $sigOkay = CORE::kill( $signal, $processId );

    return  if ($sigOkay);

    #-------------------------------------------------------------------
    # Oops. Something went wrong. If server not running and we're
    # in 'restart' mode it's not fatal

    if ($! and $! == EPERM) {
	warn "$BaseName: Error: no permission to signal PSD server\n";
    } elsif ($! and $! == ESRCH) {
	my $text = ( $processId ? " as pid=$processId" : "" );
	if ( $Opts->restart() ) {
	    warn "$BaseName: Note: server not running$text\n";
	    return;
	} else {
	    warn "$BaseName: Error: PSD server not running$text\n";
	}
    } elsif ($!) {
	warn "$BaseName: Error: can't send 'SIG$signal' to PSD server: $!\n";
    }
    exit(-1);
}


sub getServerPid
{   my($class, $config) = @_;

    if (! ref $config) {
	my $configFile = $Opts->get('configFile')
	    or die "$BaseName: Error: No configFile found";

	$config ||= $ConfigClass->new( $configFile )
	    or die $ConfigClass->error();
	$config->postLoadProcess();         # do a little set up...
    }

    my $rootDir  = $config->globalDirective('ServerRoot', "sansQuotes")
	or die "$BaseName: Error: No 'ServerRoot' found";

    my $pidFile  = $config->globalDirective('PidFile',    "sansQuotes")
	or die "$BaseName: Error: No 'PidFile' found";

    $pidFile = "$rootDir/$pidFile" 
	unless ($pidFile =~ m#^/#);

    if (! -f $pidFile ) {
	warn "$BaseName: Error: No 'pid file' found to check\n";
	exit(-1);

    } elsif (! -r _ ) {
	warn "$BaseName: Error: The 'pid file' is not readable\n";
	exit(-1);
    }

    local(*IN);
    open(IN, "<$pidFile") || die "$BaseName: Error: can't open '$pidFile': $!";
    my $processId = <IN>  || die "$BaseName: Error: can't read '$pidFile': $!";
    close(IN)             || die "$BaseName: Error: can't close '$pidFile': $!";
    chomp $processId;

    if ($processId =~ /^(\d+)$/) {           # verify (and detaint) the PID
	$processId = $1;
    } else {
	warn "$BaseName: Error: non-numeric PID '$processId' in 'pid file'\n";
	exit(-1);
    }

    return $processId;
}
#_________________________
1; # Required by require()
