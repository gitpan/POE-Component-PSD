# -*- Perl -*-
#
# File:  POE/Component/Server/PSD/CGI.pm
# Desc:  Generic IO handler for process sessions
# Date:  Wed Feb 02 17:03:35 2005
# Stat:  Prototype, Experimental
#
# Abstract:
#        Example of using the ubiquitous CGI.pm class to read
#        and parse HTTP requests from the PSD process manager,
#        and to generate responses for the client/browser.
#
#        This class, when used to interface with the PSD server,
#        *should* behave just like CGI.pm does in the 'standard'
#        CGI environment (with the one exception of 'flushing' 
#        output at the end of each request cycle). Everything 
#        looks copacetic so far, but there could well be subtle
#        nuances that the PSD server still needs to support.
#
#        The INTENT here is that existing CGI scripts will work
#        unchanged, except for wrapping each script in a 'while' 
#        loop and flushing output as shown in the Synopsis below.
#
#        Note that this will NOT work with 'Server Push' scripts
#        as the underlying 'POE::Component::Server::SimpleHTTP'
#        class does not support this functionality. Currently
#        the PSD server is limited to 'one-request, one-response'.
#
# Synopsis:
#        use POE::Component::PSD::Server::CGI;
#  -or-  use POE::Component::PSD::Server::CGI qw( Debug );
#
#        $cgiWrapper = "POE::Component::PSD::Server::CGI";
#
#        while( 1 ) {
#            # Each instantiation is one HTTP "request cycle".
#            # The $cgi object should behave just like CGI.pm
#            # For multiple calls to 'new' method, as some scripts
#            # do within a single "request cycle", simply use the  
#            # original CGI module and call 'new' on that class.
#
#            $cgi = $cgiWrapper->new();           # parse new request
#
#            print $cgi->header( -type => 'text/html' );
#            print $cgi->start_form();            # the "normal CGI stuff"
#            # ... do this, that, whatever ...    # (but output is delayed)
#
#            $text = $cgi->untaint( $text )       # safely 'untaint' strings
#                if $cgi->isTainted( $text );
#
#            $cgi->flushOutput();                 # send output to client
#
#            $button = $cgi->param('Button') || $cgi->param('button') || "";
#            exit(0) if ($button eq "Logout" );   # determine if exit/Logout
#        }
#
# Processing:
#        Each instantiation of this class is one HTTP request cycle.
#
#        PARENT: PSD process initialization protocol is to 
#        .  run the external script that maintains a "persistent session"
#        .  send the following arguments to the script during startup
#           (these are the "static" arguments that should not vary)
#           -   [ list is TBD ]   user, realm, (certificate?), etc.
#           -  
#        PARENT: PSD process HTTP request protocol is to 
#        .  write a 6-digit "header length" value to STDOUT (Child)
#        .  write subset of headers w/EnvVar names and values to Child
#           (the "dynamic" arguments that vary per HTTP request cycle)
#           FIX: include both original request URI and "proxy URI"
#        .  write the HTTP request content to Child
#        .  all output on STDERR (from Child) is collected and logged
#        .  wait for "EOD" marker on STDIN (from Child) before returning 
#              the HTTP "response" to the client/browser
#        .  if the Child process using THIS class dies, any STDERR
#              output collected during a given "request cycle" is 
#              sent to the client/browser to aid in troubleshooting
#
#        CHILD: CGI "emulation" processing in this class includes
#        .  redirect all "print" and "printf" output to a string variable
#        .  read the 6-digit "header length" value from STDIN (Parent)
#        .  read any "EnvVar" headers and set EVs with the passed values
#        .  read the HTTP request content and parse using CGI.pm class
#        .  collect STDOUT from a "normal" CGI script in the string var
#        .  provide a method to flush collected STDOUT to Parent process
#        .  let all STDERR output flow to Parent process for logging, etc.
#
# Note:  The 'OutputToString' class used to redirect STDOUT output to
#        a string variable is included at the end of this module.
#

package POE::Component::PSD::Server::CGI;
use 5.006;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.02';
our @ISA     = qw( CGI );

use CGI;

my $Debug = 0;

sub new
{   my($class, $noRedirect) = @_;

    # Process:
    # . redirect STDOUT (print, printf) to a string variable
    #   (this way, existing scripts or modules that expect to
    #   run in a "normal" CGI environment do not have to change)
    # . parse "Environment Variable" headers passed from parent
    # . reset the CGI 'globals' variables to start a new request cycle
    # . call on CGI.pm to read and parse the current request
    #
    $class->redirectStdout()  unless ($noRedirect);

    $class->setupEnvironment();         # collect/set request EVs...

    $class->initialize_globals();       # reset parser, and then...

    return $class->SUPER::new();        # ...read and parse 'content'
}

sub import
{   my($class,$debug) = @_;
    $Debug = 1 if ($debug and $debug =~ /^debug/i);
}

sub setupEnvironment
{   my($class) = @_;

    # Read the 6-digit "header-length" value from parent and,
    # if parent passed EV headers, read 'em and set 'em.
    #
    my($headerLength, $headerData) = (0,"");

    $class->read_from_parent( \$headerLength, 6,0 );

    if ( $headerLength and int $headerLength > 0 ) {
	$class->read_from_parent( \$headerData, $headerLength,0 );

	my($ev,$value);
	foreach my $line (split("\n", $headerData)) {
	    next unless $line;
	    #
	    # FIX? Allow for deleting any prior EVs that are now unset?
	    # Currently parent passes all EVs; some may have null values.
	    # EVs are prepended with "EV:" to allow passing other things.
	    # The following EVs will be passed in the following format 
	    # (of course, the values change to match the current request).
            #    EV:CONTENT_LENGTH=376
            #    EV:CONTENT_TYPE=application/x-www-form-urlencoded
            #    EV:HTTPS=on
            #    EV:REQUEST_METHOD=POST
            #    EV:QUERY_STRING=
            #    EV:PATH_INFO=
	    # FIX: include both original request URI and "proxy URI" here.
	    #
	    ($ev,$value) = $line =~ /^EV:([^=]*)=(.*)$/;
	    next unless $ev;
	    defined $value or $value = "";      # allow for a '0' value
	    $ENV{$ev} = $value;
	}
	#warn "INPUT='$headerData'\n";
    }

    if ( $Debug ) {
	##my(@EVs) = qw(
	##    CONTENT_LENGTH  CONTENT_TYPE  HTTPS  QUERY_STRING
	##    REQUEST_METHOD  PATH_INFO
	##);
	##foreach my $env ( @EVs ) {

	foreach my $env ( sort keys %ENV ) {
	    my $val = $ENV{$env} ||"";
	    warn "DEBUG: EV: $env = $ENV{$env}\n";
	}
	warn "HEADER_LENGTH='$headerLength'\n";
	my $len = $ENV{CONTENT_LENGTH};
	warn "DEBUG: READING $len bytes of 'content' from parent\n";
    }
    return;   
}

#-----------------------------------------------------------------------
# Usage:
#   if ( $class->isTainted( $text ) ) {
#       $text = $class->untaint( $text );
#   }
#
# Test the contents of a scalar variable for 'taintedness'. Note that
# running CGI scripts in 'Taint' mode is highly recommended as a best
# practice with Perl.

*isTainted = \&is_tainted;

sub is_tainted
{   my($class, $text) = @_;
    my $test = substr($text,0,0);
    local $@;
    eval { eval "# $test" };
    return length($@) != 0;
}

# Usage:
#   $text = $class->untaint( $text [, $allowedCharList ] );
#
# Any character not in the "$allowedCharList" becomes an underscore ("_")
# The default "$allowedCharList" includes those characters identified in
# "The WWW Security FAQ" with the addition of the space (" ") character.

sub untaint
{   my($class, $text, $allowedChars) = @_;

    $allowedChars ||= '- a-zA-Z0-9_.@';      # default allowed chars

    $text =~ s/[^$allowedChars]/_/go;        # replace disallowed chars
    $text =~ m/(.*)/;                        # untaint using a match
    return $1;                               # return untainted match
}

#-----------------------------------------------------------------------
# Read data from a file handle  (Borrowed from CGI.pm)
# The orig method changes in various CGI.pm versions,
# so we're much better off just including it here.

*readFromParent = \&read_from_parent;

sub read_from_parent
{   my($self, $buff, $len, $offset) = @_;
    local $^W=0;                # prevent a warning

    ## warn "DEBUG: read_from_parent: len=$len (offset=$offset)\n";

    return read(\*STDIN, $$buff, $len, $offset);
}

#-----------------------------------------------------------------------
# PSD protocol requires "End Of Data" marker. With incoming data 
# we have a nice 'content-length' header. Sending output back to
# a POE "wheel" is a bit more problematic. A better way would be
# nice here. (This is not necessary with 'STDERR' output, as that
# is controlled by what does or does not get sent through STDOUT.)
#
my $EOD = ":HTTP_PSD_EOD:";

*writeToParent = \&write_to_parent;

sub write_to_parent
{   my($self, $output) = @_;
 
    ## my($len1, $len2) = ( length( $output ), length( "\n$EOD" ) );
    ## warn "DEBUG: write_to_parent: len=$len1 (+ $len2 EOD)\n";

    return syswrite( \*STDOUT, "$output\n$EOD" );
}

*errToParent = \&err_to_parent;

sub err_to_parent
{   my($self, $errText) = @_;
 
    ## my $len = length $errText;
    ## warn "DEBUG: err_to_parent: len=$len\n";

    return syswrite( \*STDERR, $errText );
}

#-----------------------------------------------------------------------
# Mixing 'print' and 'sysread' calls on a filehandle is usually bad.
# Here we provide a mechanism that will interrupt all output from
# 'print' and 'printf' calls and stuff the output into a string
# variable. After all output is collected, the 'flushStdout()' 
# method should be called which will 'syswrite()' to the parent.
# FIX: So why does 'warn' work so well in passing STDERR output
# back to the parent?? How can we get 'print' to work nicely too??
#
my($Redirected,$OrigOut,$TempOut) = (0,undef,undef);

*redirectStdout = \&redirect_stdout;

sub redirect_stdout
{   my($class) = @_;

    if ($Redirected) {         # Oops! already redirected
	$TempOut = undef;      # start with a "clean slate"
	untie *STDOUT;
    }
    $OrigOut = *STDOUT;

    # Overrides Perl's "print" and "printf" but not "write".
    # Note: 'OutputToString' class is defined, below.
    #
    $TempOut = tie *STDOUT, 'OutputToString';

    $Redirected = 1;
    return;
}

*flushStdout  = \&flush_stdout;
*flushOutput  = \&flush_stdout;
*flush_output = \&flush_stdout;

sub flush_stdout
{   my($class, $output) = @_;

    if (! $Redirected ) {
	return $class->write_to_parent( $output );
    }

    untie *STDOUT;
    $class->write_to_parent( $$TempOut );   # note scalar reference here
    $TempOut = undef;                       # don't forget memory cleanup
    $Redirected = 0;
    return;
}

package OutputToString;  # Send FILE output to a string
sub TIEHANDLE { my $str; bless \$str, ref($_[0])||$_[0] }  # instantiate/tie
sub PRINT     { ${$_[0]} .= ( $_[1] ||'' )              }  # override 'print'
sub PRINTF    { ${$_[0]} .= sprintf $_[1],$_[2]         }  # override 'printf'
sub UNTIE 
{   my ($self,$count) = @_;
    # Suppress warning: can't undef $TempOut until *after* untie.
    # warn "untie: $count inner references still exist" if $count;
}

package OutputToArray;  # Send FILE output to an array
sub TIEHANDLE { bless [], ref($_[0])||$_[0]          }  # instantiate on 'tie'
sub PRINT     { push  @{$_[0]}, $_[1]                }  # override 'print'
sub PRINTF    { push  @{$_[0]}, sprintf $_[1],$_[2]  }  # override 'printf'
sub WRITE     { print "WRITE CALLED...NOT\n"         }  # this does NOT work
#_________________________
1; # Required by require()
