# -*- Perl -*-
#                                 ## for use with mod_perl 1.99 (2.x) ##
# File:  Apache2/UriProxy.pm
# Desc:  Selectively invokes mod_proxy for "internal" Non-proxy Requests
# Auth:  This module is based on the original Apache::UriProxy module
#        which, in turn, is based on the example by Stein, MacEachern, 
#        in the book "Writing Apache Modules," Chap 7, Pub by O'Reilly.
# Stat:  Prototype, Experimental
#
# Abstract:
#      Input URI:  scheme://host[:port]/some/path[?some+arguments]
#      Input Map:  /some/path => [scheme://]host:port/other/path
#      Process:    Create a proxy-redirect from original URL to new URL.
#
# Note:  As of 09-Jun2006, a pertinent excerpt from Chap 7 of the
#        above mentioned book is available at the following URL.
#        http://www.infocopter.com/perl/mod_perl_proxy.htm 
#        (This explains the original Apache::UriProxy module.)
#
# Synopsis:
#        # Config directive (httpd.conf, etc.)
#        # The last entry will use original scheme (http or https). 
#        #
#        PerlTransHandler  Apache2::UriProxy
#        PerlSetVar PerlUriProxy \
#            '/session/ => https://foo.bar.com:12345/session/, \
#             /testSSL/ => https://foo.bar.com:12345/session/, \
#             /testing/ =>         foo.bar.com:12344/session/'
#
#        From the above mentioned URL:
#        "The PerlUriProxy variable contains a string representing a 
#        series of URI=>proxy pairs, separated by commas. A backslash
#        at the end of a line can be used to split the string over
#        several lines [to improve] readability."
#
# Dependencies:
#        Apache2.x, with the following modules
#        .  mod_perl2.x
#        .  mod_proxy
#        .  mod_ssl
#
# Setup to proxy http:// and/or https:// URIs
#        .  add desired URL map entries to the httpd.conf file (see above)
#        .  add the following 'load modules' to the httpd.conf file
#             LoadModule perl_module          /full/path/mod_perl.so
#             LoadModule proxy_module         /full/path/mod_proxy.so
#             LoadModule proxy_http_module    /full/path/mod_proxy_http.so
#             LoadModule proxy_connect_module /full/path/mod_proxy_connect.so
#             LoadModule rewrite_module       /full/path/mod_rewrite.so
#             LoadModule ssl_module           /full/path/mod_ssl.so
#           (or, in the *strange* case of SUSE 10.1 httpd configuration,
#           edit the APACHE_MODULES var in script /etc/sysconfig/apache2)
#        .  add the following directives to the httpd.conf file
#             ProxyRequests On
#        .  add the following directives to the SSL virtual host
#             SSLProxyEngine on
#
#-----------------------------------------------------------------------
# Examples and Alternatives of 'httpd.conf' Configuration Directives
#-----------------------------------------------------------------------
# URL pass-through using 'Apache2::UriProxy' and mod_perl directives
# . path-info and arguments are passed through
# . no wild-cards are allowed here
# . 'scheme' is validated (e.g., https proxy to http port is invalid)
# . 'scheme' will default to scheme of original request
# 
# Warning: When configuring a forward proxy make sure you understand 
# the proper httpd security considerations for your installation.
# <Proxy *>
#    Order Deny,Allow
#    Deny from all
#    Allow from 192.168.0
# </Proxy>
#
# <VirtualHost 192.168.0.101:443>
#    ProxyRequests  on
#    PerlTransHandler Apache2::UriProxy
#    PerlSetVar  PerlUriProxy \
#                  '/session/ => https://192.168.0.101:19665/session/, \
#                   /testing/ =>         192.168.0.101:19665/session/'
#    SSLEngine on
#    SSLProxyEngine on
#    SSLCertificateFile /path/to/ssl.crt/server.crt
#    SSLCertificateKeyFile /path/to/ssl.key/server.key
# </VirtualHost>
# 
#-----------------------------------------------------------------------
# URL pass-through using 'mod_rewrite' directives
# . path-info and arguments are passed through
# . wild-cards are allowed here
# . 'scheme' is not validated here
# . 'scheme' will not default here
#
# <VirtualHost 192.168.0.101:443>
#    ProxyRequests off
#    RewriteEngine on
#    RewriteRule ^/session(.*) https://192.168.0.101:19665/session$1 [P] 
#
#    SSLEngine on
#    SSLProxyEngine on
#    SSLCertificateFile /path/to/ssl.crt/server.crt
#    SSLCertificateKeyFile /path/to/ssl.key/server.key
# </VirtualHost>
#
#-----------------------------------------------------------------------
# URL pass-through using 'mod_proxy' directives
# . path-info and arguments are passed through
# . no wild-cards are allowed here
# . 'scheme' is not validated here
# . 'scheme' will not default here
# 
# <VirtualHost 192.168.0.101:443>
#    ProxyRequests off
#    ProxyPass  /session  https://192.168.0.101:19665/session
#
#    SSLEngine on
#    SSLProxyEngine on
#    SSLCertificateFile /path/to/ssl.crt/server.crt
#    SSLCertificateKeyFile /path/to/ssl.key/server.key
# </VirtualHost>
# 
#-----------------------------------------------------------------------

package Apache2::UriProxy;
use 5.008;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.01';
our @ISA     = qw( );

use Apache2::Const qw(DECLINED SERVER_ERROR OK);     # import constants
use Apache2::URI;
use APR::URI;

my(@Mappings,%Mappings);
my $DEBUG = 0;

sub handler
{   my( $r ) = @_;

    return DECLINED if $r->proxyreq();   # don't re-proxy if already proxied

    if (!@Mappings) {
	(@Mappings) = split /\s*(?:,|=>)\s*/, $r->dir_config('PerlUriProxy');

	if (@Mappings & 1) {             # this means a config file error
	    $r->log_reason("odd number of map entries: '@Mappings' in $PACK");
	    return SERVER_ERROR;
	}
	# Not really an error, just log a debug notice:
	## $r->log_error("DEBUG: map: '@Mappings'") if $DEBUG;

	%Mappings = ( @Mappings );       # create hash of URL map(s)
    }

    #-------------------------------------------
    # Note: To obtain components of the orig URL request (e.g., 'scheme',
    # host, port, arguments, etc...) the *exact* calling sequence shown
    # below must be used. See the following classes for further details.
    # .  APR::URI
    # .  Apache2::URI 
    # .  Apache2::RequestRec
    #-------------------------------------------

    my $uri      = $r->uri();           # collect the orig request path
    my $origUri  = $uri;                # copy the orig request path

    for my $src (keys %Mappings) {
	next unless $uri =~ s/^$src/$Mappings{$src}/;    # test/Modify URI

        #----------------------------------------------------------
	# Next, parse the *full* original URL. Make sure to collect
	# the URL arguments, if any, *before* calling parse_uri()
	# as the '$origUrl' does not yet contain the orig args!
	#
	my $origUrl  = $r->construct_url();     # see Apache2::URI
	## $hostPort = $r->construct_server();  # see Apache2::URI

	my $origArgs = $r->args();              # see Apache2::URI


	$r->parse_uri( $origUrl );              # see Apache2::URI
	my $r_parsed_uri = $r->parsed_uri();    # see Apache2::URI

	if ($origArgs) {      # retain any args from the orig URL
	    $origUrl .= '?' . $origArgs;
	    $uri     .= '?' . $origArgs;
	}

        #----------------------------------------------------------
	# One more check...make sure the two URI 'schemes' are the
	# same. Do not proxy 'https' to 'http' or vice-versa. Also,
	# allow for a missing scheme in the target of the mapping.
	# (Scheme is NOT the 'protocol' [HTTP 1.0, HTTP 1.1, etc],
	# NOR is this the 'authentication scheme' [Basic, etc]. See 
	# pgs. 478 and 479 in the "Writing Apache Modules" book.)
	#
	my $origScheme = $r_parsed_uri->scheme() ||"";
	my($newScheme) = $uri =~ m#^([^:]*)://#;

	if (! $newScheme) {
	    # Here we allow for incomplete mappings, and
	    # will use the orig scheme for the proxy. 
	    # E.g.:   '/orig/path/ => host.domain:port/new/path'

	    $uri = $origScheme ."://". $uri;
	    $newScheme = $origScheme;

	} elsif ( $newScheme ne $origScheme ) {
	    # Do not proxy 'https' to 'http' or vice-versa.
	    $r->log_reason("Will not proxy '$origUrl' ($origScheme) to '$uri' ($newScheme)");
	    return SERVER_ERROR;
	}

        #----------------------------------------------------------
	# Here we set up the proxy request and then simply return.
	# See brief example in the Apache2::RequestRec class at URL
	# http://perl.apache.org/docs/2.0/api/Apache2/RequestRec.html
	# (near the bottom in the 'proxyreq' section under 'API').

	$r->proxyreq(1);                # turn into proxy request
	$r->uri( "$uri" );              # rewrite the modified URI
	$r->filename( "proxy:$uri" );   # special mod_proxy syntax
	$r->handler('proxy-server');    # set content-handler

	# Not really an error, just log a debug notice:
	# (how does one create an 'access log' entry with mod_perl??)
	#
	$r->log_error("DEBUG: proxy/redirect '$origUrl' to '$uri'")  if $DEBUG;

     ## Hmmm... can we also forward to another proxy?? This would be
     ## nice to know, but it's not a big deal for this app if we can't
     ##	$r->uri('http://web-proxy.cup.hp.com:8080');
     ##	$r->filename('proxy:http://web-proxy.cup.hp.com:8080');

	return OK;
    }

    # If the URI did not match any proxy mapping(s), simply
    # decline to process the current request.
    #
    return DECLINED;
}
#_________________________
1; # Required by require()

__END__

=head1 NAME

Apache2::UriProxy - Proxy Apache URIs to PSD Server (with two alternatives)

=head1 VERSION

This document describes version 0.01, released March, 2007.


=head1 SYNOPSIS

 [--------------------------------------------------------------------]
 [ This is prototype software -- not yet intended for production use. ]
 [--------------------------------------------------------------------]

=head1 DESCRIPION



=head1 WARNINGS

 [--------------------------------------------------------------------]
 [ This is prototype software -- not yet intended for production use. ]
 [--------------------------------------------------------------------]

If you are sending passwords across the network you will surely want to
use SSL to communicate between the client (browser or script) and server
(Apache and/or PSD server).

=head1 AUTHOR

Chris Cobb, E<lt>nospamplease@ccobb.netE<gt>


=head1 COPYRIGHT

Copyright (c) 2006-2007 by Chris Cobb. All rights reserved. 
This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut

