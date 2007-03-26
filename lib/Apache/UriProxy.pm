# -*- Perl -*-
#                                       ## for use with mod_perl 1.x ##
# File:  Apache/UriProxy.pm
# Desc:  Invokes mod_proxy for "internal" Non-proxy Requests
# Auth:  This module is based on the example by Stein, MacEachern, in
#        the book "Writing Apache Modules," Chap 7, Pub by O'Reilly.
# Stat:  Prototype, Experimental
#
# Note:  As of 09-Jun2006, a pertinent excerpt from Chap 7 of the
#        above mentioned book is available at the following URL.
#        http://www.infocopter.com/perl/mod_perl_proxy.htm 
#
# Synopsis:
#        # Config directive (httpd.conf, etc.)
#        #
#        PerlTransHandler  Apache::UriProxy
#        PerlSetVar PerlUriProxy '/session/ => https://foo.bar.com:12345/, \
#                                 /testSSL/ => https://foo.bar.com:12345/, \
#  # will use orig scheme here:   /testing/ =>         foo.bar.com:12344/'
#
#        From the above mentioned URL:
#        "The PerlUriProxy variable contains a string representing a 
#        series of URI=>proxy pairs, separated by commas. A backslash
#        at the end of a line can be used to split the string over
#        several lines, improving readability."
#
# Dependencies:
#        Apache, with the following modules
#        .  mod_perl
#        .  mod_proxy
#        .  mod_ssl    (optional, to proxy https:// URIs)
#
# Setup to proxy https:// URIs
#        .  add the following directives to the SSL virtual host
#             SSLProxyEngine on
#             SSLProxyMachineCertificateFile /path/to/server.cert
#
#        Note: This does work when the "server.cert" file used to proxy
#              *is* the same used in the "SSLCertificateFile" directive
#              (but is this a good idea? confirm this!)
#
#        FIX:  Check the scheme in the handler below to ensure
#              that, for HTTPS redirects, an "https://" URI *was* 
#              used in the *orig* URI. If not, fail the proxy!
#        

package Apache::UriProxy;
use 5.008;
use strict;
use warnings;

our $PACK    = __PACKAGE__;
our $VERSION = '0.01';
our @ISA     = qw( );

use Apache::Constants qw(:common);
use Apache::URI ();

sub handler
{   my( $r ) = @_;

    return DECLINED if $r->proxyreq();  # don't re-proxy if already proxied

    my(@mappings) = split /\s*(?:,|=>)\s*/, $r->dir_config('PerlUriProxy');

    if (@mappings & 1) {                # this means a config file error
	$r->log_reason("odd number of proxy map entries: '@mappings' in $PACK");
	return SERVER_ERROR;
    }
    my %mappings = ( @mappings );

    my $uri     = $r->uri();            # collect the orig request location
    my $origUri = $uri;

    #-------------------------------------------
    # Note: To obtain the original request 'scheme' (http,  https, etc),
    # must first use the following syntax to create a new URI object from
    # the current request object. This is NOT the 'protocol' (HTTP 1.0, 
    # HTTP 1.1, etc) NOR is this the 'authentication scheme' (Basic, etc).
    # See pgs. 478 and 479 in Chap 9 of the "Writing Apache Modules" book.
    #
    #   $newUri = Apache::URI->parse( $r );
    #   $scheme = $newUri->scheme();
    #-------------------------------------------

    for my $src (keys %mappings) {
	next unless $uri =~ s/^$src/$mappings{$src}/;    # test/Modify URI

	#$r->log_error("DEBUG: proxy $origUri to '$uri'");   # DEBUG
	my $unparsedUri   = $r->unparsed_uri();
	my $r_parsed_uri  = Apache::URI->parse( $r );
	my $origScheme    = $r_parsed_uri->scheme()   ||"";
	my $origPort      = $r_parsed_uri->port()     ||"";
	my $origHost      = $r_parsed_uri->hostname() ||"";

	$origUri = "$origScheme://$origHost:$origPort" . $unparsedUri;

	##-------------------------------------------
	my($newScheme) = $uri =~ m#^([^:]*)://#;

	if (! $newScheme) {
	    # Here we allow for incomplete mappings, and
	    # will use the orig scheme for the proxy. 
	    # E.g.:   '/redirect/ => host.domain:port'

	    $uri = $origScheme ."://". $uri;

	} elsif ( $newScheme ne $origScheme ) {
	    $r->log_reason("Will not proxy '$origUri' ($origScheme) to '$uri' ($newScheme)");
	    return SERVER_ERROR;
	}
	$r->log_error("DEBUG: proxy '$origUri' to '$uri'");   # DEBUG
	##-------------------------------------------

	$r->proxyreq(1);                # turn into proxy request
	$r->uri( "$uri" );              # rewrite the modified URI
	$r->filename( "proxy:$uri" );   # special mod_proxy syntax

     ## Hmmm... can we also forward to another proxy?? This would be
     ## nice to know, but it's not a big deal for this app if we can't
     ##	$r->uri('http://web-proxy.cup.hp.com:8080');
     ##	$r->filename('proxy:http://web-proxy.cup.hp.com:8080');

	$r->handler('proxy-server');         # set content-handler
	return OK;
    }

  # # DEBUG:
  # $r->log_reason("failed to match '$uri' in '@mappings'");
  # return SERVER_ERROR;

    return DECLINED;
}
#_________________________
1; # Required by require()

__END__

=head1 NAME

Apache::UriProxy - Proxy Apache URIs to PSD Server (with two alternatives)

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

