# -*- Perl -*-
#
# File:  Makefile.PL
# Desc:  Make the makefile for POE-Component-PSD
# Date:  Sat Mar 24 08:16:01 2007
#
use inc::Module::Install;

name		'POE-Component-PSD';
author		'Chris Cobb <nospamplease@ccobb.net>';
license 	'perl';
all_from	'lib/POE/Component/PSD/Server.pm';
tests		't/*/*.t  t/*/*/*/*.t  t/*/*/*/*/*.t';  # (inc. t/Apache*/*.t)
##tests		't/*/*/*/*.t t/*/*/*/*/*.t';           # (excl. t/Apache*/*.t)

# When building this distribution
#no_index	directory 	=> 'eg';
build_requires	Test::More	=> 0;

# Standard modules needed
requires	CGI		=> 0;
requires	Exporter	=> 0;
requires	Carp		=> 0;
requires	Fcntl		=> 0;
requires	POSIX		=> 0;
requires	strict		=> 0;
requires	warnings	=> 0;

# Additional modules needed
requires	Apache::Admin::Config 	=> 0;
requires 	Date::Format		=> 2.22;
requires 	Date::Parse		=> 2.23;
requires	Digest::MD5		=> 0;
requires 	Getopt::Long		=> 2.17;
requires	IO::Socket::SSL		=> 0;
requires	FileHandle    		=> 0;
requires	POE			=> 0;
requires	POE::Component::Server::SimpleHTTP	=> 0;
requires	POE::Component::SSLify	=> 0;
requires	PTools::Local		=> 0;

# optional	Apache::Constants	=> 0;    # for mod_perl 1.x
# optional	Apache::URI		=> 0;    # for mod_perl 1.x

# optional	Apache2::Const		=> 0;    # for mod_perl 1.99
# optional	Apache2::URI		=> 0;    # for mod_perl 1.99
# optional	APR::URI		=> 0;    # for mod_perl 1.99

WriteAll();
