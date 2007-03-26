#!/opt/perl/bin/perl -T
#
# File:  psdServer.pl
# Desc:  Run the Persistent Session Daemon Web service
# Stat:  Prototype, Experimental
#
use Cwd;
BEGIN {  # Script is relocatable. See http://ccobb.net/ptools/
  my $cwd = $1 if ( $0 =~ m#^(.*/)?.*# );  chdir( "$cwd/.." );
  my($top,$app)=($1,$2) if ( getcwd() =~ m#^(.*)(?=/)/?(.*)#);
  $ENV{'PTOOLS_TOPDIR'} = $top;  $ENV{'PTOOLS_APPDIR'} = $app;
} #-----------------------------------------------------------
use PTools::Local;          # PTools local/global vars/methods

my $config = PTools::Local->path('app_cfgdir', "psd_min.conf");

use POE::Component::PSD::Server;
run POE::Component::PSD::Server( $config );
exit(0);

# die "Config file: $config\n";
# warn PTools::Local->dump('vars');
# die PTools::Local->dump('inclibs,incpaths');
