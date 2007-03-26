#########################

use Test::More tests => 1;

TODO: {
    local $TODO = "will fail unless older mod_perl installed";
    { use_ok('Apache::UriProxy') };
}
#########################
