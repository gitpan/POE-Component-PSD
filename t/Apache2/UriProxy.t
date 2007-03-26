#########################

use Test::More tests => 1;

TODO: {
    local $TODO = "will fail unless newer mod_perl installed";
    { use_ok('Apache2::UriProxy') };
}

#########################
