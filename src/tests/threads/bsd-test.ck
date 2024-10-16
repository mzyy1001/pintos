# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(bsd-test) begin
(bsd-test) Thread nice -10 with nice -10 has recent_cpu: -1000 and priority: 63
(bsd-test) Thread nice -5 with nice -5 has recent_cpu: −500 and priority: 63
(bsd-test) Thread nice 0 with nice 0 has recent_cpu: 0 and priority: 63
(bsd-test) Thread nice 5 with nice 5 has recent_cpu: 500 and priority: 51
(bsd-test) Thread nice 10 with nice 10 has recent_cpu: 1000 and priority: 40
(bsd-test) Final system load_avg: 1
(bsd-test) end
EOF
pass;