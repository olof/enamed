#!/usr/bin/perl
# Lolconv is a laughable attempt at generating a coverage report,
# for erlang (and eunit), soley based on the name of the tests
# and the name of the function it should test.
#
# It will report any function that doesn't have a corresponding
# unit test function. Let's say your function is called foo, then
# you should create a function called foo_test or foo_test_ as
# well.

use 5.010;
use strict;
use warnings FATAL => 'all';

my %funcs;

my $func_re = qr{^(\S+)\([^)]+\)\s+->};
my $test_re = qr{^(\S+)_test_?\(\)\s+->};

while(<>) {
	$funcs{$1}->{test} = 1 if /$test_re/;
	$funcs{$1}->{func} = 1 if /$func_re/;
}

for my $func (grep {
	$funcs{$_}->{func} and not $funcs{$_}->{test}
} keys %funcs) {
	say $func;
}
