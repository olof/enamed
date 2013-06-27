export LANG=C
.PHONY: test clean

ERLC ?= erlc
ERL ?= erl

MODULES = dnspkt listener

GENERATED_FILES = \
	$(addsuffix .beam, $(MODULES)) \
	erl_crash.dump \
	readme.html

all: $(addsuffix .beam, $(MODULES))

test: dnspkt.beam
	$(ERL) -noshell -run dnspkt test -s init stop

clean:
	$(RM) $(GENERATED_FILES)

%.beam: %.erl
	$(ERLC) $<
