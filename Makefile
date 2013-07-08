export LANG=C
.PHONY: test clean

ERLC ?= erlc
ERL ?= erl

# For now, every beam file depends on every header file.. :(
HEADERS = dnspkt.hrl

ERLCFLAGS += -Werror

MODULES = enamed dnspkt

GENERATED_FILES = \
	$(addsuffix .beam, $(MODULES)) \
	erl_crash.dump \
	readme.html

all: $(addsuffix .beam, $(MODULES))

test: dnspkt.beam
	$(ERL) -noshell -run dnspkt test -s init stop

clean:
	$(RM) $(GENERATED_FILES)

%.beam: %.erl $(HEADERS)
	$(ERLC) $(ERLCFLAGS) $<
