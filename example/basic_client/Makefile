REBAR = $(shell pwd)/rebar3
APP=oidcc

.PHONY: all ct test clean elvis compile

all: compile

clean:
	$(REBAR) clean
	rm -f rebar.lock
	rm -rf _build

oidcc_psycho_dev:
	cp -r ../../src/* _build/default/lib/oidcc_psycho/src
	rm -rf _build/default/lib/oidcc_psycho/ebin

compile:
	$(REBAR) compile

run:
	$(REBAR) run


run-dev: oidcc_psycho_dev
	$(REBAR) run
