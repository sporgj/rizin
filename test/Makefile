all: rz-test-tests unit_tests

bins:
	git clone --depth 1 https://github.com/rizinorg/rizin-testbins bins

fuzz/targets:
	git clone --depth 1 https://github.com/rizinorg/rizin-fuzztargets fuzz/targets

RUNTEST=rz-test ${RZ_TEST_ARGS} -L -o results.json

rz-test-tests: bins
	${RUNTEST}

fuzz-tests: bins
	rz-test -LF bins/fuzzed @fuzz

keystone: bins
	${RUNTEST} db/extras/asm/x86.ks_

swf: bins
	${RUNTEST} db/extras/cmd/swf

m68k-extras: bins
	${RUNTEST} db/extras/asm/m68k

mc6809: bins
	${RUNTEST} db/extras/asm/x86.udis

microblaze: bins
	${RUNTEST} db/extras/asm/microblaze.gnu

udis86: bins
	${RUNTEST} db/extras/asm/mc6809

olly-extras: bins
	${RUNTEST} db/extras/asm/x86.olly

dwarf: bins
	${RUNTEST} db/extras/asm/dwarf

yara: bins
	${RUNTEST} db/extras/cmd/yara

clean:
	rm -rf tmp

symstall:

install:

uninstall:

unit unit_tests: bins
	$(MAKE) -C unit
	$(MAKE) -C unit run

.PHONY: all clean unit install uninstall
