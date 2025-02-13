PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
LIBDIR ?= ${PREFIX}/lib
SHAREDIR ?= ${PREFIX}/share
EXAMPLESDIR ?= ${SHAREDIR}/examples

MANDIR.${PREFIX} = ${PREFIX}/share/man
MANDIR./usr/local = /usr/local/man
MANDIR. = /usr/share/man
MANDIR ?= ${MANDIR.${PREFIX}}

.PHONY: all install test distrib

all: target/release/pizauth

target/release/pizauth:
	cargo build --release

PLATFORM=$(shell uname)

install: target/release/pizauth
	install -d ${DESTDIR}${BINDIR}
	install -c -m 555 target/release/pizauth ${DESTDIR}${BINDIR}/pizauth
	install -d ${DESTDIR}${MANDIR}/man1
	install -d ${DESTDIR}${MANDIR}/man5
	install -c -m 444 pizauth.1 ${DESTDIR}${MANDIR}/man1/pizauth.1
	install -c -m 444 pizauth.conf.5 ${DESTDIR}${MANDIR}/man5/pizauth.conf.5
	install -d ${DESTDIR}${EXAMPLESDIR}/pizauth
	install -c -m 444 examples/pizauth.conf ${DESTDIR}${EXAMPLESDIR}/pizauth/pizauth.conf
	install -d ${DESTDIR}${SHAREDIR}/bash-completion/completions
	install -c -m 444 share/bash/completion.bash ${DESTDIR}${SHAREDIR}/bash-completion/completions/pizauth
	install -d ${DESTDIR}${SHAREDIR}/fish/vendor_completions.d
	install -c -m 444 share/fish/pizauth.fish ${DESTDIR}${SHAREDIR}/fish/vendor_completions.d
ifeq ($(PLATFORM), Linux)
	install -d ${DESTDIR}${LIBDIR}/systemd/user
	install -c -m 444 lib/systemd/user/pizauth.service ${DESTDIR}${LIBDIR}/systemd/user/pizauth.service
	install -d ${DESTDIR}${EXAMPLESDIR}/pizauth/systemd-dropins
	install -c -m 444 examples/systemd-dropins/age.conf ${DESTDIR}${EXAMPLESDIR}/pizauth/systemd-dropins/age.conf
	install -c -m 444 examples/systemd-dropins/gpg-dump.conf ${DESTDIR}${EXAMPLESDIR}/pizauth/systemd-dropins/gpg-dump.conf
endif

test:
	cargo test
	cargo test --release

distrib:
	test "X`git status --porcelain`" = "X"
	@read v?'pizauth version: ' \
	  && mkdir pizauth-$$v \
	  && cp -rp Cargo.lock Cargo.toml COPYRIGHT LICENSE-APACHE LICENSE-MIT \
	    Makefile CHANGES.md README.md build.rs pizauth.1 pizauth.conf.5 \
	    examples lib share src pizauth-$$v \
	  && tar cfz pizauth-$$v.tgz pizauth-$$v \
	  && rm -rf pizauth-$$v
