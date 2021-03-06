[![Build Status](https://travis-ci.org/tpltnt/go-bsm.svg?branch=master)](https://travis-ci.org/tpltnt/go-bsm)

# go-bsm

This is a parser for the FreeBSD audit file format (based on Sun's Basic Security Module (BSM) file format).
It can be installed by running `go install github.com/tpltnt/go-bsm`.

# caveat
This tool uses a dirty handwritten parser for binary files. This was done because yacc wasn't available as
a tool for Go (as of beginning of 2018) and ANTLv4 requires Java.

# TODO
* parse all tokens
* rewrite using parser combinators

# references
* [audit.log(5)](https://www.freebsd.org/cgi/man.cgi?query=audit.log&apropos=0&sektion=0&arch=default&format=html)
* [FreeBSD handbook Chapter 16: Security Event Auditing](https://www.freebsd.org/doc/handbook/audit.html)
* [TrustedBSD OpenBSM](http://trustedbsd.org/openbsm.html) - [github repository](https://github.com/openbsm/openbsm)
* [Forensics Wiki: Basic Security Module (BSM) file format](http://forensicswiki.org/wiki/Basic_Security_Module_(BSM)_file_format)
* [SunSHIELD Basic Security Module Guide (pdf)](https://docs.oracle.com/cd/E19457-01/801-6636/801-6636.pdf)
