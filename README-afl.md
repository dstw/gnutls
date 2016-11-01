# Testing GnuTLS with AFL

There is a limited test suite for parts of GnuTLS against American Fuzzy Lop
(AFL). This is located on ```tests/suite/afl``` and is built by default when
building from the master repository.


The following instructions are to demonstrate running the test for DN
decoding.

```
$ CC=afl-gcc ./configure --disable-doc --with-included-libtasn1
$ make
$ cd tests/suite/afl
$ make && ./afl-dn.sh
```
