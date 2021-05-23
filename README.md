# baSHA12

Low speed SHA1/2 message digest in Bash

### What's this?

This is an implementation of [**MD5**](https://en.wikipedia.org/wiki/MD5), [**SHA1**](https://en.wikipedia.org/wiki/SHA-1) and [**SHA2**](https://en.wikipedia.org/wiki/SHA-2) message digest algorithms, using only pure [**bash**](https://tiswww.case.edu/php/chet/bash/bashtop.html) without any external programs. No dependencies, other than a recent version of bash.

[**SHA3**](https://en.wikipedia.org/wiki/SHA-3) is an entirely different beast and is not supported here (but who knows in the future...).

**WARNING: THIS IS EXTREMELY SLOW AND INEFFICIENT. DO NOT USE IT FOR ANY SERIOUS PURPOSE, AND DO NOT USE IT ON LARGE AMOUNTS OF DATA (EVEN _A FEW TENS_ OF KB ARE ALREADY A LOT FOR THIS BEAST). YOU HAVE BEEN WARNED.**

### Why is it "low speed"?

See the following comparison with [openssl](https://www.openssl.org/) to calculate the SHA2-512 digest of a ~50K file:

<pre><code>
$ <b>ls -l /bin/cmp</b>
-rwxr-xr-x 1 root root 51856 Apr  8  2019 /bin/cmp
$ <b>time openssl sha512 /bin/cmp > /dev/null</b>

real	0m0.016s
user	0m0.007s
sys	0m0.008s
$ <b>time ./sha512.sh < /bin/cmp > /dev/null</b>

real	1m29.471s
user	1m29.397s
sys	0m0.071s
</code></pre>

### How do I install it?

Just run the `sha*.sh` script that you want/need, feeding input on stdin (so use pipes or redirections). Sample run:

<pre><code>
$ <b>echo foobarbazzz12345 | ./sha1.sh</b>
2654fedc3cbf3add0a1a49b8fd8ae735013f4973
</code></pre>

### Testing

If you feel masochistic, there are some test scripts inside the `tests/` directory. Just run the one(s) you want from the root of the repo.
