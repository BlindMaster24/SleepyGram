# Bundled SQLCipher

`sqlite3.c` and `sqlite3.h` come from SQLCipher Community v4.20.0 (SQLite
3.54.1), commit `355d4db92d3404e71faa8088d071a71d767807f4`. They are the
unmodified output of the upstream amalgamation generator.

- [Upstream release](https://github.com/sqlcipher/sqlcipher/releases/tag/v4.20.0)
- [Pinned source archive](https://codeload.github.com/sqlcipher/sqlcipher/tar.gz/355d4db92d3404e71faa8088d071a71d767807f4)
- [SQLCipher license at the pinned revision](https://github.com/sqlcipher/sqlcipher/blob/355d4db92d3404e71faa8088d071a71d767807f4/LICENSE.md)
- [SQLite notices at the pinned revision](https://github.com/sqlcipher/sqlcipher/blob/355d4db92d3404e71faa8088d071a71d767807f4/SQLITE_LICENSE.md)

## Generation

Verify the source archive digest before extracting it. Run the generator in a
separate build directory with `source_dir` set to the extracted directory and
`openssl_prefix` set to the installed OpenSSL 3. The upstream build uses its
bundled Jim Tcl for code generation with these options.

```sh
CC=clang CFLAGS="-O2 -g0" CPPFLAGS="-I${openssl_prefix}/include" \
  LDFLAGS="-L${openssl_prefix}/lib" LIBS="-lcrypto" \
  "${source_dir}/configure" --disable-tcl --with-tempstore=yes
make sqlite3.c sqlite3.h
```

| File | SHA-256 |
| --- | --- |
| Source archive | `fc5394c916beeabb1f43e2ac97d0827f36e8917f6675a00cca54537c32cb36a2` |
| `sqlite3.c` | `8cd2347d18886fee4651153fabeeeffb7cec008700987dab1c00261febc4220f` |
| `sqlite3.h` | `e36eb6ed4de77e56a633866a8f84ed339785662d0cf79cf099f420b638bf28ec` |
| `LICENSE-SQLCipher.txt` (upstream `LICENSE.md`) | `2a2826f6acf46fa650730cf42cbb22a642be33a7ef119c9c4f4bf6daf3bef48e` |
