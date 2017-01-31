# erl_tar2

This is a reimplementation of `erl_tar` from the Erlang standard library, the following changes
have been made:

- Support for reading archives in v7, STAR, USTAR, GNU-tar, and PAX formats
- Support for reading archives using the GNU tar sparse files extension
- Creating new archives will now automatically upgrade headers to PAX format if
the file being added requires it due to restrictions in older formats (such as
the filename limitation of v7, STAR, and USTAR formats).

This is a large set of changes from the original `erl_tar` module - while there is numerous places
where old code has been reused, the vast majority of it is brand new. This repository is here
for reference, as well as to make working on the code easier for me.

The end goal is to get these changes merged into OTP itself.

# TODO

- [x] Run test suite for erl_tar
- [x] Clean up formatting
  - [x] Try to fit all lines within 80 chars
  - [x] Consistent typespecs
- [x] Create test suite for erl_tar
- [x] Run dialyzer, update accordingly
- [ ] Update documentation, comments
- [ ] Open PR with as much detail as possible for discussion
