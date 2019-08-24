# GSoC 2019: Dual-stack ping command

The main goals were to merge ping6 into ping, remove code duplication and make the code more maintainable while not changing stdout output. The code was moved, compartmentalized, and modified rather than rewritten. Thus, the new ping command should be fully functional. Usage information can be found in the new manual page.

## How the work was done

During the first two phases I worked on my branch hosted on GitHub. I communicated with my mentor mainly by comments of the commits. In the third phase I started using FreeBSD's Phabricator for a code review to get feedback from the community and to the code merged into FreeBSD.

## What work was done

Major changes:

- It's possible to build IPv4-only, IPv6-only, and IPv4-IPv6 version.
- All the code including the tests is built with WARNS=6.
- Major code duplications were eliminated (option parsing, initialization, signal handling, the pinger loop, macros, helper functions, manual pages).
- Some of the options of ping6 were renamed for better consistency with ping. Equivalent options have the same flags, and nonequivalent options have different flags. Options of ping have not been changed.
- Use of global variables was eliminated. The variables were either made local or were grouped to a global structures.
- The code was compartmentalized into smaller separate source files. Unused code was removed.
- Capsicum and Casper support was added for IPv6 ping code.
- Option parsing is extensively tested using ATF C tests.
- The Internet checksum function in_cksum() is tested using ATF C tests.
- Basic functionality of ping is tested using ATF sh tests.
- Function arguments were constified where possible.
- More functions have their return value checked.
- Dynamically allocated resources are freed in case of successful exit.
- The program exits only in main.c.

Minor changes:

- More of [style(9)](https://www.freebsd.org/cgi/man.cgi?query=style&sektion=9) conformance (spaces, line width, comments, ...).
- Unnecessary comments were removed.
- Unused variables were removed.
- Obsoleted `alarm()` was replaced with `setitimer()`.
- `putchar()` calls were replaced with `printf()`.
- `u_intXX_t` types were replaced with `uintXX_t`.
- Scope of local variables were reduced were possible heeding style(9).
- Use of sysexits(3) exit codes was removed.
- IEEE legacy `bzero()` and `bcopy()` were replaced with `memset()` and `memcpy()` respectively.
- Errors in the manual page, which were detected by `igor` and `mandoc -Tlint`, were fixed.

## What code got merged

- ping: Fix alignment errors ([351440](https://svnweb.freebsd.org/base?view=revision&revision=351440))
- ping: fix include guard symbol name to reflect the header file name ([351424](https://svnweb.freebsd.org/base?view=revision&revision=351424))
- ping: By default, don't reverse lookup IP addresses ([351398](https://svnweb.freebsd.org/base?view=revision&revision=351398))
- ping: add a basic functional test ([351393](https://svnweb.freebsd.org/base?view=revision&revision=351393))
- ping: add -H option for enabling reverse DNS lookup ([351354](https://svnweb.freebsd.org/base?view=revision&revision=351354))
- ping: do reverse DNS lookup of the target address ([351330](https://svnweb.freebsd.org/base?view=revision&revision=351330))
- ping: Add tests of the Internet checksum function ([351318](https://svnweb.freebsd.org/base?view=revision&revision=351318))
- Fix uninitialized variable warnings when MK_CASPER=no ([351226](https://svnweb.freebsd.org/base?view=revision&revision=351226))
- ping: fix -Wformat-truncating warning with GCC ([351223](https://svnweb.freebsd.org/base?view=revision&revision=351223))
- ping: Move in_cksum() to a separate source file ([351171](https://svnweb.freebsd.org/base?view=revision&revision=351171))
- ping: Make in_cksum() operate on u_char buffer ([351033](https://svnweb.freebsd.org/base?view=revision&revision=351033))
- ping: fix triptime calculation after r350998 ([351030](https://svnweb.freebsd.org/base?view=revision&revision=351030))
- ping: use the monotonic clock to measure durations ([350998](https://svnweb.freebsd.org/base?view=revision&revision=350998))
- ping: fix data type of a variable for a packet sequence number ([350994](https://svnweb.freebsd.org/base?view=revision&revision=350994))
- ping6: Rename options for better consistency with ping ([351423](https://svnweb.freebsd.org/base?view=revision&revision=351423))
- ping6: add a basic functional test ([351394](https://svnweb.freebsd.org/base?view=revision&revision=351394))
- ping6: revert r350857 ([351216](https://svnweb.freebsd.org/base?view=revision&revision=351216))
- ping6: Raise WARNS level to 6 ([351172](https://svnweb.freebsd.org/base?view=revision&revision=351172))
- ping6: Fix dnsdecode() bug introduced by r350859 ([351170](https://svnweb.freebsd.org/base?view=revision&revision=351170))
- ping6: Fix alignment errors ([351102](https://svnweb.freebsd.org/base?view=revision&revision=351102))
- ping6: fix uninitialized variable warnings when MK_CASPER=no ([351101](https://svnweb.freebsd.org/base?view=revision&revision=351101))
- ping6: Fix data type of the buffer for ancillary data of a received message ([351090](https://svnweb.freebsd.org/base?view=revision&revision=351090))
- ping6: fix uninitialized variable warning for intvl ([351082](https://svnweb.freebsd.org/base?view=revision&revision=351082))
- ping6: quiet an undefined variable warning ([351080](https://svnweb.freebsd.org/base?view=revision&revision=351080))
- ping6: quiet warning about unused copyright variable ([351079](https://svnweb.freebsd.org/base?view=revision&revision=351079))
- ping6: use the monotonic clock to measure durations ([350997](https://svnweb.freebsd.org/base?view=revision&revision=350997))
- Consistently use the byteorder functions in the correct direction ([350993](https://svnweb.freebsd.org/base?view=revision&revision=350993))
- ping6: Fix data type of a variable for a packet sequence number ([350987](https://svnweb.freebsd.org/base?view=revision&revision=350987))
- ping6: Remove unnecessary level of indirection from dnsdecode() parameter ([350859](https://svnweb.freebsd.org/base?view=revision&revision=350859))
- ping6: Add missing static keyword for a global variable ([350858](https://svnweb.freebsd.org/base?view=revision&revision=350858))
- ping6: Revoke root privilege earlier ([350857](https://svnweb.freebsd.org/base?view=revision&revision=350857))
- ping6: Capsicumize ping6 ([350556](https://svnweb.freebsd.org/base?view=revision&revision=350556))

## What's left to do

Most of the code has not been merged to FreeBSD yet.

## Conclusion
