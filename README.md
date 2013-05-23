
mkpasswd:   a passphrase generator

            mkpasswd was inspired by the babble strings produced by the
            original Bellcore S/Key OTP generator - however, its purpose
            is merely to produce passwords with a promise of 66 bits of
            entropy (in the default configuration).  The dictionary differs
            from the original in that only 3- and 4-letter words are used.
            The security of the passphrases generated is reducible to the
            security of the underlying system RNG (e.g., /dev/random). Six
            words are selected at random from a dictionary of 2048 words,
            yielding 2^66 possible passphrases.

            To make passphrases more legible, the -s option inserts spaces,
            and the -d option inserts dashes.  It is up to the user whether
            to include these.

            Since the common Linux implementation of /dev/random blocks, a
            conditional compile for Linux has the program use /dev/urandom.
            This may reduce the security of passwords.  On FreeBSD and OS X
            /dev/random is of a different design, using a 256-bit variant of
            Yarrow when no hardware RNG is present, with support for hardware
            RNGs if available.
