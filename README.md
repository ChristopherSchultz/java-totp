# java-totp

An implementation of the Time-Based One-Time Password Algorithm described in [RFC 6238](https://tools.ietf.org/html/rfc6238).

You can use java-totp in your code easily to check a TOTP token for validity:

    TimeBasedOneTimePassword totp = new TimeBasedOneTimePassword();
    String seed = "3132333435363738393031323334353637383930";
    String token = [read from user];
    if(!totp.isValid(seed, token)) {
        // HCF
    }

## Building

Use Maven

    mvn package

