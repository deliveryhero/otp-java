# One-Time-Password (OTP) library for Java [![Build Status](https://travis-ci.org/deliveryhero/rps-otp-java.svg?branch=master)](https://travis-ci.org/deliveryhero/rps-otp-java)

This is a fork of the [original repository](https://github.com/manzke/otp-java) from Daniel Manzke, which
has been used in production environments already.

Still there doesn't exist a full-blown and supported OTP library for Java. Aerogear OTP is deprecated
and lacks a lof of functionality, `otp-java` provides. Since there's no official artifact of this
available on maven central, we simply forked it to publish artifacts to our internal maven repository.

`java-otp` supports TOTP, MOTP and GTOTP and allows customization regarding hash algorithms and
tolerance intervals.

The [original README](README) has been left intact.

## Examples

### TOTP

```
Totp totp = new Totp("mysecret");
String sixDigitTotp = totp.now();
boolean isValid = totp.verify(sixDigitTotp);
```

This will create a default TOTP with 6 digits, with an interval of 30 seconds (~TTL),
an interval tolerance of 1, using the given secret and SHA1 as hash algorithm.
A TOTP can be quickly checked using `verify(otp)` as well.

If different defaults should be used, you can provide a configuration to the constructor:

```
TotpConfig config = Totp.configure("mysecret");
config.clock(new ExactClock(60));
config.tolerance(0);
config.hash(Hash.SHA256);
config.digits(Digits.EIGHT);

Totp totp = new Totp(config);
String eightDigitTotp = totp.now();
```

This will create a TOTP with 8 digits using a 60 seconds interval with no tolerance using
the given secret and SHA256 as hash algorithm. 

*Note:* Be aware that the password length has to be 20, 32, or 64 characters long depending on the chosen
hash algorithm (SHA1, SHA256, SHA512).
