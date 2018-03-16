
# OTP library for Java

This is a fork of the [original repository](https://github.com/manzke/otp-java) from Daniel Manzke, which
has been used in production environments already.

Still there doesn't exist a full-blown and supported OTP library for Java. Aerogear OTP is deprecated
and lacks a lof of functionality, `otp-java` provides. Since there's no official artifact of this
available on maven central, we simply forked it to publish artifacts to our internal maven repository.

`java-otp` supports TOTP, MOTP and GTOTP and allows customization regarding hash algorithms and
tolerance intervals.

The original [README] has been left intact.
