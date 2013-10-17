/*
Copyright 2013 Daniel Manzke (devsurf)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
package de.devsurf.security.otp.api.internal;

import de.devsurf.security.otp.api.Digits;

public class Util {
    public static int bytesToInt( byte[] hash, Digits digits ) {
        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary =
            ( ( hash[offset] & 0x7f ) << 24 ) | ( ( hash[offset + 1] & 0xff ) << 16 )
                | ( ( hash[offset + 2] & 0xff ) << 8 ) | ( hash[offset + 3] & 0xff );

        return binary % digits.getValue();
    }

    public static String leftPadding( int otp, Digits digits ) {
        return String.format( "%0" + digits.getLength() + "d", otp );
    }
}
