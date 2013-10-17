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

public class Hex {
    public static final char[] DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
        'F' };

    public static String encode( byte[] raw ) {
        int length = raw.length;
        char[] hex = new char[length * 2];
        for ( int i = 0; i < length; i++ ) {
            int value = ( raw[i] + 256 ) % 256;
            int highIndex = value >> 4;
            int lowIndex = value & 0x0f;
            int j = i * 2;
            hex[j + 0] = DIGITS[highIndex];
            hex[j + 1] = DIGITS[lowIndex];
        }
        return new String( hex );
    }
}
