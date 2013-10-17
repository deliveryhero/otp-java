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
package de.devsurf.security.otp.api;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

import de.devsurf.security.otp.api.Otp.OtpAdapter;
import de.devsurf.security.otp.api.internal.Hex;

/**
 * @author Daniel Manzke
 */
public class Motp
    extends OtpAdapter {
    private static final long serialVersionUID = 3164522944038490813L;

    private final String pin;

    /**
     * Initialize an OTP instance with the shared secret generated on Registration process
     * 
     * @param secret Shared secret
     */
    public Motp( String pin, String secret ) {
        this( Motp.configure( secret, pin ) );
    }

    public Motp( MotpConfig config ) {
        super( config );
        this.pin = config.pin;
    }

    /**
     * Verifier - To be used only on the server side
     * <p/>
     * Taken from Google Authenticator with small modifications from {@see <a href=
     * "http://code.google.com/p/google-authenticator/source/browse/src/com/google/android/apps/authenticator/PasscodeGenerator.java?repo=android#212"
     * >PasscodeGenerator.java</a>}
     * <p/>
     * Verify a timeout code. The timeout code will be valid for a time determined by the interval period and the number
     * of adjacent intervals checked.
     * 
     * @param otp Timeout code
     * @return True if the timeout code is valid
     *         <p/>
     *         Author: sweis@google.com (Steve Weis)
     */
    @Override
    protected String hash( long epoch ) {
        try {
            String base = Long.toString( epoch ) + new String( key, Charset.forName( "UTF-8" ) ) + pin;
            byte[] bytes = hash.digest( base.getBytes( "UTF-8" ) );

            return Hex.encode( bytes ).substring( 0, digits.getLength() );
        }
        catch ( NoSuchAlgorithmException e ) {
            e.printStackTrace();
            return "";
        }
        catch ( UnsupportedEncodingException e ) {
            e.printStackTrace();
            return "";
        }
    }

    public static MotpConfig configure( String pin, String secret ) {
        return new MotpConfig().pin( pin ).secret( secret );
    }

    public static class MotpConfig
        extends OtpConfig<Motp, MotpConfig> {
        private String pin;

        protected MotpConfig() {
            super();
            this.hash = Hash.MD5;
            this.clock = new Clock( 10 );
            this.digits = Digits.SIX;
            this.tolerance = 3;
        }

        public MotpConfig pin( String pin ) {
            this.pin = pin;
            return this;
        }

        @Override
        public MotpConfig inherit( Motp otp ) {
            this.hash = otp.hash;
            this.clock = otp.clock;
            this.digits = otp.digits;
            this.tolerance = otp.delayWindow;
            this.key = otp.key;
            this.pin = otp.pin;

            return this;
        }

        @Override
        public MotpConfig clock( Clock clock ) {
            clock.interval = 10;
            return super.clock( clock );
        }

        @Override
        public MotpConfig secret( String secret ) {
            this.key = secret.getBytes( Charset.forName( "UTF-8" ) );
            return this;
        }

        @Override
        public MotpConfig self() {
            return this;
        }

        public Motp build() {
            return new Motp( this );
        }
    }
}
