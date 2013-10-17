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

import static de.devsurf.security.otp.api.internal.Util.bytesToInt;
import static de.devsurf.security.otp.api.internal.Util.leftPadding;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

import de.devsurf.security.otp.api.internal.Hmac;

public interface Otp
    extends Serializable {

    int DEFAULT_DELAY_WINDOW = 1;

    String now();

    boolean verify( String otp );

    public static abstract class OtpAdapter
        implements Otp {
        private static final long serialVersionUID = 223637555064879264L;

        protected final Clock clock;

        protected final Digits digits;

        protected final Hash hash;

        protected final int delayWindow;

        protected final byte[] key;

        public <ConfigType extends OtpConfig<?, ?>> OtpAdapter( ConfigType config ) {
            this.clock = config.clock;
            this.digits = config.digits;
            this.hash = config.hash;
            this.key = config.key;
            this.delayWindow = config.tolerance;
        }

        /**
         * Retrieves the current OTP
         * 
         * @return OTP
         */
        public String now() {
            return hash( clock.getCurrentInterval() );
        }

        /**
         * Verifier - To be used only on the server side
         * <p/>
         * Taken from Google Authenticator with small modifications from {@see <a href=
         * "http://code.google.com/p/google-authenticator/source/browse/src/com/google/android/apps/authenticator/PasscodeGenerator.java?repo=android#212"
         * >PasscodeGenerator.java</a>}
         * <p/>
         * Verify a timeout code. The timeout code will be valid for a time determined by the interval period and the
         * number of adjacent intervals checked.
         * 
         * @param otp Timeout code
         * @return True if the timeout code is valid
         */
        public boolean verify( String otp ) {
            // make sure everything is in uppercase
            otp = otp.toUpperCase( Locale.ENGLISH );
            long currentInterval = clock.getCurrentInterval();

            int pastResponse = Math.max( delayWindow, 0 );

            for ( int i = pastResponse; i >= 0; --i ) {
                String candidate = hash( currentInterval - i );
                if ( otp.equals( candidate ) ) {
                    return true;
                }
            }

            return false;
        }

        protected String hash( long interval ) {
            byte[] bytes = new byte[0];
            try {
                byte[] challenge = ByteBuffer.allocate( 8 ).putLong( interval ).array();
                bytes = new Hmac( hash, key ).digest( challenge );
            }
            catch ( NoSuchAlgorithmException e ) {
                e.printStackTrace();
                return "";
            }
            catch ( InvalidKeyException e ) {
                e.printStackTrace();
                return "";
            }

            return leftPadding( bytesToInt( bytes, digits ), digits );
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ( ( clock == null ) ? 0 : clock.hashCode() );
            result = prime * result + delayWindow;
            result = prime * result + ( ( digits == null ) ? 0 : digits.hashCode() );
            result = prime * result + ( ( hash == null ) ? 0 : hash.hashCode() );
            result = prime * result + Arrays.hashCode( key );
            return result;
        }

        @Override
        public boolean equals( Object obj ) {
            if ( this == obj ) return true;
            if ( obj == null ) return false;
            if ( getClass() != obj.getClass() ) return false;
            OtpAdapter other = (OtpAdapter) obj;
            if ( clock == null ) {
                if ( other.clock != null ) return false;
            } else if ( !clock.equals( other.clock ) ) return false;
            if ( delayWindow != other.delayWindow ) return false;
            if ( digits != other.digits ) return false;
            if ( hash != other.hash ) return false;
            if ( !Arrays.equals( key, other.key ) ) return false;
            return true;
        }

        @Override
        public String toString() {
            return "OtpAdapter [clock=" + clock + ", digits=" + digits + ", hash=" + hash + ", delayWindow="
                + delayWindow + ", key=***** ]";
        }
    }

    public static abstract class OtpConfig<OtpType extends Otp, ConfigType extends OtpConfig<OtpType, ConfigType>> {
        protected Digits digits = Digits.SIX;

        protected Hash hash = Hash.SHA1;

        protected byte[] key;

        protected Clock clock = new Clock.ExactClock();

        protected int tolerance = DEFAULT_DELAY_WINDOW;

        public static <OtpType extends Otp, ConfigType extends OtpConfig<OtpType, ConfigType>> ConfigType type( Class<ConfigType> type )
            throws InstantiationException {
            try {
                return type.newInstance();
            }
            catch ( IllegalAccessException e ) {
                throw new InstantiationException( e.getMessage() );
            }
        }

        protected OtpConfig() {}

        public abstract ConfigType self();

        public abstract OtpType build()
            throws Exception;

        public abstract ConfigType inherit( OtpType otp );

        public abstract ConfigType secret( String secret )
            throws Exception;

        public ConfigType tolerance( int tolerance ) {
            this.tolerance = tolerance;
            return self();
        }

        public ConfigType clock( Clock clock ) {
            this.clock = clock;
            return self();
        }

        public ConfigType digits( Digits digits ) {
            this.digits = digits;
            return self();
        }

        public ConfigType hash( Hash hash ) {
            this.hash = hash;
            return self();
        }
    }
}
