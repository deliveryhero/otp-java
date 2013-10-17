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
import java.net.URLEncoder;

import de.devsurf.security.otp.api.Otp.OtpAdapter;
import de.devsurf.security.otp.api.internal.Base32;

public final class GTotp
    extends OtpAdapter {

    private static final long serialVersionUID = -219290322726755187L;

    /**
     * Initialize an OTP instance with the shared secret generated on Registration process
     * 
     * @param secret Shared secret
     * @throws DecodingException
     */
    public GTotp( String secret ) {
        this( GTotp.configure( secret ) );
    }

    public GTotp( GTotpConfig config ) {
        super( config );
    }

    /**
     * Prover - To be used only on the client side Retrieves the encoded URI to generated the QRCode required by Google
     * Authenticator
     * 
     * @param name Account name
     * @return Encoded URI
     */
    public String uri( String name ) {
        try {
            return String.format( "otpauth://totp/%s?secret=%s", URLEncoder.encode( name, "UTF-8" ),
                                  Base32.encode( key ) );
        }
        catch ( UnsupportedEncodingException e ) {
            throw new IllegalArgumentException( e.getMessage(), e );
        }
    }

    public static GTotpConfig configure( String secret ) {
        return new GTotpConfig().secret( secret );
    }

    public static class GTotpConfig
        extends OtpConfig<GTotp, GTotpConfig> {
        protected GTotpConfig() {
            super();
            this.digits = Digits.SIX;
            this.hash = Hash.SHA1;
            this.clock = new Clock();
        }

        @Override
        public GTotpConfig inherit( GTotp otp ) {
            this.hash = otp.hash;
            this.clock = otp.clock;
            this.digits = otp.digits;
            this.tolerance = otp.delayWindow;
            this.key = otp.key;

            return this;
        }

        @Override
        public GTotpConfig self() {
            return this;
        }

        @Override
        public GTotpConfig secret( String secret ) {
            this.key = Base32.decode( secret );
            return this;
        }

        public GTotp build() {
            return new GTotp( this );
        }
    }
}
