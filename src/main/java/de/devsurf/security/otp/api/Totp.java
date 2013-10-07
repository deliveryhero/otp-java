package de.devsurf.security.otp.api;

import java.nio.charset.Charset;

import de.devsurf.security.otp.api.Otp.OtpAdapter;

/**
 * Time-based One-time Password
 */
public class Totp extends OtpAdapter {

	private static final long serialVersionUID = -6440399720265141908L;

	public Totp(String secret) {
		this(Totp.configure(secret));
	}

	public Totp(TotpConfig config) {
		super(config);
	}
	
	@Override
	public String toString() {
		return "Totp [clock=" + clock + ", digits=" + digits + ", hash=" + hash + ", delayWindow="
				+ delayWindow + ", key=****]";
	}

	public static TotpConfig configure(String secret) {
		return new TotpConfig().secret(secret);
	}

	public static class TotpConfig extends OtpConfig<Totp, TotpConfig> {
		protected TotpConfig() {
			super();
			this.clock = new Clock();
		}
		
		@Override
		public TotpConfig inherit(Totp otp) {
			this.hash = otp.hash;
			this.clock = otp.clock;
			this.digits = otp.digits;
			this.tolerance = otp.delayWindow;
			this.key = otp.key;
			
			return this;
		}
		
		@Override
		public TotpConfig secret(String secret) {
			this.key = secret.getBytes(Charset.forName("UTF-8"));
			if (key.length == 20)
				this.hash = Hash.SHA1;
			else if (key.length == 32)
				this.hash = Hash.SHA256;
			else if (key.length == 64)
				this.hash = Hash.SHA512;
			else
				throw new IllegalArgumentException(
						"Key length not supported, use a key of size of 20, 32 or 64 bytes");

			return this;
		}

		@Override
		public TotpConfig self() {
			return this;
		}

		public Totp build() {
			return new Totp(this);
		}
	}
}