package de.devsurf.security.otp.api.internal;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.devsurf.security.otp.api.Hash;

public class Hmac {

	public static final String ALGORITHM = "RAW";
	private final String hash;
	private final byte[] secret;

	public Hmac(Hash hash, byte[] secret) {
		this.hash = "HMAC" + hash.toString();
		this.secret = secret;
	}

	public byte[] digest(byte[] challenge) throws NoSuchAlgorithmException,
			InvalidKeyException {
		Mac mac = Mac.getInstance(hash);
		SecretKeySpec macKey = new SecretKeySpec(secret, ALGORITHM);
		mac.init(macKey);
		return mac.doFinal(challenge);
	}
}
