package de.devsurf.security.otp.api;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public enum Hash {

	MD4("MD4"), MD5("MD5"), SHA1("SHA1"), SHA256("SHA256"), SHA512("SHA512");

	private String hash;

	Hash(String hash) {
		this.hash = hash;
	}
	
	public byte[] digest(byte[] challenge) throws NoSuchAlgorithmException{
		MessageDigest digest = MessageDigest.getInstance(this.toString());
		return digest.digest(challenge);
	}

	@Override
	public String toString() {
		return hash;
	}
}
