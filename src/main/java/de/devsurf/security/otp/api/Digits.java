package de.devsurf.security.otp.api;

public enum Digits {
    ZERO(0), ONE(1), TWO(2), THREE(3), FOUR(4), FIVE(5), SIX(6), SEVEN(7), EIGHT(8);

    private int digits;
    private int length;

    Digits( int length) {
        this.digits = (int) Math.pow(10, length);
        this.length = length;
    }

    public int getValue() {
        return digits;
    }
    
    public int getLength() {
    	return length;
    }
}
