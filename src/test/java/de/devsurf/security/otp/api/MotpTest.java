package de.devsurf.security.otp.api;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.devsurf.security.otp.api.Motp.MotpConfig;
import de.devsurf.security.otp.api.Otp.OtpConfig;

public class MotpTest {

    @Mock
    private Clock clock;

    private MotpConfig config;

    private String sharedSecret = "B2374TNIQ3HKC446";

    private String pin = "1234";

    @BeforeMethod
    public void setUp()
        throws Exception {
        MockitoAnnotations.initMocks( this );
        config = OtpConfig.type( MotpConfig.class ).clock( clock ).pin( pin ).secret( sharedSecret );
    }

    private void setTimeTo( long milliseconds ) {
        when( clock.getCurrentInterval() ).thenReturn( milliseconds / 1000 / 10 );
    }

    @Test
    public void testNow()
        throws Exception {
        setTimeTo( System.currentTimeMillis() );
        Motp motp = config.build();
        String otp = motp.now();
        assertEquals( 6, otp.length() );
    }

    @Test
    public void testValidOtp()
        throws Exception {
        setTimeTo( System.currentTimeMillis() );
        Motp motp = config.build();
        String otp = motp.now();
        System.out.println( otp );
        assertTrue( motp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testExpectedOtpWith16Secret()
        throws Exception {
        String secret = "31740cc7f06a10e3";
        String expectedOtp = "78e84c";
        setTimeTo( 1362318636794l );

        Motp motp = config.secret( secret ).build();
        assertTrue( motp.verify( expectedOtp ), "OTP should be valid" );
    }

    @Test
    public void testExpectedOtpWith32Secret()
        throws Exception {
        String secret = "cc61e14886870231f8fecdeb517bfa50";
        String expectedOtp = "d611e7";
        setTimeTo( 1362318718971l );
        Motp motp = config.secret( secret ).build();

        assertTrue( motp.verify( expectedOtp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter10seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 10000 );
        assertTrue( motp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter20seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 20000 );
        assertTrue( motp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter25seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 25000 );
        assertTrue( motp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter30seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 30000 );
        assertTrue( motp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter40seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 40000 );
        assertFalse( motp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter50seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 50000 );
        assertFalse( motp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter59seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 59000 );
        assertFalse( motp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter60seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 60000 );
        assertFalse( motp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter61seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 61000 );
        assertFalse( motp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter120seconds()
        throws Exception {
        long millis = System.currentTimeMillis();
        setTimeTo( millis );
        Motp motp = config.build();

        String otp = motp.now();
        setTimeTo( millis + 120000 );
        assertFalse( motp.verify( otp ), "OTP should be invalid" );
    }
}
