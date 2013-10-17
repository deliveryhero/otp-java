package de.devsurf.security.otp.api;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.logging.Logger;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class GTotpTest {

    private final static Logger LOGGER = Logger.getLogger( GTotpTest.class.getName() );

    @Mock
    private Clock clock;

    private GTotp totp;

    private String sharedSecret = "B2374TNIQ3HKC446";

    @BeforeMethod
    public void setUp()
        throws Exception {
        MockitoAnnotations.initMocks( this );
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) );
        totp = GTotp.configure( sharedSecret ).clock( clock ).build();
    }

    private long addElapsedTime( int seconds ) {
        Calendar calendar = GregorianCalendar.getInstance( TimeZone.getTimeZone( "UTC" ) );
        LOGGER.info( "Current time: " + calendar.getTime() );
        calendar.add( Calendar.SECOND, seconds );
        LOGGER.info( "Updated time (+" + seconds + "): " + calendar.getTime() );
        long currentTimeSeconds = calendar.getTimeInMillis() / 1000;
        return currentTimeSeconds / 30;
    }

    @Test
    public void testUri()
        throws Exception {
        String name = "john";
        String url = String.format( "otpauth://totp/%s?secret=%s", name, sharedSecret );
        assertEquals( url, totp.uri( "john" ) );
    }

    @Test
    public void testUriEncoding()
        throws Exception {
        GTotp totp = new GTotp( sharedSecret );
        String url = String.format( "otpauth://totp/%s?secret=%s", "john%23doe", sharedSecret );
        assertEquals( url, totp.uri( "john#doe" ) );
    }

    @Test
    public void testLeadingZeros()
        throws Exception {
        final String expected = "002941";

        when( clock.getCurrentInterval() ).thenReturn( 45187109L );
        String secret = "R5MB5FAQNX5UIPWL";
        GTotp totp = GTotp.configure( secret ).clock( clock ).build();
        String otp = totp.now();
        assertEquals( expected, otp, "Generated token must be zero padded" );
        assertTrue( totp.verify( otp ), "Generated token must be valid" );
    }

    @Test
    public void testNow()
        throws Exception {
        String otp = totp.now();
        assertEquals( 6, otp.length() );
    }

    @Test
    public void testValidOtp()
        throws Exception {
        String otp = totp.now();
        assertTrue( totp.verify( otp ), "OTP is not valid" );
    }

    @Test
    public void testOtpAfter10seconds()
        throws Exception {
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 10 ) );
        assertTrue( totp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter20seconds()
        throws Exception {
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 20 ) );
        assertTrue( totp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter25seconds()
        throws Exception {
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 25 ) );
        assertTrue( totp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter30seconds()
        throws Exception {
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 30 ) );
        assertTrue( totp.verify( otp ), "OTP should be valid" );
    }

    @Test
    public void testOtpAfter31seconds()
        throws Exception {
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) - 1 );
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 31 ) );
        assertFalse( totp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter32seconds()
        throws Exception {
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) - 1 );
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 31 ) );
        assertFalse( totp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter40seconds()
        throws Exception {
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) - 1 );
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 40 ) );
        assertFalse( totp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter50seconds()
        throws Exception {
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) - 1 );
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 50 ) );
        assertFalse( totp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter59seconds()
        throws Exception {
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) - 1 );
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 59 ) );
        assertFalse( totp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter60seconds()
        throws Exception {
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) - 1 );
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 60 ) );
        assertFalse( totp.verify( otp ), "OTP should be invalid" );
    }

    @Test
    public void testOtpAfter61seconds()
        throws Exception {
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 0 ) - 1 );
        String otp = totp.now();
        when( clock.getCurrentInterval() ).thenReturn( addElapsedTime( 61 ) );
        assertFalse( totp.verify( otp ), "OTP should be invalid" );
    }
}
