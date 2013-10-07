package de.devsurf.security.otp.api;

import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.devsurf.security.otp.api.Otp.OtpConfig;
import de.devsurf.security.otp.api.Totp.TotpConfig;

public class TotpTest {
    @Mock
    private Clock clock;
    private TotpConfig config;
    
    public static final String key20 = "12345678901234567890";
    public static final String key32 = key20 + "123456789012";
    public static final String key64 = key20 + key20 + key20 + "1234";

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        config = OtpConfig.type(TotpConfig.class).clock(clock).digits(Digits.EIGHT);
    }
    
    private void setTimeTo(long milliseconds) {
    	when(clock.getCurrentInterval()).thenReturn(milliseconds / 1000 / 30);
    }
    
    @Test
    public void testKey20Time1() throws Exception {
    	setTimeTo(59000L);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("94287082", token, "token doesn't match");
    }
    
    @Test
    public void testKey20Time2() throws Exception {
    	setTimeTo(1111111109000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("07081804", token, "token doesn't match");
    }
    
    @Test
    public void testKey20Time3() throws Exception {
    	setTimeTo(1111111111000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("14050471", token, "token doesn't match");
    }
    
    @Test
    public void testKey20Time4() throws Exception {
    	setTimeTo(1234567890000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("89005924", token, "token doesn't match");
    }
    
    @Test
    public void testKey20Time5() throws Exception {
    	setTimeTo(2000000000000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("69279037", token, "token doesn't match");
    }
    
    @Test
    public void testKey20Time6() throws Exception {
    	setTimeTo(20000000000000l);
        Totp totp = config.secret(key20).build();
        String token = totp.now();
        assertEquals("65353130", token, "token doesn't match");
    }
    
    @Test
    public void testKey32Time1() throws Exception {
    	setTimeTo(59000L);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("46119246", token, "token doesn't match");
    }
    
    @Test
    public void testKey32Time2() throws Exception {
    	setTimeTo(1111111109000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("68084774", token, "token doesn't match");
    }
    
    @Test
    public void testKey32Time3() throws Exception {
    	setTimeTo(1111111111000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("67062674", token, "token doesn't match");
    }
    
    @Test
    public void testKey32Time4() throws Exception {
    	setTimeTo(1234567890000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("91819424", token, "token doesn't match");
    }
    
    @Test
    public void testKey32Time5() throws Exception {
    	setTimeTo(2000000000000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("90698825", token, "token doesn't match");
    }
    
    @Test
    public void testKey32Time6() throws Exception {
    	setTimeTo(20000000000000l);
        Totp totp = config.secret(key32).build();
        String token = totp.now();
        assertEquals("77737706", token, "token doesn't match");
    }
    
    
    @Test
    public void testKey64Time1() throws Exception {
    	setTimeTo(59000L);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("90693936", token, "token doesn't match");
    }
    
    @Test
    public void testKey64Time2() throws Exception {
    	setTimeTo(1111111109000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("25091201", token, "token doesn't match");
    }
    
    @Test
    public void testKey64Time3() throws Exception {
    	setTimeTo(1111111111000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("99943326", token, "token doesn't match");
    }
    
    @Test
    public void testKey64Time4() throws Exception {
    	setTimeTo(1234567890000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("93441116", token, "token doesn't match");
    }
    
    @Test
    public void testKey64Time5() throws Exception {
    	setTimeTo(2000000000000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("38618901", token, "token doesn't match");
    }
    
    @Test
    public void testKey64Time6() throws Exception {
    	setTimeTo(20000000000000l);
        Totp totp = config.secret(key64).build();
        String token = totp.now();
        assertEquals("47863826", token, "token doesn't match");
    }
}
