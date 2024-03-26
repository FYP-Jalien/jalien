package alien.io.xrootd.envelopes;

import alien.config.ConfigUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;

import static org.junit.jupiter.api.Assertions.*;

class JWTGeneratorTest {

    private JWTGenerator.Builder builder;

    @BeforeEach
    public void setUp() {
        builder = new JWTGenerator.Builder();
    }

    @Test
    public void givenAllParameters_whenJWTSign_thenWorks() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        KeyPair keypair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String jwt = builder
                .withIssuer("https://" + ConfigUtils.getLocalHostname() + ":8080/")
                .withSubject("aliprod")
                .withAudience("https://wlcg.cern.ch/jwt/v1/any")
                .withPrivateKey((RSAPrivateKey) keypair.getPrivate())
                .withExpirationTime(3600)
                .withScope("storage.write:/eos/dev/alice/test1")
                .withJWTId("1234")
                .sign();

        assertNotNull(jwt);
        assertFalse(jwt.isEmpty());
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);

        // Decode and verify JWT header
        String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
        assertEquals("{\"typ\":\"JWT\",\"alg\":\"RS256\",\"wlcg.ver\":\"1.0\"}", header);

        // Decode and verify JWT payload
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        Object pobj;
        JSONObject jsonObject;
        final JSONParser parser = new JSONParser();

        try {
            pobj = parser.parse(new StringReader(payload));
            jsonObject = (JSONObject) pobj;
        } catch (final ParseException e) {
            throw new IllegalArgumentException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        assertEquals("https://" + ConfigUtils.getLocalHostname() + ":8080/", jsonObject.get("iss"));
        assertEquals("https://wlcg.cern.ch/jwt/v1/any", jsonObject.get("aud"));
        assertEquals("aliprod", jsonObject.get("sub"));
        assertEquals("storage.write:/eos/dev/alice/test1", jsonObject.get("scope"));

        // Verify JWT signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(keypair.getPublic());
        signature.update((parts[0] + "." + parts[1]).getBytes()); // Concatenate header and payload
        boolean isSignatureValid = signature.verify(java.util.Base64.getUrlDecoder().decode(parts[2]));

        assertTrue(isSignatureValid);
    }

    @Test
    public void givenPrivateKey_whenSignWithPrivateKey_thenWorks() throws NoSuchAlgorithmException {
        // Generate a temporary key pair
        builder.withPrivateKey((RSAPrivateKey) KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate());
        String jwt = builder.sign();
        assertNotNull(jwt);
        assertFalse(jwt.isEmpty());
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);
    }

    @Test
    public void givenPrivateKeyPath_whenSignWithPrivateKeyPath_thenWorks() {
        // If the default key does not exist, skip this test
        if (!new java.io.File("/etc/grid-security/hostkey.pem").exists()) {
            System.out.println("Skipping test: /etc/grid-security/hostkey.pem does not exist");
            return;
        }

        builder.withPrivateKeyPath("/etc/grid-security/hostkey.pem");
        String jwt = builder.sign();
        assertNotNull(jwt);
        assertFalse(jwt.isEmpty());
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);
    }

    @Test
    public void givenNoPrivateKey_whenSignWithPrivateKey_thenThrowsException() {
        // If the default key exists, skip this test
        if (new java.io.File("/etc/grid-security/hostkey.pem").exists()) {
            System.out.println("Skipping test: /etc/grid-security/hostkey.pem exists");
            return;
        }

        Exception exception = assertThrows(RuntimeException.class, () -> builder.sign());

        assertTrue(exception.getCause() instanceof java.security.InvalidKeyException);
    }
}