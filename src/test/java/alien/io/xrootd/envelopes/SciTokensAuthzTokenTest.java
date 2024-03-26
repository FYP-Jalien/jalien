package alien.io.xrootd.envelopes;

import alien.api.TomcatServer;
import alien.catalogue.GUID;
import alien.catalogue.GUIDUtils;
import alien.catalogue.access.XrootDEnvelope;
import alien.config.ConfigUtils;
import alien.se.SE;
import alien.se.SEUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;

class SciTokensAuthzTokenTest {

    private AuthzToken sciTokensAuthzToken;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyPair authenKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        sciTokensAuthzToken = new SciTokensAuthzToken((RSAPrivateKey) authenKeyPair.getPrivate());
    }

    @Test
    void testSealAndUnseal() throws GeneralSecurityException {
        final String ticket = "access=read&"
                + "turl=root://pcepalice11.cern.ch:1094//tmp/xrd/00/19194/02bbaa0a-2e32-11e0-b69a-001e0b24002f&"
                + "lfn=/pcepalice11/user/a/admin/juduididid&"
                + "size=72624&"
                + "se=pcepalice11::CERN::XRD&"
                + "guid=02BBAA0A-2E32-11E0-B69A-001E0B24002F&"
                + "md5=21c88efc53d16fbaa6543955de92a7c7&"
                + "pfn=/tmp/xrd/00/19194/02bbaa0a-2e32-11e0-b69a-001e0b24002f&";

        // Mock the behavior of GUIDUtils.getGUID
        final GUID targetGuid = new GUID(UUID.fromString("02BBAA0A-2E32-11E0-B69A-001E0B24002F"));

        try (MockedStatic<GUIDUtils> guidUtils = mockStatic(GUIDUtils.class);
             MockedStatic<SEUtils> seUtils = mockStatic(SEUtils.class)) {
            guidUtils.when(() -> GUIDUtils.getGUID(any(UUID.class), eq(true))).thenReturn(targetGuid);
            seUtils.when(() -> SEUtils.getSE(any(String.class))).thenReturn(
                    new SE("pcepalice11::CERN::XRD", 1, "test", "/tmp", "test"));

            // Test seal method
            final XrootDEnvelope envelope = new XrootDEnvelope(ticket);
            sciTokensAuthzToken.init(envelope, null);
            final String enticket = sciTokensAuthzToken.seal(envelope);
            assertNotNull(enticket);
            assertFalse(enticket.isEmpty());
            System.out.println(enticket);

            // Test unseal method
            final String deticket = sciTokensAuthzToken.unseal(enticket);
            assertNotNull(deticket);
            assertFalse(deticket.isEmpty());
            System.out.println(deticket);

            int splitIndex = deticket.indexOf('{', 1);
            String header = deticket.substring(0, splitIndex);
            String payload = deticket.substring(splitIndex);
            assertEquals("{\"typ\":\"JWT\",\"alg\":\"RS256\",\"wlcg.ver\":\"1.0\"}", header);

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
            assertEquals("https://" + ConfigUtils.getLocalHostname() + ":" + TomcatServer.getPort() + "/", jsonObject.get("iss"));
            assertEquals("https://wlcg.cern.ch/jwt/v1/any", jsonObject.get("aud"));
            assertEquals("aliprod", jsonObject.get("sub"));
            assertEquals("storage.read:/tmp/xrd/00/19194/02bbaa0a-2e32-11e0-b69a-001e0b24002f", jsonObject.get("scope"));
        }
    }
}