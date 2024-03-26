package alien.io.xrootd.envelopes;

import alien.catalogue.GUID;
import alien.catalogue.GUIDUtils;
import alien.catalogue.access.XrootDEnvelope;
import alien.se.SE;
import alien.se.SEUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;

class SignedAuthzTokenTest {

    private SignedAuthzToken signedAuthzToken;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyPair authenKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        signedAuthzToken = new SignedAuthzToken((RSAPrivateKey) authenKeyPair.getPrivate());
        signedAuthzToken.setAuthenPubKey((RSAPublicKey) authenKeyPair.getPublic());
    }

    @Test
    void testSealAndUnseal() throws GeneralSecurityException {
        // Note that in this ticket turl is replaced by path
        final String ticket = "access=read&"
                + "path=root://pcepalice11.cern.ch:1094//tmp/xrd/00/19194/02bbaa0a-2e32-11e0-b69a-001e0b24002f&"
                + "lfn=/pcepalice11/user/a/admin/juduididid&"
                + "size=72624&"
                + "se=pcepalice11::CERN::XRD&"
                + "guid=02BBAA0A-2E32-11E0-B69A-001E0B24002F&"
                + "md5=21c88efc53d16fbaa6543955de92a7c7&"
                + "pfn=/tmp/xrd/00/19194/02bbaa0a-2e32-11e0-b69a-001e0b24002f";

        final GUID targetGuid = new GUID(UUID.fromString("02BBAA0A-2E32-11E0-B69A-001E0B24002F"));

        try (MockedStatic<GUIDUtils> guidUtils = mockStatic(GUIDUtils.class);
             MockedStatic<SEUtils> seUtils = mockStatic(SEUtils.class)) {
            guidUtils.when(() -> GUIDUtils.getGUID(any(UUID.class), eq(true))).thenReturn(targetGuid);
            seUtils.when(() -> SEUtils.getSE(any(String.class))).thenReturn(
                    new SE("pcepalice11::CERN::XRD", 1, "test", "/tmp", "test"));

            // Test seal method
            final XrootDEnvelope envelope = new XrootDEnvelope(ticket);
            signedAuthzToken.init(envelope, null);
            String enticket = signedAuthzToken.seal(envelope);
            assertNotNull(enticket);
            assertFalse(enticket.isEmpty());
            System.out.println(enticket);

            // Test unseal method
            final String deticket = signedAuthzToken.unseal(enticket);
            assertNotNull(deticket);
            assertFalse(deticket.isEmpty());
            System.out.println(deticket);
            assertEquals(enticket.substring(0, enticket.indexOf("&signature")), deticket);
        }
    }
}