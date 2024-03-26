package alien.io.xrootd.envelopes;

import alien.catalogue.access.XrootDEnvelope;
import alien.config.ConfigUtils;
import alien.se.SE;
import alien.user.JAKeyStore;
import alien.user.UserFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.FileSystems;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author ron
 * @since Nov 14, 2010
 */
public class XrootDEnvelopeSigner {

	/**
	 * logger
	 */
	static final Logger logger = ConfigUtils.getLogger(XrootDEnvelopeSigner.class.getCanonicalName());

	private static final String JAuthZPrivLocation;
	private static final String JAuthZPubLocation;
	private static final String SEPrivLocation;
	private static final String SEPubLocation;

	private static final RSAPrivateKey JAuthZPrivKey;
	private static final RSAPublicKey JAuthZPubKey;
	private static final RSAPrivateKey SEPrivKey;
	private static final RSAPublicKey SEPubKey;

	/*
	 * load the RSA keys for envelope signature, keys are supposed to be in pem, and can be created with: openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout lpriv.pem -out lpub.pem
	 */
	static {
		Security.addProvider(new BouncyCastleProvider());

		JAuthZPrivLocation = ConfigUtils.getConfig().gets("jAuthZ.priv.key.location", UserFactory.getUserHome() + FileSystems.getDefault().getSeparator() + ".alien"
				+ FileSystems.getDefault().getSeparator() + "authen" + FileSystems.getDefault().getSeparator() + "lpriv.pem");
		JAuthZPubLocation = ConfigUtils.getConfig().gets("jAuthZ.pub.key.location", UserFactory.getUserHome() + FileSystems.getDefault().getSeparator() + ".alien"
				+ FileSystems.getDefault().getSeparator() + "authen" + FileSystems.getDefault().getSeparator() + "lpub.pem");
		SEPrivLocation = ConfigUtils.getConfig().gets("SE.priv.key.location", UserFactory.getUserHome() + FileSystems.getDefault().getSeparator() + ".alien"
				+ FileSystems.getDefault().getSeparator() + "authen" + FileSystems.getDefault().getSeparator() + "rpriv.pem");
		SEPubLocation = ConfigUtils.getConfig().gets("SE.pub.key.location", UserFactory.getUserHome() + FileSystems.getDefault().getSeparator() + ".alien"
				+ FileSystems.getDefault().getSeparator() + "authen" + FileSystems.getDefault().getSeparator() + "rpub.pem");

		if (logger.isLoggable(Level.FINEST)) {
			logger.log(Level.FINEST, "Using private JAuthZ Key: " + JAuthZPrivLocation + "/" + JAuthZPubLocation);
			logger.log(Level.FINEST, "Using private SE Key: " + SEPrivLocation + "/" + SEPubLocation);
		}

		RSAPrivateKey jAuthZPrivKey = null;
		RSAPublicKey jAuthZPubKey = null;
		RSAPrivateKey sePrivKey = null;
		RSAPublicKey sePubKey = null;

		try {
			jAuthZPrivKey = (RSAPrivateKey) JAKeyStore.loadPrivX509(JAuthZPrivLocation, null);

			final X509Certificate[] certChain = JAKeyStore.loadPubX509(JAuthZPubLocation, false);

			if (certChain != null)
				jAuthZPubKey = (RSAPublicKey) certChain[0].getPublicKey();
		}
		catch (final IOException | PKCSException | OperatorCreationException e) {
			logger.log(Level.WARNING, "Authen keys could not be loaded from " + JAuthZPrivLocation + "/" + JAuthZPubLocation, e);
		}

		try {
			sePrivKey = (RSAPrivateKey) JAKeyStore.loadPrivX509(SEPrivLocation, null);

			final X509Certificate[] certChain = JAKeyStore.loadPubX509(SEPubLocation, false);

			if (certChain != null)
				sePubKey = (RSAPublicKey) certChain[0].getPublicKey();

		}
		catch (final IOException | PKCSException | OperatorCreationException e) {
			logger.log(Level.WARNING, "SE keys could not be loaded from " + SEPrivLocation + "/" + SEPubLocation, e);
		}

		JAuthZPrivKey = jAuthZPrivKey;
		JAuthZPubKey = jAuthZPubKey;
		SEPrivKey = sePrivKey;
		SEPubKey = sePubKey;
	}

	/**
	 * @param envelope XRootD envelope to be encrypted/signed
	 * @throws NoSuchAlgorithmException thrown by SignedAuthzToken
	 * @throws InvalidKeyException thrown by SignedAuthzToken
	 * @throws SignatureException thrown by SignedAuthzToken
     * @throws GeneralSecurityException thrown by seal() method
	 */
	public static void sealEnvelope(final XrootDEnvelope envelope) throws GeneralSecurityException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		final AuthzToken authz;
		final SE referenceSE = envelope.pfn.getSE();

		if (referenceSE == null || referenceSE.needsEncryptedEnvelope)
			authz = new EncryptedAuthzToken(JAuthZPrivKey, SEPubKey, false);
		else if (referenceSE.needsSciTokensEnvelope)
			authz = new SciTokensAuthzToken(JAuthZPrivKey);
		else
			authz = new SignedAuthzToken(JAuthZPrivKey);

		if (logger.isLoggable(Level.FINEST))
			logger.log(Level.FINEST, "Encrypting this envelope:\n" + envelope.getPlainEnvelope());

		envelope.setSecureEnvelope(authz.seal(envelope));
	}

	/**
     * Verify signed envelope
     * Doesn't work with encrypted envelopes and sciTokens
     *
	 * @param envelope signed envelope
	 * @param selfSigned <code>true</code> if self signed
	 * @return <code>true</code> if the signature verifies
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static boolean verifyEnvelope(final String envelope, final boolean selfSigned) throws GeneralSecurityException {
		final SignedAuthzToken authz = new SignedAuthzToken();

		if (selfSigned)
			authz.setAuthenPubKey(JAuthZPubKey);
		else
			authz.setAuthenPubKey(SEPubKey);

		return authz.unseal(envelope) != null;
	}

	/**
     * Decrypt envelope
     * Doesn't work with signed envelopes and sciTokens
     *
	 * @param envelope encrypted envelope
	 * @return a loaded XrootDEnvelope with the verified values
	 * @throws GeneralSecurityException
	 */
	public static XrootDEnvelope decryptEnvelope(final String envelope) throws GeneralSecurityException {
		final EncryptedAuthzToken authz = new EncryptedAuthzToken(SEPrivKey, JAuthZPubKey, true);

		return new XrootDEnvelope(authz.unseal(envelope));
	}

	/**
	 * @param envelope encrypted envelope
	 * @return the decrypted envelope, for debugging
	 * @throws GeneralSecurityException
	 */
	public static String decrypt(final String envelope) throws GeneralSecurityException {
		final EncryptedAuthzToken authz = new EncryptedAuthzToken(SEPrivKey, JAuthZPubKey, true);

		return authz.unseal(envelope);
	}

	/**
	 * Testing method that decrypts an envelope received from the console (until Ctrl-D)
	 *
	 * @param args
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static void main(final String[] args) throws GeneralSecurityException, IOException {
		final StringBuilder sb = new StringBuilder();

		String sLine;

		try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
			while ((sLine = br.readLine()) != null)
				sb.append(sLine).append("\n");
		}

		System.out.println(decrypt(sb.toString()));
	}

}
