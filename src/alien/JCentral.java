package alien;

import java.security.KeyStoreException;
import java.util.logging.Level;
import java.util.logging.Logger;

import alien.api.DispatchSSLServer;
import alien.api.TomcatServer;
import alien.config.ConfigUtils;
import alien.config.Context;
import alien.user.JAKeyStore;

/**
 * @author ron
 * @since Jun 6, 2011
 */
public class JCentral {

	static {
		ConfigUtils.getVersion();
	}

	/**
	 * Logger
	 */
	static transient final Logger logger = ConfigUtils.getLogger(JCentral.class.getCanonicalName());

	/**
	 * @param args
	 * @throws KeyStoreException
	 */
	public static void main(final String[] args) throws KeyStoreException {

		try {
			JAKeyStore.loadServerKeyStorage();
		} catch (final Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		logger.setLevel(Level.WARNING);
		Context.addToLoggingContext("JCentral");

		try {
			// SimpleCatalogueApiService catalogueAPIService = new SimpleCatalogueApiService();
			// catalogueAPIService.start();
			TomcatServer.startTomcatServer(0);
			DispatchSSLServer.runService();
			
		} catch (final Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
