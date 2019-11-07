package alien;

import java.security.KeyStoreException;
import java.util.logging.Level;
import java.util.logging.Logger;

import alien.api.JBoxServer;
import alien.api.TomcatServer;
import alien.config.ConfigUtils;
import alien.user.JAKeyStore;
import joptsimple.OptionParser;
import joptsimple.OptionSet;

/**
 * @author ron
 * @since Jun 21, 2011
 */
public class JBox {

	/**
	 * Logger
	 */
	static transient final Logger logger = ConfigUtils.getLogger(JBoxServer.class.getCanonicalName());

	/**
	 * Debugging method
	 *
	 * @param args
	 * @throws KeyStoreException
	 */
	public static void main(final String[] args) throws KeyStoreException {

		System.out.println("Starting JBox");

		logger.log(Level.FINE, "Starting JBox");

		final OptionParser parser = new OptionParser();
		parser.accepts("login");
		parser.accepts("debug").withRequiredArg().ofType(Integer.class);

		int iDebug = 0;

		try {
			final OptionSet options = parser.parse(args);

			if (options.has("debug"))
				iDebug = ((Integer) options.valueOf("debug")).intValue();
		}
		catch (final Exception e) {
			// nothing, we just let it 0, nothing to debug
			e.printStackTrace();
		}

		// First, load user certificate (or token) and create keystore
		if (JAKeyStore.loadKeyStore()) {
			JBoxServer.startJBoxService();
			TomcatServer.startTomcatServer();

			if (!ConfigUtils.writeJClientFile(ConfigUtils.exportJBoxVariables(iDebug)))
				logger.log(Level.INFO, "Failed to export JBox variables");
		}
		else {
			logger.log(Level.INFO, "JBox failed to load any credentials");
			System.err.println("JBox failed to load any credentials");
		}
	}
}