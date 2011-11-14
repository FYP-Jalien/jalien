package alien;

import java.security.KeyStoreException;
import java.util.logging.Level;
import java.util.logging.Logger;


import joptsimple.OptionParser;
import joptsimple.OptionSet;

import alien.api.JBoxServer;
import alien.config.ConfigUtils;

/**
 * @author ron
 * @since Jun 21, 2011
 */
public class JBox {

	/**
	 * Logger
	 */
	static transient final Logger logger = ConfigUtils
	.getLogger(JBoxServer.class.getCanonicalName());

	
	
	/**
	 * Debugging method
	 * 
	 * @param args
	 * @throws KeyStoreException 
	 */
	public static void main(String[] args) throws KeyStoreException {
		
		System.out.println( "Starting JBox");

		logger.log(Level.FINE, "Starting JBox");
		
		final OptionParser parser = new OptionParser();
		parser.accepts("login");
		parser.accepts( "debug" ).withRequiredArg().ofType( Integer.class );

		int iDebug = 0;

		try{
			OptionSet options = parser.parse(args);

			if(options.has("debug")){
				//iDebug = Integer.parseInt((String) options.valueOf("debug"));
				iDebug = ((Integer) options.valueOf("debug")).intValue();
			}

		} catch (Exception e) {
			//nothing, we just let it 0, nothing to debug
			e.printStackTrace();
		}


		JBoxServer.startJBoxService(iDebug);
		
	}
}