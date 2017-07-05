/**
 *
 */
package alien.config;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;
import java.util.Properties;
import java.util.Set;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import alien.user.LDAPHelper;
import lazyj.DBFunctions;
import lazyj.ExtProperties;
import lazyj.cache.ExpirationCache;
import lazyj.commands.SystemCommand;
import lia.Monitor.monitor.AppConfig;

/**
 * @author costing
 * @since Nov 3, 2010
 */
public class ConfigUtils {
	private static ExpirationCache<String, String> seenLoggers = new ExpirationCache<>();

	/**
	 * Logger
	 */
	static transient final Logger logger = ConfigUtils.getLogger(ConfigUtils.class.getCanonicalName());

	private static final Map<String, ExtProperties> dbConfigFiles;

	private static final Map<String, ExtProperties> otherConfigFiles;

	private static final String CONFIG_FOLDER;

	private static LoggingConfigurator logging = null;

	private static final ExtProperties appConfig;

	private static boolean hasDirectDBConnection = false;

	static {
		String sConfigFolder = null;

		final HashMap<String, ExtProperties> dbconfig = new HashMap<>();

		final HashMap<String, ExtProperties> otherconfig = new HashMap<>();

		ExtProperties applicationConfig = null;

		try {
			sConfigFolder = System.getProperty("AliEnConfig", "config");

			final File f = new File(sConfigFolder);

			// System.err.println("Config folder: "+f.getCanonicalPath());

			if (f.exists() && f.isDirectory() && f.canRead()) {
				if (System.getProperty("lazyj.config.folder") == null)
					System.setProperty("lazyj.config.folder", sConfigFolder);

				final File[] list = f.listFiles();

				if (list != null)
					for (final File sub : list)
						if (sub.isFile() && sub.canRead() && sub.getName().endsWith(".properties")) {
							String sName = sub.getName();
							sName = sName.substring(0, sName.lastIndexOf('.'));

							// System.err.println("Found configuration file: "+sName);

							final ExtProperties prop = new ExtProperties(sConfigFolder, sName);
							prop.setAutoReload(1000 * 60);

							if (sName.equals("config"))
								applicationConfig = prop;
							else {
								prop.makeReadOnly();

								if (sName.equals("logging")) {
									logging = new LoggingConfigurator(prop);

									if (System.getProperty("lia.Monitor.ConfigURL") == null) {
										// give the ML components the same logging
										// configuration file if not explicitly set
										try {
											System.setProperty("lia.Monitor.ConfigURL", "file:" + sub.getCanonicalPath());
										} catch (final IOException ioe) {
											System.err.println("Could not resolve the canonical path of " + sub.getAbsolutePath() + " : " + ioe.getMessage());
											// ignore
										}

										// force a call to this guy so everything
										// instantiates correctly
										AppConfig.lastReloaded();
									}
								}
								else
									if (prop.gets("driver").length() > 0) {
										dbconfig.put(sName, prop);

										if (prop.gets("password").length() > 0)
											hasDirectDBConnection = true;
									}
									else
										otherconfig.put(sName, prop);
							}
						}
			}

			// if (logging == null){
			// final ExtProperties prop = new ExtProperties();
			//
			// prop.set("handlers", "java.util.logging.ConsoleHandler");
			// prop.set("java.util.logging.ConsoleHandler.level", "FINEST");
			// prop.set(".level", "INFO");
			// prop.set("java.util.logging.ConsoleHandler.formatter",
			// "java.util.logging.SimpleFormatter");
			//
			// logging = new LoggingConfigurator(prop);
			// }
		} catch (final Throwable t) {
			System.err.println("ConfigUtils: static: caught: " + t + " (" + t.getMessage() + ")");
			t.printStackTrace();
		}

		CONFIG_FOLDER = sConfigFolder;

		dbConfigFiles = Collections.unmodifiableMap(dbconfig);

		otherConfigFiles = Collections.unmodifiableMap(otherconfig);

		if (applicationConfig != null)
			appConfig = applicationConfig;
		else
			if (System.getProperty("lia.Monitor.ConfigURL") != null)
				appConfig = new ExtProperties(AppConfig.getPropertiesConfigApp());
			else
				appConfig = new ExtProperties();

		for (final Map.Entry<Object, Object> entry : System.getProperties().entrySet())
			appConfig.set(entry.getKey().toString(), entry.getValue().toString());

		appConfig.makeReadOnly();
	}

	/**
	 * @return the base directory where the configuration files are
	 */
	public static final String getConfigFolder() {
		return CONFIG_FOLDER;
	}

	/**
	 * @return <code>true</code> if direct database access is available
	 */
	public static final boolean isCentralService() {
		return hasDirectDBConnection;
	}

	/**
	 * Get all database-related configuration files
	 *
	 * @return db configurations
	 */
	public static final Map<String, ExtProperties> getDBConfiguration() {
		return dbConfigFiles;
	}

	/**
	 * Get a DB connection to a specific database key. The code relies on the <i>AlienConfig</i> system property to point to a base directory where files named <code>key</code>.properties can be
	 * found. If a file for this key can be found it is returned to the caller, otherwise a <code>null</code> value is returned.
	 *
	 * @param key
	 *            database class, something like &quot;catalogue_admin&quot;
	 * @return the database connection, or <code>null</code> if it is not available.
	 */
	public static final DBFunctions getDB(final String key) {
		final ExtProperties p = dbConfigFiles.get(key);

		if (p == null)
			return null;

		return new DBFunctions(p);
	}

	/**
	 * Get the global application configuration
	 *
	 * @return application configuration
	 */
	public static final ExtProperties getConfig() {
		return appConfig;
	}

	/**
	 * Get the contents of the configuration file indicated by the key
	 *
	 * @param key
	 * @return configuration contents
	 */
	public static final ExtProperties getConfiguration(final String key) {
		return otherConfigFiles.get(key);
	}

	/**
	 * Set the Java logging properties and subscribe to changes on the configuration files
	 *
	 * @author costing
	 * @since Nov 3, 2010
	 */
	static class LoggingConfigurator implements Observer {
		private final ExtProperties prop;

		/**
		 * Set the logging configuration
		 *
		 * @param p
		 */
		LoggingConfigurator(final ExtProperties p) {
			prop = p;

			prop.addObserver(this);

			update(null, null);
		}

		@Override
		public void update(final Observable o, final Object arg) {
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();

			try {
				prop.getProperties().store(baos, "AliEn Loggging Properties");
			} catch (final Throwable t) {
				System.err.println("Cannot store default props");
				t.printStackTrace();
			}

			final byte[] buff = baos.toByteArray();

			final ByteArrayInputStream bais = new ByteArrayInputStream(buff);

			try {
				LogManager.getLogManager().readConfiguration(bais);
			} catch (final Throwable t) {
				System.err.println("Cannot load default props into LogManager");
				t.printStackTrace();
			}
		}
	}

	/**
	 * Get the logger for this component
	 *
	 * @param component
	 * @return the logger
	 */
	public static Logger getLogger(final String component) {
		final Logger l = Logger.getLogger(component);

		if (logging != null) {
			final String s = seenLoggers.get(component);

			if (s == null)
				seenLoggers.put(component, component, 60 * 1000);
		}

		if (l.getFilter() == null)
			l.setFilter(LoggingFilter.getInstance());

		return l;
	}

	private static final String jAliEnVersion = "0.0.1";

	/**
	 * @return JAlien version
	 */
	public static final String getVersion() {
		return jAliEnVersion;
	}

	/**
	 * @return machine platform
	 */
	public static final String getPlatform() {
		final String unameS = SystemCommand.bash("uname -s").stdout.trim();
		final String unameM = SystemCommand.bash("uname -m").stdout.trim();
		return unameS + "-" + unameM;
	}

	/**
	 * @return the site name closest to where this JVM runs
	 */
	public static String getSite() {
		// TODO implement this properly
		return "CERN";
	}

	/**
	 * @return global config map
	 */
	public static HashMap<String, Object> getConfigFromLdap() {
		return getConfigFromLdap(false);
	}

	/**
	 * @param checkContent
	 * @return global config map
	 */
	public static HashMap<String, Object> getConfigFromLdap(boolean checkContent) {
		HashMap<String, Object> configuration = new HashMap<>();
		// Get hostname and domain
		String hostName = "";
		String domain = "";
		try {
			hostName = InetAddress.getLocalHost().getCanonicalHostName();
			hostName = hostName.replace("/.$/", "");
			domain = hostName.substring(hostName.indexOf(".") + 1, hostName.length());
		} catch (final UnknownHostException e) {
			logger.severe("Error: couldn't get hostname");
			e.printStackTrace();
			return null;
		}

		HashMap<String, Object> voConfig = LDAPHelper.getVOConfig();
		if (voConfig == null || voConfig.size() == 0)
			return null;

		// We get the site name from the domain and the site root info
		Set<String> siteset = LDAPHelper.checkLdapInformation("(&(domain=" + domain + "))", "ou=Sites,", "accountName");

		if (checkContent && (siteset == null || siteset.size() == 0 || siteset.size() > 1)) {
			logger.severe("Error: " + (siteset == null ? "null" : String.valueOf(siteset.size())) + " sites found for domain: " + domain);
			return null;
		}

		// users won't be always in a registered domain so we can exit here
		if (siteset.size() == 0 && !checkContent)
			return configuration;

		String site = siteset.iterator().next();

		// Get the root site config based on site name
		HashMap<String, Object> siteConfig = LDAPHelper.checkLdapTree("(&(ou=" + site + ")(objectClass=AliEnSite))", "ou=Sites,", "site");

		if (checkContent && siteConfig.size() == 0) {
			logger.severe("Error: cannot find site root configuration in LDAP for site: " + site);
			return null;
		}

		// Get the hostConfig from LDAP based on the site and hostname
		HashMap<String, Object> hostConfig = LDAPHelper.checkLdapTree("(&(host=" + hostName + "))", "ou=Config,ou=" + site + ",ou=Sites,", "host");

		if (checkContent && hostConfig.size() == 0) {
			logger.severe("Error: cannot find host configuration in LDAP for host: " + hostName);
			return null;
		}

		if (checkContent && !hostConfig.containsKey("host_ce")) {
			logger.severe("Error: cannot find ce configuration in hostConfig for host: " + hostName);
			return null;
		}

		if (hostConfig.containsKey("host_ce")) {
			// Get the CE information based on the site and ce name for the host
			HashMap<String, Object> ceConfig = LDAPHelper.checkLdapTree("(&(name=" + hostConfig.get("host_ce") + "))", "ou=CE,ou=Services,ou=" + site + ",ou=Sites,", "ce");

			if (checkContent && ceConfig.size() == 0) {
				logger.severe("Error: cannot find ce configuration in LDAP for CE: " + hostConfig.get("host_ce"));
				return null;
			}

			configuration.putAll(ceConfig);
		}
		// We put the config together
		configuration.putAll(voConfig);
		configuration.putAll(siteConfig);
		configuration.putAll(hostConfig);

		// Overwrite values
		configuration.put("organisation", "ALICE");
		if (appConfig != null) {
			Properties props = appConfig.getProperties();
			for (Object s : props.keySet()) {
				String key = (String) s;
				configuration.put(key, props.get(key));
			}
		}

		return configuration;
	}

}
