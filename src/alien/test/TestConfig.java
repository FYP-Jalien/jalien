package alien.test;

import java.io.File;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Date;

import alien.test.utils.Functions;
import alien.test.utils.TestException;

/**
 * @author ron
 * @since Sep 16, 2011
 */
public class TestConfig {

	
	/**
	 * default home of jalien
	 */
	public static final String jalien_home = System.getProperty("user.home")
			+ "/.alien";
	
	/**
	 * default home of the testVO
	 */
	public static final String tvo_home = jalien_home + "/testVO";

	/**
	 * testVO creation time stamp
	 */
	public static final String now = (new SimpleDateFormat("HHmmss-yyyyMMdd"))
			.format(new Date());

	/**
	 * home of the testVO
	 */
	public static final String tvo_real_home = tvo_home + "_" + now;
	/**
	 * the testVO certificate location
	 */
	public static final String tvo_certs = tvo_home + "/globus";

	/**
	 * the testVO certificate location
	 */
	public static final String tvo_trusts = tvo_home + "/trusts";

	/**
	 * the testVO config location
	 */
	public static final String tvo_config = tvo_home + "/config";
	

	/**
	 * the testVO config location
	 */
	public static final String tvo_logs = tvo_home + "/logs";
	
	/**
	 * the testVO certificate subject for the CA
	 */
	public static final String certSubjectCA = 	"/C=CH/O=jAliEn/CN=jAlienCA";
	
	/**
	 * the testVO certificate subject for the user cert
	 */
	public static final String certSubjectuser = 	"/C=CH/O=jAliEn/CN=jTestUser";
	
	
	
	/**
	 * the testVO ldap config location
	 */
	public static final String ldap_config = tvo_config + "/ldap.config";
	

	/**
	 * the LDAP location
	 */
	public static final String ldap_home = TestConfig.tvo_home + "/slapd";
	
	
	/**
	 * the testVO ldap conf file location
	 */
	public static final String ldap_conf_file = ldap_home + "/slapd.conf";

	/**
	 * the testVO ldap log file location
	 */
	public static final String ldap_log = tvo_logs + "/lapd.log";
	
	

	/**
	 * the user's private key
	 */
	public static String user_key = tvo_certs + "/userkey.pem";

	/**
	 * the user's cert
	 */
	public static String user_cert = tvo_certs + "/usercert.pem";

	/**
	 * the ca's private key
	 */
	public static String ca_key = tvo_certs + "/cakey.pem";

	/**
	 * the ca's cert
	 */
	public static String ca_cert = tvo_certs + "/cacert.pem";

	/**
	 * the host's private key
	 */
	public static String host_key = tvo_certs + "/hostkey.pem";

	/**
	 * the host's cert
	 */
	public static String host_cert = tvo_certs + "/hostcert.pem";

	/**
	 * port number for the LDAP server
	 */
	public static final int ldap_port = 8389;

	/**
	 * port number for the SQL server
	 */
	public static final int sql_port = 3307;

	/**
	 * port number for the API server
	 */
	public static final int api_port = 8998;

	/**
	 * the fully qualified host name
	 */
	public static String full_host_name;

	/**
	 * the fully qualified host name
	 */
	public static String VO_name;

	/**
	 * the fully qualified host name
	 */
	public static String domain;

	/**
	 * the LDAP root string
	 */
	public static String ldap_root;
	
	/**
	 * the LDAP suffix string
	 */
	public static String ldap_suffix;
	
	/**
	 * the LDAP pass string
	 */
	//public static String ldap_pass = UUID.randomUUID().toString(); 
	public static String ldap_pass = "pass";
	
	
	/**
	 * the user base directory in the catalogue
	 */
	public static String base_home_dir;
	
	

	/**
	 * the LDAP location
	 */
	public static final String sql_home = TestConfig.tvo_home + "/sql";
	
	
	/**
	 * the testVO ldap conf file location
	 */
	public static final String mysql_conf_file = sql_home + "/mysqld.conf";
	
	
	/**
	 * the LDAP pass string
	 */
	//public static String mysql_pass = UUID.randomUUID().toString(); 
	public static String sql_pass = "pass";

	/**
	 * the test SEs' home directories
	 */
	public static final String se_home = TestConfig.tvo_home + "/SE_storage";
	

	/**
	 * @param tvohome
	 * @throws Exception
	 */
	public static void initialize() throws Exception {

		
		if(InetAddress.getByName("127.0.0.1")
				.getCanonicalHostName().contains(".")){
			full_host_name = InetAddress.getByName("127.0.0.1")
				.getCanonicalHostName();
			VO_name = full_host_name.substring(0, full_host_name.indexOf("."));
			domain = full_host_name.substring(full_host_name.indexOf(".")+1);
		} else {
			VO_name = "localhost";
			domain = "localdomain";
			full_host_name = VO_name + "." + domain;
		}
		
		System.out.println("Your local hostname is: " + full_host_name);
		System.out.println("domain/DC/VO will be: " + domain);
		System.out.println("O/VO will be: " + VO_name);
		ldap_suffix = "dc=" + domain;
		
		ldap_root = "cn=Manager,"+ldap_suffix;
		base_home_dir = "/" + domain + "/user/";

	}

	/**
	 * name of the data database
	 */
	public static final String dataDB = "testVO_data";
	
	/**
	 * name of the users database
	 */
	public static final String userDB = "testVO_users";
	
	/**
	 *  name of the processes database
	 */
	public static final String processesDB = "processes";
	
	/**
	 * @throws Exception
	 */
	public static void createConfig() throws Exception {
		File config = new File(tvo_config);
		if (config.mkdir()){
			Functions.writeOutFile(tvo_config + "/config.properties",
					getConfigProperties());
			Functions.writeOutFile(tvo_config + "/alice_data.properties",
					getDatabaseProperties(dataDB));
			Functions.writeOutFile(tvo_config + "/alice_users.properties",
					getDatabaseProperties(userDB));
			Functions.writeOutFile(tvo_config + "/processes.properties",
					getDatabaseProperties("processes"));
			Functions.writeOutFile(tvo_config + "/logging.properties",
					getLoggingProperties());
		}
		File logs = new File(tvo_logs);
		if (!logs.mkdir())
			throw new TestException("Could not create log directory: " + tvo_logs);
		File ldap = new File(ldap_home);
		if (!ldap.mkdir())
			throw new TestException("Could not create ldap directory: " + ldap_home);
		File mysql = new File(sql_home);
		if (!mysql.mkdir())
			throw new TestException("Could not create mysql directory: " + sql_home);
		File se = new File(se_home);
		if (!se.mkdir())
			throw new TestException("Could not create SE directory: " + se_home);
		
	}

	/**
	 * @return the content for the config.properties file
	 */
	private static String getConfigProperties() {
		return "\n" + "ldap_server = 127.0.0.1:" + ldap_port
				+ "\n" + "ldap_root = " + ldap_root + "\n"
				+ "alien.users.basehomedir = " + base_home_dir + "\n" + "\n"
				+ "apiService = 127.0.0.1:" + api_port + "\n"
				+ "\n" + "trusted.certificates.location = + " + tvo_trusts
				+ "\n" + "host.cert.priv.location = + " + host_key + "\n"
				+ "host.cert.pub.location = + " + host_cert + "\n"
				+ "user.cert.priv.location = + " + user_key + "\n"
				+ "user.cert.pub.location = + " + user_cert + "\n"
		
		
		+"\n";
	}
	
	/**
	 * @return the content for the config.properties file
	 */
	private static String getDatabaseProperties(String db) {
			return 	"\n" 
				+ "password=" + sql_pass + "\n"
				+ "driver=com.mysql.jdbc.Driver\n"
				+ "host=127.0.0.1\n"
				+ "port=3307\n"
				+ "database="+db+"\n"
				+ "user=root\n";
	}

	/**
	 * @return the content for the config.properties file
	 */
	private static String getLoggingProperties() {
		return "\n"
				+ "handlers= java.util.logging.FileHandler\n"
				+ "java.util.logging.FileHandler.formatter = java.util.logging.SimpleFormatter\n"
				+ "java.util.logging.FileHandler.limit = 1000000\n"
				+ "java.util.logging.FileHandler.count = 4\n"
				+ "java.util.logging.FileHandler.append = true\n"
				+ "java.util.logging.FileHandler.pattern = alien%g.log\n"
				+ ".level = OFF\n" + "alien.level = OFF\n"
				+ "lia.level = OFF\n" + "lazyj.level = OFF\n"
				+ "apmon.level = OFF\n"
				+ "# tell LazyJ to use the same logging facilities\n"
				+ "use_java_logger=true\n";
	}

}
