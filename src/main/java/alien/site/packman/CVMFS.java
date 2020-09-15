/**
 *
 */
package alien.site.packman;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import alien.config.ConfigUtils;
import alien.config.Version;
import alien.site.JobAgent;
import lazyj.commands.SystemCommand;

/**
 * @author mmmartin
 *
 */
public class CVMFS extends PackMan {

	/**
	 * logger object
	 */
	static final Logger logger = ConfigUtils.getLogger(JobAgent.class.getCanonicalName());

	private boolean havePath = true;

	/**
	 * CVMFS paths
	 */
	private final static String CVMFS_BASE_DIR = "/cvmfs/alice.cern.ch";
	private final static String JAVA32_DIR = CVMFS_BASE_DIR + "/java/JDKs/i686/jdk-latest/bin";
	private static String ALIEN_BIN_DIR = CVMFS_BASE_DIR + "/bin";

	/**
	 * Constructor just checks CVMFS bin exist
	 *
	 * @param location
	 */
	public CVMFS(final String location) {
		if (location != null && !location.isBlank()) {
			if (Files.exists(Paths.get(location + (location.endsWith("/") ? "" : "/") + "alienv")))
				ALIEN_BIN_DIR = location;
			else {
				havePath = false;
				ALIEN_BIN_DIR = null;
			}
		}
	}

	/**
	 * returns if alienv was found on the system
	 */
	@Override
	public boolean getHavePath() {
		return havePath;
	}

	/**
	 * get the list of packages in CVMFS, returns an array
	 */
	@Override
	public List<String> getListPackages() {
		logger.log(Level.INFO, "PackMan-CVMFS: Getting list of packages ");

		if (this.getHavePath()) {
			final String listPackages = SystemCommand.bash(ALIEN_BIN_DIR + "/alienv q --packman").stdout;
			return Arrays.asList(listPackages.split("\n"));
		}

		return null;
	}

	/**
	 * get the list of installed packages in CVMFS, returns an array
	 */
	@Override
	public List<String> getListInstalledPackages() {
		logger.log(Level.INFO, "PackMan-CVMFS: Getting list of packages ");

		if (this.getHavePath()) {
			final String listPackages = SystemCommand.bash(ALIEN_BIN_DIR + "/alienv q --packman").stdout;
			return Arrays.asList(listPackages.split("\n"));
		}
		return null;
	}

	@Override
	public String getMethod() {
		return "CVMFS";
	}

	@Override
	public Map<String, String> installPackage(final String user, final String packages, final String version) {
		final HashMap<String, String> environment = new HashMap<>();
		String args = packages;

		if (version != null)
			args += "/" + version;

		final String source = SystemCommand.bash(ALIEN_BIN_DIR + "/alienv printenv " + args).stdout;

		final ArrayList<String> parts = new ArrayList<>(Arrays.asList(source.split(";")));
		parts.remove(parts.size() - 1);

		for (final String value : parts)
			if (!value.contains("export")) {
				final String[] str = value.split("=");

				if (str[1].contains("\\"))
					str[1] = str[1].replace("\\", "");

				environment.put(str[0], str[1].trim()); // alienv adds a space at the end of each entry
			}

		return environment;
	}

	/**
	 * @return the command to get the full environment to run JAliEn components
	 */
	public static String getAlienvPrint() {
		return ALIEN_BIN_DIR + "/alienv printenv JAliEn" + getJAliEnVersion();
	}

	/**
	 *
	 * @return JAliEn version as a string
	 */
	public static String getJAliEnVersion() {
		try {
			final String loadedmodules = System.getenv().get("LOADEDMODULES");
			final int jalienModulePos = loadedmodules.lastIndexOf(":JAliEn/");

			String jalienVersionString = "";
			if (jalienModulePos > 0) {
				jalienVersionString = loadedmodules.substring(jalienModulePos + 7);

				if (jalienVersionString.contains(":"))
					jalienVersionString = jalienVersionString.substring(0, jalienVersionString.indexOf(':'));
			}
			if (!jalienVersionString.equals(""))
				return jalienVersionString;
		}
		catch (StringIndexOutOfBoundsException | NullPointerException e) {
			logger.log(Level.WARNING, "Could not get JAliEn version");
		}

		return "/Git: " + Version.getGitHash() + ". Build date: " + Version.getCompilationTimestamp();
	}

	/**
	 * @return 32b JRE location in CVMFS, to be used for all WN activities due to its much lower virtual memory footprint
	 */
	public static String getJava32Dir() {
		return JAVA32_DIR;
	}

	/**
	 * @return location of script used for cleanup of stale processes
	 */
	public static String getCleanupScript() {
		return CVMFS_BASE_DIR + "/scripts/ja_cleanup.pl";
	}

	/**
	 * @return location of script used for LHCbMarks
	 */
	public static String getLhcbMarksScript() {
		return CVMFS_BASE_DIR + "/scripts/lhcbmarks.sh";
	}

	/**
	 * @return path to job container
	 */
	public static String getContainerPath() {
		return CVMFS_BASE_DIR + "/containers/fs/singularity/centos7";
	}
}
