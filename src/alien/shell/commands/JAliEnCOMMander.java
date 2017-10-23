package alien.shell.commands;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import alien.api.JBoxServer;
import alien.api.catalogue.CatalogueApiUtils;
import alien.api.taskQueue.TaskQueueApiUtils;
import alien.catalogue.LFN;
import alien.catalogue.access.AuthorizationFactory;
import alien.config.ConfigUtils;
import alien.shell.FileEditor;
import alien.user.AliEnPrincipal;
import alien.user.UsersHelper;
import joptsimple.OptionException;
import lazyj.Format;

// TODO: remove comments
// TODO: discuss whether the whole command list has to be seen for anyone

/**
 * @author ron
 * @since June 4, 2011
 */
public class JAliEnCOMMander extends Thread {

	private final static int maxTryConnect = 3;

	private int triedConnects = 0;

	/**
	 * Logger
	 */
	static transient final Logger logger = ConfigUtils.getLogger(JBoxServer.class.getCanonicalName());

	/**
	 *
	 */
	public final CatalogueApiUtils c_api;

	/**
	 *
	 */
	public final TaskQueueApiUtils q_api;

	/**
	 * The commands that have a JAliEnCommand* implementation
	 */
	private static final String[] jAliEnCommandList = new String[] { "ls", "get", "cat", "whereis", "cp", "cd", "time", "mkdir", "find", "listFilesFromCollection", "scrlog", "submit", "motd",
			"access", "commit", "packages", "pwd", "ps", "rmdir", "rm", "mv", "masterjob", "user", "touch", "type", "kill", "lfn2guid", "guid2lfn", "w", "uptime", "addFileToCollection",
			"addMirror", "addTag", "addTagValue", "chgroup", "chown", "createCollection", "deleteMirror", "df", "du", "fquota", "jobinfo", "jquota", "killTransfer", "listSEDistance", "listTransfer",
			"md5sum", "mirror", "queue", "queueinfo", "register", "registerOutput", "removeTag", "removeTagValue", "resubmit", "resubmitTransfer", "showTags", "showTagValue", "spy", "top", "groups",
			"token" };

	private static final String[] jAliEnAdminCommandList = new String[] { "addTrigger", "addHost", "queue", "register", "addSE", "addUser", "calculateFileQuota", "calculateJobQuota", "groupmembers" };

	/**
	 * The commands that are advertised on the shell, e.g. by tab+tab
	 */
	private static final String[] commandList;

	static {
		final List<String> comm_set = new ArrayList<>(Arrays.asList(jAliEnCommandList));
		final List<String> comms = comm_set;
		comms.addAll(Arrays.asList(jAliEnAdminCommandList));
		comms.add("shutdown");

		comms.addAll(FileEditor.getAvailableEditorCommands());

		commandList = comms.toArray(new String[comms.size()]);
	}

	/**
	 * Commands to let UI talk internally with us here
	 */
	private static final String[] hiddenCommandList = new String[] { "whoami", "roleami", "listFilesFromCollection", "cdir", "commandlist", "gfilecomplete", "cdirtiled", "blackwhite", "color",
			"setshell", "type" };

	private UIPrintWriter out = null;

	/**
	 *
	 */
	protected AliEnPrincipal user;

	/**
	 *
	 */
	protected String site;

	private final String myHome;

	private final HashMap<String, File> localFileCash;

	private boolean degraded = false;

	private static JAliEnCOMMander lastInstance = null;

	/**
	 * @return a commander instance
	 */
	public static synchronized JAliEnCOMMander getInstance() {
		if (lastInstance == null)
			lastInstance = new JAliEnCOMMander();

		return lastInstance;
	}

	/**
	 */
	public JAliEnCOMMander() {
		this(null, null, null, null);
	}

	/**
	 * @param user
	 * @param curDir
	 * @param site
	 * @param out
	 */
	public JAliEnCOMMander(final AliEnPrincipal user, final LFN curDir, final String site, final UIPrintWriter out) {
		c_api = new CatalogueApiUtils(this);

		q_api = new TaskQueueApiUtils(this);

		this.user = (user != null) ? user : AuthorizationFactory.getDefaultUser();
		this.site = (site != null) ? site : ConfigUtils.getConfig().gets("alice_close_site").trim();
		myHome = UsersHelper.getHomeDir(this.user.getName());
		localFileCash = new HashMap<>();

		this.out = out;
		degraded = false;

		if (curDir == null)
			initializeJCentralConnection();
		else
			this.curDir = curDir;

		setName("Commander");
	}

	private boolean initializeJCentralConnection() {
		triedConnects++;

		try {
			curDir = c_api.getLFN(myHome);
			degraded = false;
		} catch (final Exception e) {
			logger.log(Level.WARNING, "Exception initializing connection", e);
			degraded = true;
		}
		return !degraded;
	}

	/**
	 * @param md5
	 * @param localFile
	 */
	protected void cashFile(final String md5, final File localFile) {
		localFileCash.put(md5, localFile);
	}

	/**
	 * @param md5
	 * @return local file name
	 */
	protected File checkLocalFileCache(final String md5) {
		if (md5 != null && localFileCash.containsKey(md5))
			return localFileCash.get(md5);
		return null;
	}

	/**
	 * Debug level as the status
	 */
	protected int debug = 0;

	/**
	 * Current directory as the status
	 */
	protected LFN curDir;

	/**
	 * get list of commands
	 *
	 * @return array of commands
	 */
	public static String getCommandList() {
		final StringBuilder commands = new StringBuilder();

		for (int i = 0; i < commandList.length; i++) {
			if (i > 0)
				commands.append(' ');

			commands.append(commandList[i]);
		}

		if (AliEnPrincipal.roleIsAdmin(AliEnPrincipal.userRole()))
			for (int i = 0; i < commandList.length; i++) {
				if (i > 0)
					commands.append(' ');

				commands.append(commandList[i]);
			}

		return commands.toString();
	}

	/**
	 * Get the user
	 *
	 * @return user
	 */
	public AliEnPrincipal getUser() {
		return user;
	}

	/**
	 * Get the site
	 *
	 * @return site
	 */
	public String getSite() {
		return site;
	}

	/**
	 * get the user's name
	 *
	 * @return user name
	 */
	public String getUsername() {
		return user.getName();
	}

	/**
	 * get the current directory
	 *
	 * @return LFN of the current directory
	 */
	public LFN getCurrentDir() {
		// if (curDir == null)
		// curDir = c_api.getLFN(myHome);
		return curDir;

	}

	/**
	 * get the current directory as string
	 *
	 * @return String of the current directory
	 */
	public String getCurrentDirName() {
		if (getCurrentDir() != null)
			return getCurrentDir().getCanonicalName();
		return "[none]";
	}

	/**
	 * get the current directory, replace home with ~
	 *
	 * @return name of the current directory, ~ places home
	 */
	public String getCurrentDirTilded() {

		return getCurrentDir().getCanonicalName().substring(0, getCurrentDir().getCanonicalName().length() - 1).replace(myHome.substring(0, myHome.length() - 1), "~");
	}

	private String[] arg = null;

	private JAliEnBaseCommand jcommand = null;

	/**
	 * Current status : 0 = idle, 1 = busy executing a command
	 */
	public AtomicInteger status = new AtomicInteger(0);

	/**
	 * Set this variable to finish commander's execution
	 */
	public volatile boolean kill = false;

	private void waitForCommand() {
		while (!kill && out == null)
			synchronized (this) {
				try {
					wait(1000);
				} catch (@SuppressWarnings("unused") final InterruptedException e) {
					// ignore
				}
			}
	}

	@Override
	public void run() {
		logger.log(Level.INFO, "Starting Commander");

		try {
			while (!kill) {
				waitForCommand();
				if (kill)
					break;

				if (degraded) {
					if (triedConnects < maxTryConnect) {
						if (!initializeJCentralConnection())
							flush();
						if (triedConnects < maxTryConnect)
							try {
								Thread.sleep(triedConnects * maxTryConnect * 500);
							} catch (final InterruptedException e) {
								e.printStackTrace();
							}
					}
					else {
						System.out.println("Giving up...");
						break;
					}
				}
				else {
					waitForCommand();
					if (kill)
						break;

					try {
						status.set(1);

						setName("Commander: Executing: " + Arrays.toString(arg));

						execute();
					} catch (final Exception e) {
						logger.log(Level.WARNING, "Got exception", e);
					}finally {
						out = null;

						setName("Commander: Idle");

						status.set(0);
						synchronized (status) {
							status.notifyAll();
						}
					}
				}
			}
		} catch (final Exception e) {
			logger.log(Level.WARNING, "Got exception", e);
		}
	}

	/**
	 * @param out
	 * @param arg
	 */
	public void setLine(final UIPrintWriter out, final String[] arg) {
		this.out = out;
		this.arg = arg;
	}

	/**
	 * execute a command line
	 *
	 * @throws Exception
	 *
	 */
	public void execute() throws Exception {
		boolean help = false;

		boolean silent = false;

		if (arg == null || arg.length == 0) {
			System.out.println("We got empty argument!");
			// flush();
			return;
		}

		final String comm = arg[0];
		logger.log(Level.INFO, "Received command = " + comm);

		final ArrayList<String> args = new ArrayList<>(Arrays.asList(arg));

		System.out.println("Received JSh call " + args);

		if (logger.isLoggable(Level.INFO))
			logger.log(Level.INFO, "Received JSh call " + args);

		args.remove(arg[0]);

		for (int i = 1; i < arg.length; i++)
			if (arg[i].startsWith("-pwd=")) {
				curDir = c_api.getLFN(arg[i].substring(arg[i].indexOf('=') + 1));
				args.remove(arg[i]);
			}
			else
				if (arg[i].startsWith("-debug=")) {
					try {
						debug = Integer.parseInt(arg[i].substring(arg[i].indexOf('=') + 1));
					} catch (@SuppressWarnings("unused") final NumberFormatException n) {
						// ignore
					}
					args.remove(arg[i]);
				}
				else
					if ("-silent".equals(arg[i])) {
						silent = true;
						args.remove(arg[i]);
					}
					else
						if ("-h".equals(arg[i]) || "--h".equals(arg[i]) || "-help".equals(arg[i]) || "--help".equals(arg[i])) {
							help = true;
							args.remove(arg[i]);
						}

		if (!Arrays.asList(jAliEnCommandList).contains(comm) &&
		// ( AliEnPrincipal.roleIsAdmin( AliEnPrincipal.userRole()) &&
				!Arrays.asList(jAliEnAdminCommandList).contains(comm) /* ) */) {
			if (Arrays.asList(hiddenCommandList).contains(comm)) {
				if ("commandlist".equals(comm))
					out.printOutln(getCommandList());
				else
					if ("whoami".equals(comm))
						out.printOutln(getUsername());
					else
						if ("blackwhite".equals(comm))
							out.blackwhitemode();
						else
							if ("color".equals(comm))
								out.colourmode();
				// else if ("shutdown".equals(comm))
				// jbox.shutdown();
				// } else if (!"setshell".equals(comm)) {
			}
			else
				out.setReturnCode(-1, "Command [" + comm + "] not found!");
			// }
		}
		else {

			final Object[] param = { this, out, args };

			try {
				jcommand = getCommand(comm, param);
			} catch (final Exception e) {

				if (e.getCause() instanceof OptionException || e.getCause() instanceof NumberFormatException)
					out.setReturnCode(-2, "Illegal command options\n");
				else {
					e.printStackTrace();
					out.setReturnCode(-3, "Error executing command [" + comm + "] : \n" + Format.stackTraceToString(e));
				}

				out.flush();
				return;
			}

			if (silent)
				jcommand.silent();

			try {
				if (jcommand == null)
					out.setReturnCode(-6, "No such command or not implemented yet. ");
				else
					if (!help && (args.size() != 0 || jcommand.canRunWithoutArguments()))
						jcommand.run();
					else {
						out.setReturnCode(-4, "Command requires an argument");
						jcommand.printHelp();
					}
			} catch (final Exception e) {
				e.printStackTrace();

				out.setReturnCode(-5, "Error executing the command [" + comm + "]: \n" + Format.stackTraceToString(e));
			}
		}
		flush();
	}

	/**
	 * flush the buffer and produce status to be send to client
	 */
	public void flush() {
		if (degraded) {
			out.degraded();
			out.setenv(UsersHelper.getHomeDir(user.getName()), getUsername());
		}
		else
			out.setenv(getCurrentDirName(), getUsername());
		out.flush();
	}

	/**
	 *
	 */
	public void killRunningCommand() {
		if (jcommand != null) {
			synchronized (jcommand) {
				jcommand.interrupt();
				jcommand = null;
			}
			out.flush();
		}
	}

	/**
	 * create and return a object of alien.shell.commands.JAliEnCommand.JAliEnCommand<classSuffix>
	 *
	 * @param classSuffix
	 *            the name of the shell command, which will be taken as the suffix for the classname
	 * @param objectParm
	 *            array of argument objects, need to fit to the class
	 * @return an instance of alien.shell.commands.JAliEnCommand.JAliEnCommand<classSuffix>
	 * @throws Exception
	 */
	protected static JAliEnBaseCommand getCommand(final String classSuffix, final Object[] objectParm) throws Exception {
		logger.log(Level.INFO, "Entering command with " + classSuffix + " and options " + Arrays.toString(objectParm));
		try {
			@SuppressWarnings("rawtypes")
			final Class cl = Class.forName("alien.shell.commands.JAliEnCommand" + classSuffix);

			@SuppressWarnings({ "rawtypes", "unchecked" })
			final java.lang.reflect.Constructor co = cl.getConstructor(new Class[] { JAliEnCOMMander.class, UIPrintWriter.class, ArrayList.class });
			return (JAliEnBaseCommand) co.newInstance(objectParm);
		} catch (@SuppressWarnings("unused") final ClassNotFoundException e) {
			// System.out.println("No such command or not implemented");
			return null;
		}
		catch (final java.lang.reflect.InvocationTargetException e) {
			logger.log(Level.SEVERE, "Exception running command", e);
			return null;
		}
	}
}
