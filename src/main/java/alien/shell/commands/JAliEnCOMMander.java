package alien.shell.commands;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
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
import alien.catalogue.LFN_CSD;
import alien.catalogue.access.AuthorizationFactory;
import alien.config.ConfigUtils;
import alien.log.RequestEvent;
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

	/**
	 * Atomic status update of the command execution
	 *
	 * @author costing
	 * @since 2018-09-11
	 */
	public static class CommanderStatus {
		private int status = 0;

		/**
		 * @return current value
		 */
		public synchronized int get() {
			return status;
		}

		/**
		 * Set the new status code
		 *
		 * @param newValue
		 * @return the old value
		 */
		public synchronized int set(final int newValue) {
			final int oldValue = status;

			status = newValue;

			return oldValue;
		}
	}

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
	private static final String[] jAliEnCommandList = new String[] { "ls", "ls_csd", "cat", "cat_csd", "whereis", "whereis_csd", "cp", "cp_csd", "cd", "cd_csd", "time", "mkdir", "mkdir_csd", "find",
			"find_csd", "listFilesFromCollection", "submit", "motd", "access", "commit", "packages", "pwd", "ps", "rmdir", "rm", "rm_csd", "mv", "mv_csd", "masterjob", "user", "touch", "touch_csd",
			"type", "kill", "lfn2guid", "guid2lfn", "guid2lfn_csd", "w", "uptime", "addFileToCollection", "chgroup", "chown", "chown_csd", "deleteMirror", "df", "du", "fquota", "jquota",
			"listSEDistance", "listTransfer", "md5sum", "mirror", "resubmit", "top", "groups", "token", "uuid", "stat", "listSEs", "xrdstat", "whois", "ping", "setSite", "grep" };

	private static final String[] jAliEnAdminCommandList = new String[] { "queue", "register", "groupmembers" };

	/**
	 * The commands that are advertised on the shell, e.g. by tab+tab
	 */
	private static final String[] commandList;

	private static final AtomicInteger commanderIDSequence = new AtomicInteger();

	/**
	 * Unique identifier of the commander
	 */
	public final int commanderId = commanderIDSequence.incrementAndGet();

	static {
		final List<String> comm_set = new ArrayList<>(Arrays.asList(jAliEnCommandList));
		final List<String> comms = comm_set;
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
	 * marker for -Colour argument
	 */
	protected boolean bColour;

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
		this.site = (site != null) ? site : ConfigUtils.getCloseSite();
		localFileCash = new HashMap<>();
		this.out = out;
		this.bColour = out != null ? out.colour() : false;

		if (this.user.isJobAgent()) {
			// For job agents we do not care about directories
			myHome = "";
			this.curDir = curDir;
		}
		else {
			// User directories must be set correctly
			myHome = UsersHelper.getHomeDir(this.user.getName());
			if (curDir == null)
				try {
					this.curDir = c_api.getLFN(myHome);
				}
				catch (final Exception e) {
					logger.log(Level.WARNING, "Exception initializing connection", e);
				}
			else
				this.curDir = curDir;
		}

		setName("Commander");
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
	 * If <code>true</code> remove stdout message from the command output
	 */
	protected boolean nomsg = false;

	/**
	 * If <code>true</code> remove key-values from the command output
	 */
	protected boolean nokeys = false;

	/**
	 * Current directory as the status
	 */
	protected LFN curDir;

	/**
	 * Current directory as the status
	 */
	protected LFN_CSD curDirCsd;

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
			for (int i = 0; i < jAliEnAdminCommandList.length; i++) {
				if (i > 0)
					commands.append(' ');

				commands.append(jAliEnAdminCommandList[i]);
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

	void setSite(final String newSiteName) {
		site = newSiteName;
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
		return curDir;
	}

	/**
	 * get the current directory
	 *
	 * @return LFNCSD of the current directory
	 */
	public LFN_CSD getCurrentDirCsd() {
		return curDirCsd;
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
	public CommanderStatus status = new CommanderStatus();

	/**
	 * Set this variable to finish commander's execution
	 */
	public volatile boolean kill = false;

	private void waitForCommand() {
		while (!kill && out == null)
			synchronized (this) {
				try {
					wait(1000);
				}
				catch (@SuppressWarnings("unused") final InterruptedException e) {
					return;
				}
			}
	}

	private static OutputStream accessLogStream = null;

	private static synchronized OutputStream getAccessLogTarget() {
		if (accessLogStream == null) {
			final String accessLogFile = ConfigUtils.getConfig().gets("alien.shell.commands.access_log");

			if (accessLogFile.length() > 0) {
				try {
					accessLogStream = new FileOutputStream(accessLogFile, true);
				}
				catch (final IOException ioe) {
					logger.log(Level.WARNING, "Cannot write to access log " + accessLogFile + ", will write to stderr instead", ioe);
				}
			}

			if (accessLogStream == null)
				accessLogStream = System.err;
		}

		return accessLogStream;
	}

	@Override
	public void run() {
		logger.log(Level.INFO, "Starting Commander");

		try {
			while (!kill) {
				waitForCommand();
				if (kill)
					break;

				try (RequestEvent event = new RequestEvent(getAccessLogTarget())) {
					event.identity = getUser();
					event.site = getSite();

					try {
						status.set(1);

						setName("Commander " + commanderId + ": Executing: " + Arrays.toString(arg));

						execute(event);
					}
					catch (final Exception e) {
						event.exception = e;

						logger.log(Level.WARNING, "Got exception", e);
					}
					finally {
						out = null;

						setName("Commander " + commanderId + ": Idle");

						status.set(0);
						synchronized (status) {
							status.notifyAll();
						}
					}
				}
			}
		}
		catch (final Exception e) {
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
	 * @param event the logging for this event
	 *
	 * @throws Exception
	 *
	 */
	public void execute(final RequestEvent event) throws Exception {
		boolean help = false;
		nomsg = false;
		nokeys = false;

		if (arg == null || arg.length == 0) {
			event.errorMessage = "No command to execute";
			// flush();
			return;
		}

		final String comm = arg[0];

		final ArrayList<String> args = new ArrayList<>(Arrays.asList(arg));

		if (logger.isLoggable(Level.FINE))
			logger.log(Level.FINE, "Received JSh call " + args);

		args.remove(arg[0]);

		event.command = arg[0];
		event.arguments = new ArrayList<>(args);

		// Set default return code and error message
		out.setReturnCode(0, "");

		for (int i = 1; i < arg.length; i++)
			if (arg[i].startsWith("-pwd=")) {
				curDir = c_api.getLFN(arg[i].substring(arg[i].indexOf('=') + 1));
				args.remove(arg[i]);
			}
			else if (arg[i].startsWith("-debug=")) {
				try {
					debug = Integer.parseInt(arg[i].substring(arg[i].indexOf('=') + 1));
				}
				catch (@SuppressWarnings("unused") final NumberFormatException n) {
					// ignore
				}
				args.remove(arg[i]);
			}
			else if ("-silent".equals(arg[i])) {
				jcommand.silent();
				args.remove(arg[i]);
			}
			else if ("-nomsg".equals(arg[i])) {
				nomsg = true;
				args.remove(arg[i]);
			}
			else if ("-nokeys".equals(arg[i])) {
				nokeys = true;
				args.remove(arg[i]);
			}
			else if (("-h".equals(arg[i]) && !comm.equals("du")) || "--h".equals(arg[i]) || "-help".equals(arg[i]) || "--help".equals(arg[i])) {
				help = true;
				args.remove(arg[i]);
			}

		if (!Arrays.asList(jAliEnCommandList).contains(comm) &&
		// ( AliEnPrincipal.roleIsAdmin( AliEnPrincipal.userRole()) &&
				!Arrays.asList(jAliEnAdminCommandList).contains(comm) /* ) */) {
			if (Arrays.asList(hiddenCommandList).contains(comm)) {
				if ("commandlist".equals(comm))
					out.printOutln(getCommandList());
				else if ("whoami".equals(comm))
					out.printOutln(getUsername());
				else if ("blackwhite".equals(comm))
					out.blackwhitemode();
				else if ("color".equals(comm))
					out.colourmode();
				// else if ("shutdown".equals(comm))
				// jbox.shutdown();
				// } else if (!"setshell".equals(comm)) {
			}
			else {
				event.errorMessage = "Command [" + comm + "] not found!";

				out.setReturnCode(-1, event.errorMessage);
			}
			// }
		}
		else {

			final Object[] param = { this, args };

			try {
				jcommand = getCommand(comm, param);
			}
			catch (final Exception e) {
				if (e.getCause() instanceof OptionException || e.getCause() instanceof NumberFormatException) {
					event.errorMessage = "Illegal command options";

					out.setReturnCode(-2, event.errorMessage);
				}
				else {
					event.exception = e;

					e.printStackTrace();
					out.setReturnCode(-3, "Error executing command [" + comm + "] : \n" + Format.stackTraceToString(e));
				}

				out.flush();
				return;
			}

			try {
				if (jcommand == null)
					out.setReturnCode(-6, "No such command or not implemented yet. ");
				else {
					if (help) {
						// Force enable stdout message
						nomsg = false;
						jcommand.printHelp();
					}
					else if (jcommand.areArgumentsOk() && (args.size() != 0 || jcommand.canRunWithoutArguments())) {
						jcommand.run();
					}
					else {
						out.setReturnCode(-4, "Command requires an argument");
						jcommand.printHelp();
					}
				}
			}
			catch (final Exception e) {
				event.exception = e;
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
		out.setenv(getCurrentDirName(), getUsername());
		out.flush();
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
			final java.lang.reflect.Constructor co = cl.getConstructor(new Class[] { JAliEnCOMMander.class, List.class });
			return (JAliEnBaseCommand) co.newInstance(objectParm);
		}
		catch (@SuppressWarnings("unused") final ClassNotFoundException e) {
			// System.out.println("No such command or not implemented");
			return null;
		}
		catch (final java.lang.reflect.InvocationTargetException e) {
			logger.log(Level.SEVERE, "Exception running command", e);
			return null;
		}
	}

	/**
	 * @return <code>true</code> if the command was silenced
	 */
	public final boolean commandIsSilent() {
		if (jcommand != null)
			return jcommand.isSilent();

		return out == null;
	}

	/**
	 * Complete current message and start the next one
	 */
	public void outNextResult() {
		if (!commandIsSilent())
			out.nextResult();
	}

	/**
	 * Print a key-value pair to the output stream
	 *
	 * @param key
	 * @param value
	 */
	public void printOut(final String key, final String value) {
		if (!commandIsSilent() && out.isRootPrinter() && !nokeys)
			out.setField(key, value);
	}

	/**
	 * Print the string to the output stream
	 *
	 * @param value
	 */
	public void printOut(final String value) {
		if (!commandIsSilent() && !nomsg)
			out.printOut(value);
	}

	/**
	 * Print a key-value (+"\n") pair to the output stream
	 *
	 * @param key
	 * @param value
	 */
	public void printOutln(final String key, final String value) {
		printOut(key, value + "\n");
	}

	/**
	 * Print the line to the output stream
	 *
	 * @param value
	 */
	public void printOutln(final String value) {
		printOut(value + "\n");
	}

	/**
	 * Print an empty line to the output stream
	 */
	public void printOutln() {
		printOut("\n");
	}

	/**
	 * Print an error message to the output stream
	 *
	 * @param value
	 */
	public void printErr(final String value) {
		if (!commandIsSilent())
			out.printErr(value);
	}

	/**
	 * Print an error message line to the output stream
	 *
	 * @param value
	 */
	public void printErrln(final String value) {
		printErr(value + "\n");
	}

	/**
	 * Set the command's return code and print an error message to the output stream
	 *
	 * @param exitCode
	 * @param errorMessage
	 */
	public void setReturnCode(final int exitCode, final String errorMessage) {
		if (out != null)
			out.setReturnCode(exitCode, errorMessage);
	}

	/**
	 * Set the command's return arguments (for RootPrinter)
	 *
	 * @param args
	 */
	public void setReturnArgs(final String args) {
		if (out != null)
			out.setReturnArgs(args);
	}

	/**
	 *
	 */
	public void pending() {
		if (!commandIsSilent())
			out.pending();
	}

	/**
	 * Get commander's output stream writer
	 *
	 * @return UIPrintWriter
	 */
	public UIPrintWriter getPrintWriter() {
		return out;
	}
}