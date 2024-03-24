package alien.site.batchqueue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import alien.site.Functions;

import lia.util.process.ExternalProcess.ExitStatus;
import lia.util.process.ExternalProcess.ExecutorFinishStatus;

import lazyj.Utils;

public class PBS extends BatchQueue {

	private final HashMap<String, String> environment = new HashMap<>();
	private TreeSet<String> envFromConfig;
	private String host_logdir = "$HOME/ALICE/alien-logs";
	private String submitCmd = "qsub";
	private String submitArg = "";
	private String statusCmd = "qstat";
	private String statusArg = "";
	private final String noStageIn = "alien_not_stage_files";
	private long seq_number = 0;
	private String preamble = "";
	private String preambleFile = "preamble.sh";
	private boolean stageIn = true;
	private String stageFiles = "true";
	private final String home;
	private final String user;

	private int tot_running = 0;
	private int tot_waiting = 0;
	private long job_numbers_timestamp = 0;

	/**
	 * @param conf
	 * @param logr
	 */
	@SuppressWarnings("unchecked")
	public PBS(final HashMap<String, Object> conf, final Logger logr) {
		config = conf;
		logger = logr;

		logger.info("This VO-Box is " + config.get("ALIEN_CM_AS_LDAP_PROXY") +
			", site is " + config.get("site_accountname"));

		host_logdir = (String) config.getOrDefault("host_logdir", host_logdir);

		// Initialize from LDAP
		submitCmd = readArgFromLdap("ce_submitcmd", submitCmd);
		submitArg = readArgFromLdap("ce_submitarg", submitArg);
		statusCmd = readArgFromLdap("ce_statuscmd", statusCmd);
		statusArg = readArgFromLdap("ce_statusarg", statusArg);

		//
		// deprecated convention: the string "alien_not_stage_files" in the submit args
		// denotes the job agent startup script must not be staged to the worker node,
		// because it will be directly available through a shared file system
		//
		// a preferred, dedicated environment variable is handled further below
		//

		final Pattern pNoStageIn = Pattern.compile(noStageIn);
		final Matcher depr = pNoStageIn.matcher(submitArg);

		if (depr.find()) {
			logger.warning("deprecated use of stage directive in submit args!");
			logger.warning("please use environment setting instead");
			submitArg = submitArg.replaceAll(noStageIn, "");
			stageIn = false;
		}

		final String ce_env_str = "ce_environment";

		if (config.get(ce_env_str) == null) {
			final String msg = ce_env_str + " not defined";
			logger.info(msg);
			config.put(ce_env_str, new TreeSet<String>());
		}

		try {
			envFromConfig = (TreeSet<String>) config.get(ce_env_str);
		}
		catch (@SuppressWarnings("unused") final ClassCastException e) {
			envFromConfig = new TreeSet<>(Arrays.asList((String) config.get(ce_env_str)));
		}

		//
		// initialize our environment from the LDAP configuration
		//
		// FIXME: this does not work!
		//

		for (final String env_field : envFromConfig) {
			final String[] parts = env_field.split("=", 2);
			final String var = parts[0];
			final String val = parts.length > 1 ? parts[1] : "";
			environment.put(var, val);
			logger.info("envFromConfig: " + var + "=" + val);
		}

		//
		// allow the process environment to override any variable and add others
		//

		environment.putAll(System.getenv());

		host_logdir = environment.getOrDefault("HOST_LOGDIR", host_logdir);

		submitCmd = environment.getOrDefault("SUBMIT_CMD", submitCmd);
		submitArg = environment.getOrDefault("SUBMIT_ARGS", submitArg);
		statusCmd = environment.getOrDefault("STATUS_CMD", statusCmd);
		statusArg = environment.getOrDefault("STATUS_ARGS", statusArg);

		stageFiles = environment.getOrDefault("STAGE_FILES", stageFiles).toLowerCase();

		final Pattern pStageTrue = Pattern.compile("^\\s*(true|yes|1)\\s*$");
		final Pattern pStageFalse = Pattern.compile("^\\s*(false|no|0)\\s*$");

		if (pStageTrue.matcher(stageFiles).find()) {
			stageIn = true;
		}
		else if (pStageFalse.matcher(stageFiles).find()) {
			stageIn = false;
		}
		else {
			final String msg = "stage directive has unsupported value: " + stageFiles;
			logger.severe(msg);
			throw new IllegalArgumentException(msg);
		}

		home = environment.get("HOME");
		user = environment.get("USER");

		if (home == null || user == null) {
			final String msg = "please define HOME and USER variables!";
			logger.severe(msg);
			throw new IllegalArgumentException(msg);
		}

		statusCmd += " -u " + user + " " + statusArg;
		submitCmd += " " + submitArg;

		preambleFile = environment.getOrDefault("PREAMBLE_FILE", preambleFile);

		if ((new File(preambleFile)).exists()) {
			final String content = Utils.readFile(preambleFile);

			if (content != null) {
				preamble += content;
				logger.info("preamble loaded from file: " + preambleFile);
			}
			else {
				final String msg = "Error reading " + preambleFile;
				logger.severe(msg);
				throw new IllegalArgumentException(msg);
			}
		}
	}


	@Override
	public void submit(final String script) {
		logger.info("Submit PBS");

		final DateFormat date_format = new SimpleDateFormat("yyyy-MM-dd");
		final String current_date_str = date_format.format(new Date());
		final Long timestamp = Long.valueOf(System.currentTimeMillis());

		String short_seq_nr = String.format("%06d", ++seq_number % 1000000L);

		String pbs_script = "#!/bin/sh\n";
		pbs_script += "#PBS -V\n";

		// Name must be max 10 characters long to fit in "qstat" name column

		final String name = String.format("JA_%s", short_seq_nr);
		pbs_script += String.format("#PBS -N %s\n", name);

		String out_cmd = "#PBS -o /dev/null\n";
		String err_cmd = "#PBS -e /dev/null\n";

		final String log_folder_path = String.format("%s/%s",
			Functions.resolvePathWithEnv(host_logdir), current_date_str);
		final File log_folder = new File(log_folder_path);

		if (!(log_folder.exists())) {
			try {
				log_folder.mkdirs();
			}
			catch (final SecurityException e) {
				logger.severe(String.format("[PBS] Permission denied: %s", log_folder_path));
				e.printStackTrace();
			}
			catch (final Exception e) {
				logger.severe(String.format("[PBS] Exception with mkdirs(): %s", log_folder_path));
				e.printStackTrace();
			}

			if (!log_folder.exists()) {
				final String msg = String.format("[PBS] Couldn't create log folder: %s", log_folder_path);
				logger.severe(msg);
				return;
			}
		}

		final String file_base_name = String.format("%s/jobagent_%d_%s", log_folder_path,
			Long.valueOf(ProcessHandle.current().pid()), short_seq_nr);

		//
		// allow possibly big stdout and stderr files to be (temporarily) suppressed...
		//

                final File enable_sandbox_file = new File(home + "/enable-sandbox");

                if (enable_sandbox_file.exists()) {
			out_cmd = String.format("#PBS -o %s.out\n", file_base_name);
			err_cmd = String.format("#PBS -e %s.err\n", file_base_name);
		}

		pbs_script += out_cmd + err_cmd;

		if (stageIn) {
			final Pattern pattern = Pattern.compile("^.*/([^/]*)$");
			final Matcher matcher = pattern.matcher("/" + script);

			if (matcher.find()) {
				final String basename = matcher.group(1);
				pbs_script += String.format("#PBS -W stagein=%s@%s:%s\n", basename,
					config.get("ce_host"), script);
			}
			else {
				logger.warning("Unable to use stage in: script = " + script);
			}
		}

		//
		// any extra PBS configuration lines etc. are taken from a local preamble script
		//

		pbs_script += preamble;

		//
		// ensure the WN hostname and the time are always recorded...
		//

		pbs_script += "hostname -f\n";
		pbs_script += "date\n";

		//
		// just append the payload to the batch script...
		//

		String payload = script;

		if ((new File(script)).exists()) {
			final String content = Utils.readFile(script);

			if (content != null) {
				payload = content;
				logger.info("payload script loaded from file: " + script);
			}
			else {
				logger.severe("Error reading " + script);
				return;
			}
		}

		pbs_script += payload + "\n";

		final String submit_file = file_base_name + ".sh";

		try (PrintWriter out = new PrintWriter(submit_file)) {
			out.println(pbs_script);
		}
		catch (final Exception e) {
			logger.severe("Error writing to submit file: " + submit_file);
			e.printStackTrace();
			return;
		}

		final ExitStatus exitStatus = executeCommand(submitCmd + " " + submit_file);
		final List<String> output = getStdOut(exitStatus);

		for (final String line : output) {
			final String trimmed_line = line.trim();
			logger.info(trimmed_line);
		}
	}

	private boolean getJobNumbers() {

		final long now = System.currentTimeMillis();
		final long dt = (now - job_numbers_timestamp) / 1000;

		if (dt < 60) {
			logger.info("Reusing cached job numbers collected " + dt + " seconds ago");
			return true;
		}

		final ExitStatus exitStatus = executeCommand(statusCmd);
		final List<String> output_list = getStdOut(exitStatus);

		if (exitStatus.getExecutorFinishStatus() != ExecutorFinishStatus.NORMAL) {
			logger.warning(String.format("Abnormal exit status for command: %s", statusCmd));

			int i = 1;

			for (final String line : output_list) {
				logger.warning(String.format("Line %2d: %s", Integer.valueOf(i), line));
				if (i++ > 10) {
					logger.warning("[...]");
					break;
				}
			}

			return false;
		}

		tot_running = 0;
		tot_waiting = 0;

		for (final String output_line : output_list) {
			final String[] line = output_line.trim().split("\\s+");

			for (final String field : line) {
				if (field.length() != 1) {
					continue;
				}

				if (field.equals("Q")) {
					tot_waiting++;
				}
				else if (field.equals("R")) {
					tot_running++;
				}
			}
		}

		logger.info("Found " + tot_waiting + " idle and " + tot_running + " running jobs");

		job_numbers_timestamp = now;
		return true;
	}

	@Override
	public int getNumberActive() {

		if (!getJobNumbers()) {
			return -1;
		}

		return tot_running + tot_waiting;
	}

	@Override
	public int getNumberQueued() {

		if (!getJobNumbers()) {
			return -1;
		}

		return tot_waiting;
	}

	@Override
	public int kill() {
		logger.info("Kill command not implemented");
		return 0;
	}

	@SuppressWarnings("unchecked")
	private String readArgFromLdap(final String argToRead, final String fallback) {
		if (!config.containsKey(argToRead) || config.get(argToRead) == null)
			return fallback;
		else if ((config.get(argToRead) instanceof TreeSet)) {
			final StringBuilder args = new StringBuilder();
			for (final String arg : (TreeSet<String>) config.get(argToRead)) {
				args.append(arg).append(' ');
			}
			return args.toString();
		}
		else {
			return config.get(argToRead).toString();
		}
	}
}
