package alien.site.batchqueue;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lia.util.process.ExternalProcess.ExitStatus;
import utils.ProcessWithTimeout;
import java.util.logging.Level;

/**
 * Base interface for batch queues
 *
 * @author mmmartin
 */
public abstract class BatchQueue {
	/**
	 * Logging mechanism shared with the implementing code
	 */
	protected Logger logger = null;

	/**
	 * Common env variables for running commands
	 */
	public HashMap<String, String> additional_env_vars = new HashMap<>(){{
			put("LD_LIBRARY_PATH", System.getenv("LD_LIBRARY_PATH"));
			put("PATH", System.getenv("PATH"));
	}};

	/**
	 * Common configuration mechanism with the BQ implementations
	 */
	protected HashMap<String, Object> config = null;

	/**
	 * Submit a new job agent to the queue
	 * 
	 * @param script
	 */
	public abstract void submit(final String script);

	/**
	 * @return number of currently active jobs
	 */
	public abstract int getNumberActive();

	/**
	 * @return number of queued jobs
	 */
	public abstract int getNumberQueued();

	/**
	 * @return how many jobs were killed
	 */
	public abstract int kill();
	// Previously named "_system" in perl

	public ArrayList<String> executeCommand(String cmd) {
		ArrayList<String> proc_output = new ArrayList<>();

		logger.info("Executing: " + cmd);

		try {
			ArrayList<String> cmd_full = new ArrayList<>();
			cmd_full.add("/bin/bash");
			cmd_full.add("-c");
			cmd_full.add(cmd);
			final ProcessBuilder proc_builder = new ProcessBuilder(cmd_full);

			Map<String, String> env = proc_builder.environment();
			String[] dirs = {
				"/cvmfs/alice.cern.ch/",
				env.get("JALIEN_ROOT"),
				env.get("JALIEN_HOME"),
				env.get("ALIEN_ROOT"),
			};

			HashMap<String, String> cleaned_env_vars = new HashMap<>();
			Pattern p = Pattern.compile(".*PATH$");

			for (String var : env.keySet()) {
				Matcher m = p.matcher(var);

				if (!m.matches()) {
					continue;
				}

				String val = env.get(var);

				//
				// remove any traces of (J)AliEn...
				//

				for (String d : dirs) {
					if (d == null) {
						continue;
					}

					String dir = d.replaceAll("/+$", "");
					String pat = "\\Q" + dir + "\\E/[^:]*:?";
					val = val.replaceAll(pat, "");
				}

				cleaned_env_vars.put(var, val);
			}

			env.putAll(cleaned_env_vars);

			proc_builder.redirectErrorStream(true);

			final Process proc = proc_builder.start();
			final ProcessWithTimeout pTimeout = new ProcessWithTimeout(proc, proc_builder);

			pTimeout.waitFor(60, TimeUnit.SECONDS);

			final ExitStatus exitStatus = pTimeout.getExitStatus();
			logger.info("Process exit status: " + exitStatus.getExecutorFinishStatus());

			final BufferedReader reader = new BufferedReader(new StringReader(exitStatus.getStdOut()));
			String output_str;

			while ((output_str = reader.readLine()) != null) {
				proc_output.add(output_str.trim());
			}
		} catch (final Throwable t) {
			logger.log(Level.WARNING, "Exception executing command: " + cmd, t);
		}

		return proc_output;

	}

	public final String getValue(final String keyValue, final String key, final String defaultValue){
		if (keyValue.startsWith(key+'='))
			return keyValue.substring(key.length()+1).trim();

		return defaultValue;
	}
}
