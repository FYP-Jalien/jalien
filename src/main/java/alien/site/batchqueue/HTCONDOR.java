package alien.site.batchqueue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import alien.test.utils.Functions;
import lia.util.process.ExternalProcess.ExitStatus;
import utils.ProcessWithTimeout;

/**
 * @author mmmartin
 */
public class HTCONDOR extends BatchQueue {

	private HashMap<String, String> environment = new HashMap<>();
	private TreeSet<String> envFromConfig;
	private String submitCmd;
	private String submitArgs = "";
	private String htc_logdir = "$HOME/htcondor";
	private String grid_resource = null;
	private boolean use_job_router = false;
	private boolean use_external_cloud = false;

	//
	// 2020-06-24 - Maarten Litmaath, Maxim Storetvedt
	//
	// to support weighted, round-robin load-balancing over a CE set:
	//

	private ArrayList<String> ce_list = new ArrayList<>();
	private HashMap<String, Double> ce_weight = new HashMap<>();
	private int next_ce = 0;
	private HashMap<String, Integer> running = new HashMap<>();
	private HashMap<String, Integer> waiting = new HashMap<>();
	private int tot_running = 0;
	private int tot_waiting = 0;
	private long job_numbers_timestamp = 0;

	//
	// our own Elvis operator approximation...
	//

	private static String if_else(String value, String fallback) {
		return value != null ? value : fallback;
	}

	/**
	 * @param conf
	 * @param logr
	 */
	@SuppressWarnings("unchecked")
	public HTCONDOR(HashMap<String, Object> conf, Logger logr) {
		config = conf;
		logger = logr;

		logger.info("This VO-Box is " + config.get("ALIEN_CM_AS_LDAP_PROXY") +
			", site is " + config.get("site_accountname"));

		String ce_env_str = "ce_environment";

		if (config.get(ce_env_str) == null) {
			String msg = ce_env_str + " needs to be defined!";
			logger.warning(msg);
			config.put(ce_env_str, new TreeSet<String>());
		}

		try {
			envFromConfig = (TreeSet<String>) config.get(ce_env_str);
		} catch (ClassCastException e) {
			envFromConfig = new TreeSet<String>(Arrays.asList((String) config.get(ce_env_str)));
		}

		//
		// initialize our environment from the LDAP configuration
		//

		for (String env_field : envFromConfig) {
			String[] parts = env_field.split("=", 2);
			String var = parts[0];
			String val = parts.length > 1 ? parts[1] : "";
			environment.put(var, val);
		}

		//
		// allow the process environment to override any variable and add others
		//

		environment.putAll(System.getenv());

		String ce_submit_cmd_str = "CE_SUBMITCMD";

		submitCmd = if_else(environment.get(ce_submit_cmd_str),
			if_else((String) config.get(ce_submit_cmd_str), "condor_submit"));

		String use_job_router_tmp = "0";
		String use_external_cloud_tmp = "0";

		for (String var : environment.keySet()) {
			String val = environment.get(var);

			if (var.equals("CE_LCGCE")) {
				double tot = 0;

				//
				// support weighted, round-robin load-balancing over a CE set
				// (mind: the WLCG SiteMon VO feed currently needs the ports):
				//
				// CE_LCGCE=[N1 * ]ce1.abc.xyz[:port], [N2 * ]ce2.abc.xyz[:port], ...
				//

				logger.info("Load-balancing over these CEs with configured weights:");

				for (String str : val.split(",")) {
					double w = 1;
					String ce = str;
					Pattern p = Pattern.compile("(\\d+)\\s*\\*\\s*(\\S+)");
					Matcher m = p.matcher(str);

					if (m.find()) {
						w = Double.parseDouble(m.group(1));
						ce = m.group(2);
					} else {
						ce = ce.replaceAll("\\s+", "");
					}

					if (!Pattern.matches(".*\\w.*", ce)) {
						logger.severe("syntax error in CE_LCGCE");
						tot = 0;
						break;
					}

					if (!Pattern.matches(".*:.*", ce)) {
						ce += ":9619";
					}

					logger.info(ce + " --> " + String.format("%5.3f", w));

					ce_list.add(ce);
					ce_weight.put(ce, w);
					tot += w;
				}

				if (tot <= 0) {
					String msg = "CE_LCGCE invalid: " + val;
					logger.severe(msg);
					throw new InstantiationException(msg);
				}

				if (ce_weight.size() != ce_list.size()) {
					String msg = "CE_LCGCE has duplicate CEs: " + val;
					logger.severe(msg);
					throw new InstantiationException(msg);
				}

				logger.info("Load-balancing over these CEs with normalized weights:");

				for (String ce : ce_list) {
					double w = ce_weight.get(ce) / tot;
					ce_weight.replace(ce, w);
					logger.info(ce + " --> " + String.format("%5.3f", w));
				}

				continue;
			}

			if (var.equals("SUBMIT_ARGS")) {
				submitArgs = val;
				continue;
			}

			if (var.equals("HTCONDOR_LOG_PATH")) {
				htc_logdir = val;
				continue;
			}

			if (var.equals("GRID_RESOURCE")) {
				grid_resource = val;
				continue;
			}

			if (var.equals("USE_JOB_ROUTER")) {
				use_job_router_tmp = val;
				continue;
			}

			if (var.equals("USE_EXTERNAL_CLOUD")) {
				use_external_cloud_tmp = val;
				continue;
			}
		}

		htc_logdir = Functions.resolvePathWithEnv(htc_logdir);
		use_job_router = Integer.parseInt(use_job_router_tmp) == 1;
		use_external_cloud = Integer.parseInt(use_external_cloud_tmp) == 1;

		if (ce_list.size() <= 0 && grid_resource == null && !use_job_router) {
			String msg = "No CE usage specified in the environment";
			logger.severe(msg);
			throw new InstantiationException(msg);
		}
	}

	public void proxyCheck() {
		//
		// not yet called, fix later...
		//

		String proxy = environment.get("X509_USER_PROXY");
		String vo_str = if_else((String) config.get("LCGVO"), "alice");
		String proxy_renewal_str = String.format("/etc/init.d/%s-box-proxyrenewal", vo_str);
		File proxy_no_check = new File(environment.get("HOME") + "/no-proxy-check");
		File proxy_renewal_svc = new File(proxy_renewal_str);

		if (proxy == null || proxy_no_check.exists() || !proxy_renewal_svc.exists()) {
			return;
		}

		String threshold = if_else(config.get("CE_PROXYTHRESHOLD"), String.valueOf(46 * 3600));
		logger.info(String.format("X509_USER_PROXY is %s", proxy));
		logger.info("Checking remaining proxy lifetime");

		String proxy_info_cmd = "voms-proxy-info -acsubject -actimeleft 2>&1";
		ArrayList<String> proxy_info_output = executeCommand(proxy_info_cmd);

		String dn_str = "";
		String time_left_str = "";

		for (String line : proxy_info_output) {
			String trimmed_line = line.trim();

			if (trimmed_line.matches("^/.+")) {
				dn_str = trimmed_line;
				continue;
			}

			if (trimmed_line.matches("^\\d+$")) {
				time_left_str = trimmed_line;
				continue;
			}
		}

		if (dn_str.length() == 0) {
			logger.warning("[LCG] No valid proxy found!");
			return;
		}

		logger.info(String.format("DN is %s", dn_str));
		logger.info(String.format("Proxy timeleft is %s (threshold is %s)", time_left_str, threshold));

		if (Integer.parseInt(time_left_str) > Integer.parseInt(threshold)) {
			return;
		}

		//
		// the proxy shall be managed by the proxy renewal service for the VO;
		// restart it as needed...
		//

		logger.info("Checking proxy renewal service");

		String proxy_renewal_cmd = String.format("%s start 2>&1", proxy_renewal_svc);
		ArrayList<String> proxy_renewal_output = null;

		try {
			proxy_renewal_output = executeCommand(proxy_renewal_cmd);
		} catch (Exception e) {
			logger.info(String.format("[LCG] Problem while executing command: %s", proxy_renewal_cmd));
			e.printStackTrace();
		} finally {
			if (proxy_renewal_output != null) {
				logger.info("Proxy renewal output:\n");

				for (String line : proxy_renewal_output) {
					logger.info(line.trim());
				}
			}
		}
	}

	@Override
	public void submit(final String script) {
		logger.info("Submit HTCONDOR");

		DateFormat date_format = new SimpleDateFormat("yyyy-MM-dd");
		String current_date_str = date_format.format(new Date());
		String log_folder_path = htc_logdir + "/" + current_date_str;
		File log_folder = new File(log_folder_path);

		if (!log_folder.exists()) {
			try {
				log_folder.mkdirs();
			} catch (Exception e) {
				logger.severe(String.format("[HTCONDOR] log folder mkdirs() exception: %s",
					log_folder_path));
				e.printStackTrace();
			}

			if (!log_folder.exists()) {
				logger.severe(String.format("[HTCONDOR] Couldn't create log folder: %s",
					log_folder_path));
				return;
			}
		}

		String file_base_name = String.format("%s/jobagent_%d", log_folder_path, System.currentTimeMillis());
		String log_cmd = String.format("log = %s.log\n", file_base_name);
		String out_cmd = "";
		String err_cmd = "";

		File enable_sandbox_file = new File(environment.get("HOME") + "/enable-sandbox");

		if (enable_sandbox_file.exists()) {
			out_cmd = String.format("output = %s.out\n", file_base_name);
			err_cmd = String.format("error = %s.err\n", file_base_name);
		}

		String submit_jdl =
			"cmd = " + script + "\n" +
			out_cmd +
			err_cmd +
			log_cmd +
			"+TransferOutput = \"\"\n" +
			"periodic_hold = JobStatus == 1 && " +
			"GridJobStatus =?= undefined && CurrentTime - EnteredCurrentStatus > 1800 || " +
			"JobStatus <= 2 && CurrentTime - EnteredCurrentStatus > 172800\n" +
			"periodic_remove = CurrentTime - QDate > 259200\n";

		//
		// via our own load-balancing (preferred), via the JobRouter, or to the single CE
		//

		if (!use_job_router && ce_list.size() > 0) {
			logger.info("Determining the next CE to use:");

			for (int i = 0; i < ce_list.size(); i++) {
				String ce = ce_list.get(next_ce);
				int idle  = waiting.get(ce);
				double w  = ce_weight.get(ce);
				double f  = tot_waiting > 0 ? (double) idle / tot_waiting : 0;

				logger.info(String.format(
					"--> %s has idle fraction %d / %d = %5.3f vs. weight %5.3f",
					ce, idle, tot_waiting, f, w
				));

				if (f < w) {
					break;
				}

				next_ce++;
				next_ce %= ce_list.size();
			}

			String ce = ce_list.get(next_ce);

			logger.info("--> next CE to use: " + ce);

			int idle  = waiting.get(ce);

			waiting.put(ce, idle + 1);
			tot_waiting++;

			next_ce++;
			next_ce %= ce_list.size();

			String h = ce.replaceAll(":.*", "");
			grid_resource = "condor " + h + " " + ce;
		}

		if (use_job_router) {
			submit_jdl +=
				"universe = vanilla\n" +
				"+WantJobRouter = True\n" +
				"job_lease_duration = 7200\n" +
				"ShouldTransferFiles = YES\n";
		} else {
			submit_jdl +=
				"universe = grid\n" +
				"grid_resource = " + grid_resource + "\n";
		}

		if (use_external_cloud) {
			submit_jdl += "+WantExternalCloud = True\n";
		}

		submit_jdl += "use_x509userproxy = true\n";

		String cm = config.get("host_host") + ":" + config.get("host_port");
		String env_cmd = String.format("ALIEN_CM_AS_LDAP_PROXY='%s'", cm);
		submit_jdl += String.format("environment = \"%s\"\n", env_cmd);

		//
		// allow preceding attributes to be overridden and others added if needed
		//

		String custom_jdl_path = environment.get("HOME") + "/custom-classad.jdl";

		if ((new File(custom_jdl_path)).exists()) {
			String custom_attr_str = "\n#\n# custom attributes start\n#\n\n";
			custom_attr_str += readJdlFile(custom_jdl_path);
			custom_attr_str += "\n#\n# custom attributes end\n#\n\n";
			submit_jdl += custom_attr_str;
			logger.info("Custom attributes added from file: " + custom_jdl_path);
		}

		//
		// finally
		//

		submit_jdl += "queue 1\n";

		//
		// keep overwriting the same file for ~1 minute
		//

		String submit_file = log_folder_path + "/htc-submit." + (job_numbers_timestamp >> 16) + ".jdl";

		try (PrintWriter out = new PrintWriter(submit_file)) {
			out.println(submit_jdl);
			out.close();
		} catch (Exception e) {
			logger.severe("Error writing to submit file: " + submit_file);
			e.printStackTrace();
			return;
		}

		String submit_cmd = submitCmd + " " + submitArgs + " " + submit_file;
		ArrayList<String> output = executeCommand(submit_cmd);

		for (String line : output) {
			String trimmed_line = line.trim();
			logger.info(trimmed_line);
		}
	}

	private String readJdlFile(String path) {
		String file_contents = "";
		String line;

		try (BufferedReader br = new BufferedReader(new FileReader(path))) {
			Pattern comment_pattern = Pattern.compile("^\\s*(#.*|//.*)?$");
			Pattern err_spaces_pattern = Pattern.compile("\\\\\\s*$");

			while ((line = br.readLine()) != null) {
				Matcher comment_matcher = comment_pattern.matcher(line);
				// skip over comment lines

				if (comment_matcher.matches()) {
					continue;
				}

				// remove erroneous spaces
				line = line.replaceAll(err_spaces_pattern.pattern(), "\\\\\n");
				file_contents += line + "\n";
			}
		} catch (Exception e) {
			logger.severe("ERROR when reading JDL file: " + path);
			e.printStackTrace();
			return "";
		}

		return file_contents;
	}

	private boolean getJobNumbers() {

		long now = System.currentTimeMillis();
		long dt  = (now - job_numbers_timestamp) / 1000;

		if (dt < 60) {
			logger.info("Reusing cached job numbers collected " + dt + " seconds ago");
			return true;
		}

		String cmd = "condor_q -const 'JobStatus < 3' -af JobStatus GridResource";
		ArrayList<String> job_list = executeCommand(cmd);

		if (job_list == null) {
			logger.info("Couldn't retrieve the list of active jobs!");
			return false;
		}

		for (String ce : ce_list) {
			running.put(ce, 0);
			waiting.put(ce, 0);
		}

		tot_running = tot_waiting = 0;
		Pattern p = Pattern.compile("^\\s*([12]).*\\s(\\S+)");

		for (String line : job_list) {
			Matcher m = p.matcher(line);

			if (m.matches()) {
				int job_status = Integer.parseInt(m.group(1));
				String ce = m.group(2);

				if (job_status == 1) {
					Integer w = waiting.get(ce);

					if (w != null) {
						waiting.put(ce, w + 1);
					}

					tot_waiting++;
				} else {
					Integer r = running.get(ce);

					if (r != null) {
						running.put(ce, r + 1);
					}

					tot_running++;
				}
			}
		}

		logger.info("Found " + tot_waiting + " idle (and " + tot_running + " running) jobs:");

		for (String ce : ce_list) {
			logger.info(String.format("%5d (%5d) for %s", waiting.get(ce), running.get(ce), ce));
		}

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

	// Previously named "_system" in perl
	private ArrayList<String> executeCommand(String cmd) {
		ArrayList<String> proc_output = new ArrayList<>();

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

					val.replaceAll("\\Q" + d + "\\E[^:]*:?", "");
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
}
