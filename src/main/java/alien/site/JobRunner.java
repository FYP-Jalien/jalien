package alien.site;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.logging.Level;
import java.util.logging.Logger;

import alien.api.DispatchSSLClient;
import alien.config.ConfigUtils;
import alien.monitoring.Monitor;
import alien.monitoring.MonitorFactory;
import alien.shell.commands.JAliEnCOMMander;

/**
 * @author sweisz
 * @since Mar 25, 2021
 */
public class JobRunner extends JobAgent {

	/**
	 * logger object
	 */
	private static final Logger logger = ConfigUtils.getLogger(JobRunner.class.getCanonicalName());

	/**
	 * ML monitor object
	 */
	static final Monitor monitor = MonitorFactory.getMonitor(JobRunner.class.getCanonicalName());

	private final JAliEnCOMMander commander = JAliEnCOMMander.getInstance();

	static {
		monitor.addMonitoring("resource_status", (names, values) -> {
			names.add("totalcpu");
			values.add(JobAgent.MAX_CPU);

			names.add("availablecpu");
			values.add(JobAgent.RUNNING_CPU);

			names.add("allocatedcpu");
			values.add(Long.valueOf(JobAgent.MAX_CPU.longValue() - JobAgent.RUNNING_CPU.longValue()));

			names.add("runningja");
			values.add(Long.valueOf(JobAgent.RUNNING_JOBAGENTS));

			names.add("slotlength");
			values.add(Integer.valueOf(JobAgent.origTtl));

		});
	}

	@Override
	public void run() {
		long timestamp = System.currentTimeMillis() / 1000;
		final long ttlEnd = timestamp + JobAgent.origTtl;
		Thread jaThread;
		int i = 0;

		final int maxRetries = Integer.parseInt(System.getenv().getOrDefault("MAX_RETRIES", "2"));

		int jrPid = MonitorFactory.getSelfProcessID();

		CgroupUtils.setupTopCgroups(jrPid);

		while (timestamp < ttlEnd) {
			synchronized (JobAgent.requestSync) {
				try {
					if (checkParameters()) {
						logger.log(Level.INFO, "Spawned thread nr " + i);
						jaThread = new Thread(new JobAgent(), "JobAgent_" + i);
						jaThread.start();
						if (cpuIsolation == true)
							checkAndApplyIsolation(jrPid);
						monitor.sendParameter("state", "Waiting for JA to get a job");
						monitor.sendParameter("statenumeric", Long.valueOf(1));
						i++;
					}
					else {
						monitor.sendParameter("state", "All slots busy");
						monitor.sendParameter("statenumeric", Long.valueOf(3));
						logger.log(Level.INFO, "No new thread");
					}

					JobAgent.requestSync.wait(3 * 60 * 1000);

				}
				catch (final InterruptedException e) {
					logger.log(Level.WARNING, "JobRunner interrupted", e);
				}

				timestamp = System.currentTimeMillis() / 1000;

				monitor.incrementCounter("startedja");

				monitor.sendParameter("retries", Long.valueOf(JobAgent.retries.get()));

				monitor.sendParameter("remainingttl", Long.valueOf(ttlEnd - timestamp));

				if (JobAgent.retries.get() >= maxRetries) {
					monitor.sendParameter("state", "Last JA cannot get job");
					monitor.sendParameter("statenumeric", Long.valueOf(2));
					logger.log(Level.INFO, "JobRunner going to exit from lack of jobs");
					System.exit(0);
					//break;
				}
			}
		}
		System.out.println("JobRunner Exiting");
	}

	public static void main(final String[] args) {
		ConfigUtils.setApplicationName("JobRunner");
		DispatchSSLClient.setIdleTimeout(30000);
		ConfigUtils.switchToForkProcessLaunching();
		final JobRunner jr = new JobRunner();
		jr.run();
	}

	/**
	 * Gets the JA sorter by different strategies to record in DB
	 *
	 * @param slotMem Total memory consumed in the slot
	 */
	public static void recordHighestConsumer(double slotMem, String reason, double parsedSlotLimit) {
		SorterByAbsoluteMemoryUsage jobSorter1 = new SorterByAbsoluteMemoryUsage();
		sortByComparator(slotMem, jobSorter1, reason, parsedSlotLimit);
		SorterByRelativeMemoryUsage jobSorter2 = new SorterByRelativeMemoryUsage();
		sortByComparator(slotMem, jobSorter2, reason, parsedSlotLimit);
		SorterByTemporalGrowth jobSorter3 = new SorterByTemporalGrowth();
		sortByComparator(slotMem, jobSorter3, reason, parsedSlotLimit);
	}

	private static void sortByComparator(double slotMem, Comparator jobSorter, String reason, double parsedSlotLimit) {
		ArrayList<JobAgent> sortedJA = new ArrayList<JobAgent>(MemoryController.activeJAInstances.values());
		for (JobAgent ja : sortedJA)
			ja.checkProcessResources();
		String sorterId = jobSorter.getClass().getCanonicalName().split("\\.")[jobSorter.getClass().getCanonicalName().split("\\.").length -1];
		Collections.sort(sortedJA, jobSorter);
		if (MemoryController.debugMemoryController) {
			logger.log(Level.INFO, "Sorted jobs with " + sorterId + ": ");
			for (JobAgent ja : sortedJA)
				logger.log(Level.INFO, "Job " + ja.getQueueId() + " consuming VMEM " + ja.RES_VMEM.doubleValue() * 1024 + " MB and RMEM " + ja.RES_RMEM.doubleValue() * 1024 + " MB RAM");
		}
		boolean success = sortedJA.get(0).recordPreemption( System.currentTimeMillis(), slotMem, sortedJA.get(0).RES_VMEM.doubleValue(), reason, parsedSlotLimit, sortedJA.size(), sorterId);
		if (!success) {
			logger.log(Level.INFO, "Could not record preemption on central DB");
		}
	}
}
