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

		try {
			CgroupUtils.setupTopCgroups(jrPid);
		}
		catch (Exception e) {
			logger.log(Level.WARNING, "Error creating top cgroup: ", e);
		}

		boolean alreadyIsol = false;

		while (timestamp < ttlEnd) {
			synchronized (JobAgent.requestSync) {
				try {
					try {
						if (checkParameters()) {
							logger.log(Level.INFO, "Spawned thread nr " + i);
							jaThread = new Thread(new JobAgent(), "JobAgent_" + i);
							jaThread.start();
							if (cpuIsolation == true && alreadyIsol == false) {
								alreadyIsol = checkAndApplyIsolation(jrPid, alreadyIsol);
							}
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
						return;
					}

					timestamp = System.currentTimeMillis() / 1000;

					monitor.incrementCounter("startedja");

					monitor.sendParameter("retries", Long.valueOf(JobAgent.retries.get()));

					monitor.sendParameter("remainingttl", Long.valueOf(ttlEnd - timestamp));

					if (JobAgent.retries.get() >= maxRetries) {
						JAliEnCOMMander.getInstance().q_api.getPinningInspection(new byte[JobAgent.RES_NOCPUS.intValue()], true, ConfigUtils.getLocalHostname());
						monitor.sendParameter("state", "Last JA cannot get job");
						monitor.sendParameter("statenumeric", Long.valueOf(2));
						logger.log(Level.INFO, "JobRunner going to exit from lack of jobs");
						System.exit(0);
						// break;
					}
				}
				catch (final Exception e) {
					logger.log(Level.WARNING, "JobRunner main loop caught another exception", e);
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
	public static void recordHighestConsumer(double slotMem, double slotMemsw, String reason, double parsedSlotLimit) {
		SorterByAbsoluteMemoryUsage jobSorter1 = new SorterByAbsoluteMemoryUsage();
		sortByComparator(slotMem, slotMemsw, jobSorter1, reason, parsedSlotLimit);
		SorterByRelativeMemoryUsage jobSorter2 = new SorterByRelativeMemoryUsage();
		sortByComparator(slotMem, slotMemsw, jobSorter2, reason, parsedSlotLimit);
		SorterByTemporalGrowth jobSorter3 = new SorterByTemporalGrowth();
		sortByComparator(slotMem, slotMemsw, jobSorter3, reason, parsedSlotLimit);
	}

	private static void sortByComparator(double slotMem, double slotMemsw, Comparator<JobAgent> jobSorter, String reason, double parsedSlotLimit) {
		ArrayList<JobAgent> sortedJA = new ArrayList<JobAgent>(MemoryController.activeJAInstances.values());
		for (JobAgent ja : sortedJA)
			ja.checkProcessResources();
		String sorterId = jobSorter.getClass().getCanonicalName().split("\\.")[jobSorter.getClass().getCanonicalName().split("\\.").length - 1];
		Collections.sort(sortedJA, jobSorter);
		if (MemoryController.debugMemoryController) {
			logger.log(Level.INFO, "Sorted jobs with " + sorterId + ": ");
			for (JobAgent ja : sortedJA)
				logger.log(Level.INFO, "Job " + ja.getQueueId() + " consuming VMEM " + ja.RES_VMEM.doubleValue() + " MB and RMEM " + ja.RES_RMEM.doubleValue() + " MB RAM");
		}
		long preemptionTs = System.currentTimeMillis();
		JobAgent toPreempt = null;
		int i = 0;
		while (i < sortedJA.size()) {
			JobAgent ja = sortedJA.get(i);
			if (ja.RES_VMEM.doubleValue() > MemoryController.MIN_MEMORY_PER_CORE * ja.cpuCores / 1024) { // Here we make sure we do not kill a job that is consuming less than 2G per slot
				toPreempt = ja;
				break;
			}
			i += 1;
		}

		if (toPreempt != null && !toPreempt.alreadyPreempted) {
			for (JobAgent ja : sortedJA) {
				boolean success = ja.recordPreemption(preemptionTs, slotMem, slotMemsw, ja.RES_VMEM.doubleValue(), reason, parsedSlotLimit, sortedJA.size(), toPreempt.getQueueId());
				if (!success) {
					logger.log(Level.INFO, "Could not record preemption on central DB");
				}
			}
			MemoryController.preemptionRound += 1;
		}
		else if (toPreempt == null) {
			logger.log(Level.INFO, "Could not start preemption. All running jobs in the slot were consuming less than 2GB/core");
		}
	}
}
