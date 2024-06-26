package alien.site;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.Comparator;
import java.util.Map;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import alien.config.ConfigUtils;
import alien.taskQueue.TaskQueueUtils;
import alien.shell.commands.JAliEnCOMMander;
import apmon.MonitoredJob;
import utils.ProcessWithTimeout;

/**
 * @author Marta
 */
public class NUMAExplorer {

	/**
	 * Logger
	 */
	static final Logger logger = ConfigUtils.getLogger(TaskQueueUtils.class.getCanonicalName());

	final JAliEnCOMMander commander = JAliEnCOMMander.getInstance();

	// Updated job assignment
	HashMap<Integer, Integer> availablePerNode;
	HashMap<Integer, byte[]> structurePerNode;
	HashMap<Integer, Integer> jobToNuma;
	static HashMap<Integer, byte[]> JAToMask;
	static int[] usedCPUs;
	HashMap<Integer, JobAgent> activeJAInstances;

	// Initial host structure
	int numCPUs;
	HashMap<Integer, Integer> initialAvailablePerNode;
	HashMap<Integer, byte[]> initialStructurePerNode;
	HashMap<Integer, Integer> coresPerNode;
	HashMap<Integer, Integer> divisionedNUMA;
	HashMap<Integer, Long> coresPerJob;

	private boolean fullMaskCgroupV2;

	/**
	 * @param numCPUs
	 */
	public NUMAExplorer(int numCPUs) {
		this.numCPUs = numCPUs;
		availablePerNode = new HashMap<>();
		initialAvailablePerNode = new HashMap<>();
		structurePerNode = new HashMap<>();
		initialStructurePerNode = new HashMap<>();
		coresPerNode = new HashMap<>();
		divisionedNUMA = new HashMap<>();
		coresPerJob = new HashMap<>();
		JAToMask = new HashMap<>();
		activeJAInstances = new HashMap<>();
		jobToNuma = new HashMap<>();
		usedCPUs = new int[numCPUs];
		fullMaskCgroupV2 = false;
		fillNumaTopology(JobAgent.initialMask, JobAgent.wholeNode, false);
	}

	/**
	 * Fills initial structures
	 *
	 * @param initMask mask from which allocation starts
	 * @param wholeNode whether if we run in a whole-node scenario
	 */
	private void fillNumaTopology(byte[] initMask, boolean wholeNode, boolean updateInit) {
		//On init mask: 1 means can not be used. 0 means free to be used
		logger.log(Level.INFO, "Filling initial NUMA structure with mask " + getMaskString(initMask) + " . Are we updating the initial configuration? " + updateInit);

		availablePerNode.clear();
		initialAvailablePerNode.clear();
		structurePerNode.clear();
		initialStructurePerNode.clear();
		divisionedNUMA.clear();
		coresPerNode.clear();
		int subcounter = 0;
		String filename = "/sys/devices/system/node/";
		File numaDir = new File(filename);
		File[] numaNodes = numaDir.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				return name.startsWith("node");
			}
		});
		if (numaNodes != null) {
			for (File node : numaNodes) {
				if (node.isDirectory()) {
					filename = node.getAbsolutePath() + "/cpulist";
					File f = new File(filename);
					String s;
					if (f.exists() && f.canRead()) {
						try (BufferedReader br = new BufferedReader(new FileReader(f))) {
							while ((s = br.readLine()) != null) {
								String[] splitted = s.split(",");
								for (String range : splitted) {
									byte[] cpuRange = new byte[numCPUs];
									String patternStr = "(\\d+)-(\\d+)";
									Pattern pattern = Pattern.compile(patternStr);
									Matcher matcher = pattern.matcher(range);
									String patternStr2 = "\\d+(,\\d+)*";
									Pattern pattern2 = Pattern.compile(patternStr2);
									Matcher matcher2 = pattern2.matcher(range);
									if (matcher.matches() || matcher2.matches()) {
										if (matcher.matches()) {
											logger.log(Level.INFO, "CPU listing in form of range " + range);
											int rangeidx = Integer.parseInt(matcher.group(1));
											int maxRangeidx = Integer.parseInt(matcher.group(2));
											int[] rangeArray = new int[maxRangeidx - rangeidx + 1];
											int i = 0;
											while (rangeidx <= maxRangeidx) {
												rangeArray[i] = rangeidx;
												rangeidx += 1;
												i += 1;
											}
											cpuRange = buildCPURange(initMask, wholeNode, subcounter, rangeArray);
										}
										else if (matcher2.matches()) {
											logger.log(Level.INFO, "CPU listing in form of comma-sepparated cores " + range);
											String[] cores = range.split(",");
											int[] rangeArray = new int[cores.length];
											int i = 0;
											for (String core : cores) {
												rangeArray[i] = Integer.parseInt(core);
												i += 1;
											}
											cpuRange = buildCPURange(initMask, wholeNode, subcounter, rangeArray);
										}

										String patternNumaStr = ".*(\\d+).*";
										Pattern patternNuma = Pattern.compile(patternNumaStr);
										Matcher matcherNuma = patternNuma.matcher(node.getName());
										if (matcherNuma.matches()) {
											int numaId = Integer.parseInt(matcherNuma.group(1));
											divisionedNUMA.put(Integer.valueOf(subcounter), Integer.valueOf(numaId));
											structurePerNode.put(Integer.valueOf(subcounter), cpuRange);
											//In structure 1 means can be used to pin, 0 is not available
											initialStructurePerNode.put(Integer.valueOf(subcounter), cpuRange.clone());
											logger.log(Level.INFO, "Filling initial structure of sub-node counter " + subcounter + " and mask "
													+ getMaskString(initialStructurePerNode.get(Integer.valueOf(subcounter))));
											int coreCount = countAvailableCores(cpuRange,(byte)1);
											availablePerNode.put(Integer.valueOf(subcounter), Integer.valueOf(coreCount));
											initialAvailablePerNode.put(Integer.valueOf(subcounter), Integer.valueOf(coreCount));
											subcounter = subcounter + 1;
										}
										else {
											logger.log(Level.INFO, "Format error found when getting NUMA node id");
											fillDefaultStructures(initMask, wholeNode);
										}
									}
									else {
										logger.log(Level.INFO, "Format error on getting NUMA range");
										fillDefaultStructures(initMask, wholeNode);
									}
								}
							}
						}
						catch (IOException e) {
							logger.log(Level.WARNING, "Could not access " + filename + " " + e);
							fillDefaultStructures(initMask, wholeNode);
						}
					}
				}
			}
		}
	}

	private byte[] buildCPURange(byte[] initMask, boolean wholeNode, int subcounter, int[] rangeArray) {
		logger.log(Level.INFO, "Filling structure with CPUs " + getMaskString(rangeArray) + "for NUMA node " + subcounter);
		byte[] cpuRange = new byte[numCPUs];
		for (int core : rangeArray) {
			coresPerNode.put(Integer.valueOf(core), Integer.valueOf(subcounter));
			if (wholeNode == false && initMask[core] == 1) {
				cpuRange[core] = 0;
				usedCPUs[core] = -1;
			}
			else {
				usedCPUs[core] = 0;
				cpuRange[core] = 1;
			}
		}
		return cpuRange;
	}

	private void fillDefaultStructures(byte[] initMask, boolean wholeNode) {
		// In case the files are not present in the machine, we just set a single NUMA node.
		byte[] cpuRange = new byte[numCPUs];
		for (int core = 0; core < cpuRange.length; core++) {
			if (wholeNode == false && initMask[core] == 1) {
				cpuRange[core] = 0;
				usedCPUs[core] = -1;
			}
			else
				cpuRange[core] = 1;
			coresPerNode.put(Integer.valueOf(core), Integer.valueOf(0));
		}
		divisionedNUMA.put(Integer.valueOf(0), Integer.valueOf(0));
		structurePerNode.put(Integer.valueOf(0), cpuRange);
		initialStructurePerNode.put(Integer.valueOf(0), cpuRange.clone());
		availablePerNode.put(Integer.valueOf(0), Integer.valueOf(numCPUs));
		initialAvailablePerNode.put(Integer.valueOf(0), Integer.valueOf(numCPUs));
	}

	private static int countAvailableCores(byte[] cpuRange, byte freeCore) {
		int counter = 0;
		for (int i = 0; i < cpuRange.length; i++) {
			if (cpuRange[i] == freeCore)
				counter = counter + 1;
		}
		return counter;
	}

	static String getMaskString(byte[] cpuRange) {
		// Aux printing for debugging purposes
		String rangeStr = "";
		for (int i = 0; i < cpuRange.length; i++) {
			rangeStr = rangeStr + cpuRange[i] + " ";
		}
		return rangeStr;
	}

	private static String getMaskString(int[] cpuRange) {
		// Aux printing for debugging purposes
		String rangeStr = "";
		for (int i = 0; i < cpuRange.length; i++) {
			rangeStr = rangeStr + cpuRange[i] + " ";
		}
		return rangeStr;
	}

	/**
	 * Computes the mask to isolate the JobRunner instance
	 *
	 * @param reqCPU required amount of CPU
	 * @param wholeNode whether if we are running in whole node
	 * @return mask to apply using taskset
	 */
	String computeInitialMask(Long reqCPU, boolean wholeNode) {

		byte[] finalMask = new byte[numCPUs];

		if (availablePerNode.keySet().size() == 0) {
			logger.log(Level.INFO, "Can not set NUMA architecture aware cpuIsolation");
			return arrayToTaskset(finalMask);
		}

		finalMask = checkAndComputeMask(reqCPU);

		for (int i = 0; i < finalMask.length; i++) {
			if (finalMask[i] == 0) {
				usedCPUs[i] = -1;
			}
		}
		byte[] checkedFinalMask = Arrays.copyOf(finalMask, numCPUs);
		int getMaskAttempts = 0;
		while (getMaskAttempts < numCPUs / reqCPU.longValue()) {
			checkedFinalMask = checkInitialMaskCS(finalMask, reqCPU, ConfigUtils.getLocalHostname());
			if (Arrays.equals(checkedFinalMask, finalMask) || countAvailableCores(checkedFinalMask, (byte) 0) == checkedFinalMask.length) {
				break;
			}
			getMaskAttempts += 1;
			if (countAvailableCores(checkedFinalMask, (byte) 3) != checkedFinalMask.length) {
				finalMask = Arrays.copyOf(checkedFinalMask, checkedFinalMask.length);
			}
		}
		// Case we do not apply pinning
		if (getMaskAttempts == numCPUs / reqCPU.longValue()) {
			logger.log(Level.INFO, "Got to the maximum amount of retries for getting pinning. Running unpinned");
			checkedFinalMask = new byte[numCPUs];
		}

		byte[] reversedFinalMask = reverseMask(checkedFinalMask);

		//Restart structures with new pinning
		fillNumaTopology(reversedFinalMask, wholeNode, true);

		return arrayToTaskset(checkedFinalMask);
	}

	private byte[] checkAndComputeMask(Long reqCPU) {
		byte[] finalMask;
		int numaNode = getNumaNode(reqCPU, System.currentTimeMillis(), null, availablePerNode);
		if (numaNode < 0) {
			finalMask = getPartitionedMask(reqCPU, 0, structurePerNode, availablePerNode, null, -1, true);
		}
		else {
			byte[] availableMask = structurePerNode.get(Integer.valueOf(numaNode));
			finalMask = buildFinalMask(availableMask, reqCPU, 0, availablePerNode, structurePerNode, null, true);
		}
		return finalMask;
	}

	byte[] checkInitialMaskCS(byte[] proposedMask, Long reqCPU, String hostname) {
		boolean needRecompute = false;
		byte[] machinePinning = new byte[proposedMask.length];
		int lockRequests = 0;
		while (lockRequests < numCPUs/reqCPU.longValue() && !needRecompute) {
			logger.log(Level.INFO, "Issuing request for pinning inspection to cs");
			byte[] responseMask = commander.q_api.getPinningInspection(proposedMask, false, hostname);
			if (responseMask == null) {
				return new byte[proposedMask.length];
			}
			if (Arrays.equals(responseMask, proposedMask)) {
				break;
			}
			logger.log(Level.INFO, "Got response mask " + getMaskString(responseMask));
			if (responseMask[0] == 3) {
				if (lockRequests < numCPUs/reqCPU.longValue()) {
					//Lock is taken, we have to wait random time between 0.5-2.5s for asking again
					long waitInterval = (long) (500 + Math.random() * 2000);
					logger.log(Level.INFO, "Lock is taken. Going to wait " + waitInterval + " ms");
					try {
						Thread.sleep(waitInterval);
					}
					catch (InterruptedException e) {
						logger.log(Level.INFO, "Exception while waiting for release of CPU pinning lock", e);
					}
					lockRequests += 1;
				} else {
					//We give up to wait for lock, go to the next request
					 return responseMask;
				}
			} else {
				for (int cpuId = 0; cpuId < proposedMask.length; cpuId++) {
					if (responseMask[cpuId] == 2) {
						needRecompute = true;
						machinePinning[cpuId] = 1;
					}
				}
			}
		}
		if (needRecompute) {
			//Restart structures with discovered pinning of other processes
			fillNumaTopology(machinePinning, JobAgent.wholeNode, true);
			return checkAndComputeMask(reqCPU);
		}
		return proposedMask;
	}

	static byte[] reverseMask(byte[] mask) {
		byte[] reversed = new byte[mask.length];
		for (int i =0; i < mask.length; i++)
			reversed[i] = (byte)(mask[i] ^ 1);
		return reversed;
	}

	/**
	 * @param reqCPU cores to allocate to job
	 * @param jobNumber job identifier
	 * @return mask of cores to pin
	 */
	String pickCPUs(Long reqCPU, int jobNumber) {
		byte[] finalMask = new byte[numCPUs];

		if (availablePerNode.keySet().size() == 0) {
			logger.log(Level.INFO, "Can not set NUMA architecture aware cpuIsolation");
			return arrayToTaskset(finalMask);
		}

		boolean rearrangementNeeded = true;
		int rearrangementCount = 0;
		int rearrangementNotPossible = 0;
		long queueId = activeJAInstances.get(Integer.valueOf(jobNumber)).getQueueId();

		while (rearrangementNeeded) {
			int numaNode = getNumaNode(reqCPU, queueId, null, availablePerNode);
			// We have not found the space needed in any node. Proceed to partition
			if (numaNode < 0) {
				if (rearrangementCount == 0 && rearrangementNotPossible < 3) {
					int[] auxUsedCPUs = rearrangeCores(jobNumber, reqCPU);
					if (!Arrays.equals(usedCPUs, auxUsedCPUs)) {
						rearrangementCount = rearrangementCount + 1;
						restartStructures(auxUsedCPUs);
						for (int i = 0; i < auxUsedCPUs.length; i++) {
							if (usedCPUs[i] != -1)
								usedCPUs[i] = auxUsedCPUs[i];
						}
						continue;
					}
					rearrangementNotPossible = rearrangementNotPossible + 1;
				}
				finalMask = getPartitionedMask(reqCPU, jobNumber, structurePerNode, availablePerNode, usedCPUs, numaNode, false);
			}
			else {
				byte[] availableMask = structurePerNode.get(Integer.valueOf(numaNode));
				finalMask = buildFinalMask(availableMask, reqCPU, jobNumber, availablePerNode, structurePerNode, Arrays.copyOf(usedCPUs, usedCPUs.length), false);
				rearrangementNeeded = false;
				jobToNuma.put(Integer.valueOf(jobNumber), Integer.valueOf(numaNode));
			}

			logger.log(Level.INFO, "Process is going to be pinned to CPU mask " + getMaskString(finalMask));

			if (rearrangementCount > 0 || rearrangementNotPossible >= 3)
				rearrangementNeeded = false;

		}
		logger.log(Level.INFO, "Current CPU-job mapping: " + getMaskString(usedCPUs));
		JAToMask.put(Integer.valueOf(jobNumber), finalMask);
		coresPerJob.put(Integer.valueOf(jobNumber), reqCPU);
		if (fullMaskCgroupV2) {
			Integer targetNodeId = jobToNuma.get(Integer.valueOf(jobNumber));
			byte[] wholeMask = getFullNUMAMask(targetNodeId);
			logger.log(Level.INFO, "Pinning job " + jobNumber + " to full NUMA mask " + arrayToTaskset(wholeMask));
			return arrayToTaskset(wholeMask);
		}
		addPinningTraceLog(finalMask, Integer.valueOf(jobNumber));
		byte[] extendedFinalMask = extendFinalMask(finalMask, jobNumber);
		logger.log(Level.INFO, "Pinning job " + jobNumber + " to mask " + getMaskString(extendedFinalMask));
		return arrayToTaskset(extendedFinalMask);
	}

	private byte[] getFullNUMAMask(Integer targetNodeId) {
		byte[] fullNUMAMask = new byte[numCPUs];
		if (targetNodeId.intValue() > -1) {
			Integer numaNode = divisionedNUMA.get(targetNodeId);
			fullNUMAMask = initialStructurePerNode.get(targetNodeId).clone();
			for (Integer subNode : divisionedNUMA.keySet()) {
				if (divisionedNUMA.get(subNode).equals(numaNode) && !targetNodeId.equals(subNode)) {
					for (int i=0; i < initialStructurePerNode.get(targetNodeId).length; i++)
						fullNUMAMask[i] += initialStructurePerNode.get(subNode)[i];
				}
			}
			logger.log(Level.INFO, "Generating full NUMA mask. subNodeId=" + targetNodeId + ", numaNode=" + numaNode + ". Full NUMA Mask computed to " + arrayToTaskset(fullNUMAMask));
		}
		return fullNUMAMask;
	}

	/**
	 * Split the unused cores within the running payloads
	 *
	 * @param finalMask
	 * @param jobNumber
	 * @return
	 */
	private byte[] extendFinalMask(byte[] finalMask, int jobNumber) {
		byte[] extendedFinalMask = finalMask.clone();

		HashMap<Integer, byte[]> masksToPin = new HashMap<>();
		for (Integer job : coresPerJob.keySet()) {
			byte[] newMask = new byte[numCPUs];
			for (int i = 0; i < usedCPUs.length; i++) {
				if ((usedCPUs[i] == job.intValue() || usedCPUs[i] == 0)
						&& (Integer.valueOf(-1).equals(jobToNuma.get(job)) || divisionedNUMA.get(coresPerNode.get(Integer.valueOf(i))).equals(divisionedNUMA.get(jobToNuma.get(job)))))
					newMask[i] = 1;
			}

			if (Integer.valueOf(jobNumber).equals(job))
				extendedFinalMask = newMask;

			masksToPin.put(job, newMask);
		}
		isolateJobs(masksToPin, true);
		return extendedFinalMask;
	}

	private int getNumaNode(Long reqCPU, long queueId, Integer previousNuma, HashMap<Integer, Integer> available) {
		int numaNode;
		if (previousNuma == null || previousNuma.intValue() < 0)
			numaNode = (int) (queueId % availablePerNode.keySet().size());
		else
			numaNode = previousNuma.intValue();
		int nodeCount = 0;
		while (nodeCount < available.keySet().size()) {
			if (available.get(Integer.valueOf(numaNode)).intValue() < reqCPU.intValue())
				numaNode = numaNode + 1;
			else
				break;
			nodeCount = nodeCount + 1;
			if (numaNode == available.keySet().size())
				numaNode = 0;
		}
		if (nodeCount == available.keySet().size())
			numaNode = -1;
		return numaNode;
	}

	/**
	 * In case of rearrangement, move jobs to the newly selected cores if needed
	 *
	 * @param auxUsedCPUs new job allocation
	 */
	private void changePinningConfig(int[] auxUsedCPUs) {
		HashMap<Integer, byte[]> masksToPin = new HashMap<>();
		for (int i = 0; i < numCPUs; i++) {
			int jobNum = auxUsedCPUs[i];
			if (jobNum != 0) {
				byte[] initMask = masksToPin.get(Integer.valueOf(jobNum));
				if (initMask == null)
					initMask = new byte[numCPUs];
				initMask[i] = 1;
				masksToPin.put(Integer.valueOf(auxUsedCPUs[i]), initMask);
			}
		}
		isolateJobs(masksToPin, false);
	}

	/**
	 * Constrain the jobs to the given CPU masks
	 *
	 * @param masksToPin
	 */
	private void isolateJobs(HashMap<Integer, byte[]> masksToPin, boolean maskExtension) {
		for (Integer jobId : masksToPin.keySet()) {
			if (!Arrays.equals(JAToMask.get(jobId), masksToPin.get(jobId))) {
				if (activeJAInstances.get(jobId) != null) {
					if (fullMaskCgroupV2) {
						byte[] wholeMask = getFullNUMAMask(jobToNuma.get(jobId));
						String codedMask = arrayToTaskset(wholeMask);
						String targetCgroup = activeJAInstances.get(jobId).agentCgroupV2;
						String patternStr = "(\\d+)-(\\d+)([^\\\"]+)";
						Pattern pattern = Pattern.compile(patternStr);
						Matcher matcher = pattern.matcher(CgroupUtils.getCPUCores(targetCgroup));
						String patternStr2 = "\\d+(,\\d+)*";
						Pattern pattern2 = Pattern.compile(patternStr2);
						Matcher matcher2 = pattern2.matcher(CgroupUtils.getCPUCores(targetCgroup));
						if (matcher.matches() || matcher2.matches()) {
							String toCheck = "";
							if (matcher.matches()) {
								int rangeidx = Integer.parseInt(matcher.group(1));
								toCheck = String.valueOf(rangeidx);
							} else if (matcher2.matches()) {
								String[] cores = CgroupUtils.getCPUCores(targetCgroup).split(",");
								toCheck = cores[0];
							}
							if (!codedMask.contains(toCheck)) {
								logger.log(Level.INFO, "Changed pinning of cgroup " + targetCgroup + " from " + CgroupUtils.getCPUCores(targetCgroup) + " to " + codedMask);
								CgroupUtils.assignCPUCores(targetCgroup, codedMask);
							} else
								logger.log(Level.INFO, "Did not change pinning of cgroup "  + targetCgroup);
						}
					} else {
						int pid = activeJAInstances.get(jobId).getChildPID();
						logger.log(Level.INFO, "Going to apply CPU constraintment to PID " + pid);
						applyTaskset(arrayToTaskset(masksToPin.get(jobId)), pid);
						if (!maskExtension) {
							addPinningTraceLog(masksToPin.get(jobId), jobId);
						}
					}
					JAToMask.put(jobId, masksToPin.get(jobId).clone());
					logger.log(Level.INFO, "Modifying pinning configuration of job ID " + jobId + ". New mask " + getMaskString(JAToMask.get(jobId)));
				}
			}
		}
	}

	private void addPinningTraceLog(byte[] newMask, Integer jobId) {
		long queueId = activeJAInstances.get(jobId).getQueueId();
		int resubmission = activeJAInstances.get(jobId).getResubmission();
		commander.q_api.putJobLog(queueId, resubmission, "proc", "Pinning job to CPUs " + arrayToTaskset(newMask));
	}

	/**
	 * Applies taskset to cores for a given pid
	 *
	 * @param isolCmd cores to pin the job to
	 * @param pidToConstrain PID to pin to the cores
	 */
	public static void applyTaskset(String isolCmd, int pidToConstrain) {
		Vector<Integer> children = MonitoredJob.getChildrenProcessIDs(pidToConstrain);

		if (children != null && isolCmd != null && isolCmd.compareTo("") != 0) {
			for (Integer pid : children) {
				logger.log(Level.INFO, "Constraining PID " + pid);
				try {
					ProcessWithTimeout.executeCommand(Arrays.asList("taskset", "-a", "-cp", isolCmd, String.valueOf(pid)), false, true, 60, TimeUnit.SECONDS);
				}
				catch (final Exception e) {
					logger.log(Level.WARNING, "Could not apply CPU mask: " + e);
				}
			}
		}
	}

	/**
	 * After CPU rearrangement, fill structures
	 *
	 * @param auxUsedCPUs new job allocation
	 */
	private void restartStructures(int[] auxUsedCPUs) {
		logger.log(Level.INFO, "NUMAExplorer reconfiguring after job rescheduling.");
		changePinningConfig(auxUsedCPUs);

		for (Integer node : initialStructurePerNode.keySet()) {
			byte[] nodeMask = initialStructurePerNode.get(node).clone();
			int available = initialAvailablePerNode.get(node).intValue();
			for (int idxMask = 0; idxMask < numCPUs; idxMask++) {
				if (nodeMask[idxMask] == 1 && auxUsedCPUs[idxMask] != 0) {
					nodeMask[idxMask] = 0;
					available = available - 1;
				}
			}
			availablePerNode.put(node, Integer.valueOf(available));
			structurePerNode.put(node, nodeMask);
		}
	}

	private byte[] getPartitionedMask(Long reqCPU, int jobNumber, HashMap<Integer, byte[]> structure, HashMap<Integer, Integer> available, int[] auxUsedCPUs, int prevAbsoluteNuma,
			boolean initAssignment) {
		byte[] finalMask;
		logger.log(Level.INFO, "Computing a partitioned mask for job " + jobNumber);
		HashMap<Integer, Long> freeOnNuma = new HashMap<>();
		for (int i = 0; i < available.keySet().size(); i++) {
			Integer absoluteNuma = divisionedNUMA.get(Integer.valueOf(i));
			int totalFree = 0;
			if (freeOnNuma.containsKey(absoluteNuma))
				totalFree = freeOnNuma.get(absoluteNuma).intValue();
			totalFree = totalFree + available.get(Integer.valueOf(i)).intValue();
			freeOnNuma.put(absoluteNuma, Long.valueOf(totalFree));
		}

		List<Map.Entry<Integer, Long>> freeList = getSortedList(freeOnNuma);

		Map.Entry<Integer, Long> freestEntry = freeList.get(0);
		Integer freestIdx = freestEntry.getKey();
		byte[] availableMask = new byte[numCPUs];
		int availableCores = freestEntry.getValue().intValue();
		if (prevAbsoluteNuma < -1) {
			Integer absoluteNuma = Integer.valueOf((prevAbsoluteNuma + 2) * (-1));
			if (freeOnNuma.get(absoluteNuma).intValue() >= reqCPU.intValue()) {
				availableCores = freeOnNuma.get(absoluteNuma).intValue();
				freestIdx = absoluteNuma;
			}
		}
		if (availableCores >= reqCPU.intValue()) {
			for (int i = 0; i < divisionedNUMA.keySet().size(); i++) {
				if (divisionedNUMA.get(Integer.valueOf(i)).equals(freestIdx)) {
					availableMask = addPinnedCores(structure.get(Integer.valueOf(i)), availableMask);
				}
			}
			jobToNuma.put(Integer.valueOf(jobNumber), Integer.valueOf(-1 * freestIdx.intValue() - 2));
		}
		else {
			for (int i = 0; i < divisionedNUMA.keySet().size(); i++) {
				availableMask = addPinnedCores(structure.get(Integer.valueOf(i)), availableMask);
			}
			jobToNuma.put(Integer.valueOf(jobNumber), Integer.valueOf(-1));
		}
		finalMask = buildFinalMask(availableMask, reqCPU, jobNumber, available, structure, auxUsedCPUs, initAssignment);
		return finalMask;
	}

	/**
	 * After job ends, fills up structures
	 *
	 * @param jobNumber job identifier
	 */
	public synchronized void refillAvailable(int jobNumber) {
		logger.log(Level.INFO, "Reconfiguring structures of NUMAExplorer. Taking out job " + jobNumber);
		for (int i = 0; i < numCPUs; i++) {
			if (usedCPUs[i] == jobNumber) {
				int numaNode = coresPerNode.get(Integer.valueOf(i)).intValue();
				int left = availablePerNode.get(Integer.valueOf(numaNode)).intValue() + 1;
				availablePerNode.put(Integer.valueOf(numaNode), Integer.valueOf(left));
				structurePerNode.get(Integer.valueOf(numaNode))[i] = 1;
				usedCPUs[i] = 0;
			}
		}
		activeJAInstances.remove(Integer.valueOf(jobNumber));
		jobToNuma.remove(Integer.valueOf(jobNumber));
		coresPerJob.remove(Integer.valueOf(jobNumber));
	}

	private static List<Map.Entry<Integer, Long>> getSortedList(HashMap<Integer, Long> freeOnNuma) {
		List<Map.Entry<Integer, Long>> freeList = new LinkedList<>(freeOnNuma.entrySet());
		Collections.sort(freeList, new Comparator<Map.Entry<Integer, Long>>() {
			@Override
			public int compare(Map.Entry<Integer, Long> o1, Map.Entry<Integer, Long> o2) {
				return (o2.getValue().compareTo(o1.getValue()));
			}
		});
		return freeList;
	}

	/**
	 * Core rearrangement for an optimal allocation
	 *
	 * @param newJobNumber job identifier
	 * @param newReqCPU amount of cores requested by new job
	 * @return array containing allocation per job
	 */
	private int[] rearrangeCores(int newJobNumber, Long newReqCPU) {
		logger.log(Level.INFO, "Starting job CPU cores rearrangement");
		coresPerJob.put(Integer.valueOf(newJobNumber), newReqCPU);
		// Init structures of node structure
		int[] auxUsedCPUs = new int[numCPUs];

		HashMap<Integer, Integer> auxAvailablePerNode = new HashMap<>();
		for (Integer node : initialAvailablePerNode.keySet())
			auxAvailablePerNode.put(node, initialAvailablePerNode.get(node));
		HashMap<Integer, byte[]> auxStructurePerNode = new HashMap<>();
		for (Integer node : initialStructurePerNode.keySet())
			auxStructurePerNode.put(node, initialStructurePerNode.get(node).clone());

		List<Map.Entry<Integer, Long>> jobCoreList = getSortedList(coresPerJob);
		for (Map.Entry<Integer, Long> entry : jobCoreList) {
			Long reqCPU = entry.getValue();
			int jobNumber = entry.getKey().intValue();
			long queueId = activeJAInstances.get(entry.getKey()).getQueueId();
			Integer previousNuma = jobToNuma.get(Integer.valueOf(jobNumber));

			int numaNode = getNumaNode(reqCPU, queueId, previousNuma, auxAvailablePerNode);

			// We have not found the space needed in any node. Proceed to partition
			if (numaNode < 0) {
				if (previousNuma != null && previousNuma.intValue() < 0) {
					getPartitionedMask(reqCPU, jobNumber, auxStructurePerNode, auxAvailablePerNode, auxUsedCPUs, previousNuma.intValue(), false);
				}
				else
					getPartitionedMask(reqCPU, jobNumber, auxStructurePerNode, auxAvailablePerNode, auxUsedCPUs, numaNode, false);
			}
			else {
				byte[] availableMask = auxStructurePerNode.get(Integer.valueOf(numaNode));
				buildFinalMask(availableMask, reqCPU, jobNumber, auxAvailablePerNode, auxStructurePerNode, auxUsedCPUs, false);
				jobToNuma.put(Integer.valueOf(jobNumber), Integer.valueOf(numaNode));
			}
		}
		for (int i = 0; i < auxUsedCPUs.length; i++) {
			if (auxUsedCPUs[i] == newJobNumber)
				auxUsedCPUs[i] = 0;
		}
		logger.log(Level.INFO, "The rearrangment result was " + getMaskString(auxUsedCPUs));
		return auxUsedCPUs;
	}

	private byte[] buildFinalMask(byte[] availableMask, Long reqCPU, int jobNumber, HashMap<Integer, Integer> available, HashMap<Integer, byte[]> structure, int[] auxUsedCPUs,
			boolean initAssignment) {
		int remainingCPU = reqCPU.intValue();
		byte[] finalMask = new byte[numCPUs];
		boolean assignmentDone = false;

		for (int i = 0; i < numCPUs; i++) {
			int numaNode = coresPerNode.get(Integer.valueOf(i)).intValue();

			if (initAssignment == true) {
				if ((availableMask[i] == 0 && numaNode > 0 && structure.get(Integer.valueOf(numaNode))[i] == 1) || (assignmentDone == true && availableMask[i] == 1)) {
					structurePerNode.get(Integer.valueOf(numaNode))[i] = 0;
					initialStructurePerNode.get(Integer.valueOf(numaNode))[i] = 0;
					availablePerNode.put(Integer.valueOf(numaNode), Integer.valueOf(availablePerNode.get(Integer.valueOf(numaNode)).intValue() - 1));
					initialAvailablePerNode.put(Integer.valueOf(numaNode), Integer.valueOf(initialAvailablePerNode.get(Integer.valueOf(numaNode)).intValue() - 1));
				}
			}
			if (availableMask[i] == 1 && assignmentDone == false) {
				finalMask[i] = 1;
				remainingCPU = remainingCPU - 1;
				if (initAssignment == false) {
					availableMask[i] = 0;
					auxUsedCPUs[i] = jobNumber;
					int left = available.get(Integer.valueOf(numaNode)).intValue() - 1;
					available.put(Integer.valueOf(numaNode), Integer.valueOf(left));
					structure.put(Integer.valueOf(numaNode), availableMask);
				}
				if (remainingCPU == 0) {
					assignmentDone = true;
				}
			}
		}
		return finalMask;
	}

	static String arrayToTaskset(byte[] array) {
		String out = "";

		for (int i = (array.length - 1); i >= 0; i--) {
			if (array[i] == 1) {
				if (out.length() != 0)
					out += ",";
				out += i;
			}
		}

		return out;
	}

	/**
	 * @return cores map
	 */
	public static int[] getUsedCPUs() {
		return usedCPUs;
	}

	private static byte[] addPinnedCores(byte[] toAdd, byte[] current) {
		byte[] finalMask = current.clone();
		for (int i = 0; i < toAdd.length; i++) {
			if (toAdd[i] == 1)
				finalMask[i] = 1;
		}
		return finalMask;
	}


	public void setFullNUMAMask() {
		this.fullMaskCgroupV2 = true;
	}
}
