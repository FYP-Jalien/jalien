package alien.site.containers;

import java.util.ArrayList;
import java.util.List;

/**
 * @author mstoretv
 */
public class Apptainer extends Containerizer {

	@Override
	public List<String> containerize(final String cmd) {
		return containerize(cmd, true);
	}

	/**
	 * @param cmd
	 * @param containall
	 * @return the command line arguments to pass to apptainer
	 */
	public List<String> containerize(final String cmd, boolean containall) {
		final List<String> apptainerCmd = new ArrayList<>();
		apptainerCmd.add(getBinPath());
		apptainerCmd.add("exec");

		if (containall)
			apptainerCmd.add("-C");

		if (useGpu) {
			final String gpuString = getGPUString();
			if (gpuString.contains("nvidia"))
				apptainerCmd.add("--nv");
			else if (gpuString.contains("kfd"))
				apptainerCmd.add("--rocm");
		}

		apptainerCmd.add("-B");
		if (workdir != null) {
			apptainerCmd.add(getCustomBinds() + getGPUdirs() + "/cvmfs:/cvmfs," + workdir + ":" + CONTAINER_JOBDIR + "," + workdir + "/tmp:/tmp");
			apptainerCmd.add("--pwd");
			apptainerCmd.add(CONTAINER_JOBDIR);
		}
		else
			apptainerCmd.add("/cvmfs:/cvmfs");

		apptainerCmd.add(containerImgPath);
		apptainerCmd.add("/bin/bash");
		apptainerCmd.add("-c");
		
		if (containall) {
			apptainerCmd.add(sourceEnvCmd() + debugCmd + cmd);
		}
		else
			apptainerCmd.add(debugCmd + cmd);
	
		return apptainerCmd;
	}

	/**
	 * @return apptainer command to execute, default simply "apptainer" but can be overriden with the $FORCE_BINPATH environment variable
	 */
	@SuppressWarnings("static-method")
	protected String getBinPath() {
		return System.getenv().getOrDefault("FORCE_BINPATH", "apptainer");
	}
}
