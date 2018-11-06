package alien.shell.commands;

import java.util.HashMap;
import java.util.List;
import java.util.Set;

import alien.catalogue.FileSystemUtils;
import alien.se.SE;
import joptsimple.OptionException;

/**
 * @author costing
 *
 */
public class JAliEnCommandlistSEDistance extends JAliEnBaseCommand {
	private boolean useWriteMetrics;
	private String site;
	private String lfn_name;

	@Override
	public void run() {
		if (!this.useWriteMetrics && (this.lfn_name == null || this.lfn_name.length() == 0)) {
			commander.printErrln("No LFN specified for read metrics");
			return;
		}

		if (lfn_name != null && lfn_name.length() != 0)
			this.lfn_name = FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDirName(), this.lfn_name);
		final List<HashMap<SE, Double>> results = commander.c_api.listSEDistance(site, this.useWriteMetrics, this.lfn_name);
		for (final HashMap<SE, Double> smap : results) {
			final Set<SE> selist = smap.keySet();
			for (final SE s : selist) {
				if (!s.seName.contains("::"))
					continue;

				commander.printOutln(String.format("%1$" + 40 + "s", s.seName) + "\t(read: " + String.format("%.9f", Double.valueOf(s.demoteRead)) + ",  write: "
						+ String.format("%.9f", Double.valueOf(s.demoteWrite)) + ",  distance: " + String.format("%.9f", smap.get(s)) + ")");
			}
		}
		commander.printOutln();
	}

	@Override
	public void printHelp() {
		commander.printOutln();
		commander.printOutln("listSEDistance: Returns the closest working SE for a particular site. Usage");
		commander.printOutln();
		commander.printOutln(" listSEDistance [<site>] [read [<lfn>]|write]");
		commander.printOutln();
		commander.printOutln();
		commander.printOutln(" Options:");
		commander.printOutln("   <site>: site name. Default: current site");
		commander.printOutln("   [read|write]: action. Default write. In the case of read, if an lfn is specified, use only SE that contain that file");
		commander.printOutln();
	}

	@Override
	public boolean canRunWithoutArguments() {
		return true;
	}

	/**
	 * @param commander
	 * @param alArguments
	 * @throws OptionException
	 */
	public JAliEnCommandlistSEDistance(final JAliEnCOMMander commander, final List<String> alArguments) throws OptionException {
		super(commander, alArguments);

		this.useWriteMetrics = true;
		try {
			final int argLen = alArguments.size();
			if (argLen == 0)
				return;
			String arg = alArguments.get(0);
			if (!arg.equals("read") && !arg.equals("write"))
				this.site = arg;
			else
				this.useWriteMetrics = (arg.equals("write"));
			arg = alArguments.get(1);
			if (!arg.equals("read") && !arg.equals("write"))
				this.lfn_name = arg;
			else
				this.useWriteMetrics = (arg.equals("write"));
			arg = alArguments.get(2);
			if (!this.useWriteMetrics && this.lfn_name == null)
				this.lfn_name = arg;
		} catch (@SuppressWarnings("unused") final IndexOutOfBoundsException e) {
			// ignore
		}
	}
}