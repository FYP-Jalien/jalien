package alien.shell.commands;

import java.util.List;

import alien.catalogue.FileSystemUtils;

/**
 *
 */
public class JAliEnCommandtouch_csd extends JAliEnBaseCommand {
	private final List<String> filelist;

	@Override
	public void run() {
		for (final String path : this.filelist) {
			if (commander.c_api.touchLFNCSD(FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDirName(), path)) == null) {
				commander.setReturnCode(1, "Failed to touch the LFN: " + FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDirName(), path));
			}
		}
	}

	@Override
	public void printHelp() {
		commander.printOutln();
		commander.printOutln(helpUsage("touch_csd", " <LFN> [<LFN>[,<LFN>]]"));
		commander.printOutln();
	}

	@Override
	public boolean canRunWithoutArguments() {
		return false;
	}

	/**
	 * Constructor needed for the command factory in commander
	 *
	 * @param commander
	 *
	 * @param alArguments
	 *            the arguments of the command
	 */
	public JAliEnCommandtouch_csd(final JAliEnCOMMander commander, final List<String> alArguments) {
		super(commander, alArguments);

		filelist = alArguments;
	}
}
