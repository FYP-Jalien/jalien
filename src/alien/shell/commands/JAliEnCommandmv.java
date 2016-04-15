package alien.shell.commands;

import java.util.ArrayList;
import java.util.List;

import alien.catalogue.FileSystemUtils;
import alien.catalogue.LFN;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;

/**
 * @author ron
 * @since June 4, 2011
 * @author sraje (Shikhar Raje, IIIT Hyderabad)
 * @since Modified July 1, 2012
 */
@SuppressWarnings("unused")
public class JAliEnCommandmv extends JAliEnBaseCommand {

	private String[] sources = null;

	private String target = null;

	/**
	 * Size of the argument list.
	 */
	int size = 0;

	@Override
	public void run() {
		final String fullTarget = FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDir().getCanonicalName(), target);
		LFN tLFN = commander.c_api.getLFN(fullTarget, false);

		if (size > 2) {
			if ((tLFN != null && tLFN.isDirectory()))
				for (int i = 0; i <= size - 2; i++) {
					final String fullSource = FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDir().getCanonicalName(), sources[i]);
					final LFN sLFN = commander.c_api.getLFN(fullSource, false);

					if (sLFN.isFile() || sLFN.isDirectory()) {
						tLFN = commander.c_api.moveLFN(sLFN.getCanonicalName(), fullTarget + "/" + sLFN.getFileName());
						if (out.isRootPrinter())
							out.setReturnArgs(deserializeForRoot(1));
					}
				}
			else if (tLFN == null) {
				tLFN = commander.c_api.createCatalogueDirectory(fullTarget, true);
				for (int i = 0; i <= size - 2; i++) {
					final String fullSource = FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDir().getCanonicalName(), sources[i]);
					final LFN sLFN = commander.c_api.getLFN(fullSource, false);

					if (sLFN.isFile() || sLFN.isDirectory()) {
						tLFN = commander.c_api.moveLFN(sLFN.getCanonicalName(), fullTarget + "/" + sLFN.getFileName());
						if (out.isRootPrinter())
							out.setReturnArgs(deserializeForRoot(1));
					}
				}
			} else {
				out.printErrln("If there are more than 2 arguments, then last one must be an existing direcetory OR a location that does not exist and can be made as new directory");
				if (out.isRootPrinter())
					out.setReturnArgs(deserializeForRoot(0));
			}
		}

		else if (size == 2) {
			final String fullSource = FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDir().getCanonicalName(), sources[0]);
			final LFN sLFN = commander.c_api.getLFN(fullSource, false);

			if (tLFN != null) {
				if (sLFN.isFile() && tLFN.isFile()) {
					// TODO File overwrite mechanism
					tLFN = commander.c_api.moveLFN(sLFN.getCanonicalName(), fullTarget + "_backup");
					if (out.isRootPrinter())
						out.setReturnArgs(deserializeForRoot(1));
				} else if ((sLFN.isDirectory() && tLFN.isDirectory()) || (sLFN.isFile() && tLFN.isDirectory())) {
					tLFN = commander.c_api.moveLFN(sLFN.getCanonicalName(), fullTarget + "/" + sLFN.getFileName());
					if (out.isRootPrinter())
						out.setReturnArgs(deserializeForRoot(1));
				} else {
					if (out.isRootPrinter())
						out.setField("error ",
								"If there are 2 arguments then only:\n1. File to file\n2. File to directory\n3. Directory to Directory\n is supported\nMost probably a directory to file mv is being attempted");
					else
						out.printErrln(
								"If there are 2 arguments then only:\n1. File to file\n2. File to directory\n3. Directory to Directory\n is supported\nMost probably a directory to file mv is being attempted");
					if (out.isRootPrinter())
						out.setReturnArgs(deserializeForRoot(0));
				}
			}

			else {
				if (target.contains("/") && !target.endsWith("/")) {
					tLFN = commander.c_api.createCatalogueDirectory(fullTarget, true);
					tLFN = commander.c_api.moveLFN(sLFN.getCanonicalName(), fullTarget + "/" + sLFN.getFileName());
				} else
					tLFN = commander.c_api.moveLFN(sLFN.getCanonicalName(), fullTarget);

				if (out.isRootPrinter())
					out.setReturnArgs(deserializeForRoot(1));
			}
		}

		else if (size == 0 || size == 1)
			printHelp();
	}

	/**
	 * printout the help info, none for this command
	 */
	@Override
	public void printHelp() {
		out.printOutln();
		out.printOutln(helpUsage("mv", " <LFN>  <newLFN> > " + ""));
		out.printOutln();
	}

	/**
	 */
	@Override
	public boolean canRunWithoutArguments() {
		return false;
	}

	/**
	 * Constructor needed for the command factory in commander
	 *
	 * @param commander
	 * @param out
	 *
	 * @param alArguments
	 *            the arguments of the command
	 */
	public JAliEnCommandmv(final JAliEnCOMMander commander, final UIPrintWriter out, final ArrayList<String> alArguments) {
		super(commander, out, alArguments);
		try {
			final OptionParser parser = new OptionParser();

			final OptionSet options = parser.parse(alArguments.toArray(new String[] {}));

			final List<String> nonOptionArguments = optionToString(options.nonOptionArguments());

			size = nonOptionArguments.size();
			sources = new String[size - 1];
			for (int i = 0; i <= (size - 2); i++)
				sources[i] = nonOptionArguments.get(i);

			target = nonOptionArguments.get(size - 1);

		} catch (final OptionException e) {
			printHelp();
			throw e;
		}
	}
}

// package alien.shell.commands;
//
// import java.util.ArrayList;
//
// import joptsimple.OptionException;
// import joptsimple.OptionParser;
// import joptsimple.OptionSet;
// import alien.catalogue.FileSystemUtils;
// import alien.catalogue.LFN;
//
// /**
// * @author ron
// * @since June 4, 2011
// */
// public class JAliEnCommandmv extends JAliEnBaseCommand {
//
//
//
// private String source = null;
//
// private String target = null;
//
// private String fullTarget = null;
//
// private String fullSource = null;
//
// @Override
// public void run()
// {
// LFN sLFN = commander.c_api.getLFN(FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDir().getCanonicalName(), source), false);
//
// if(sLFN!=null)
// {
// fullTarget = FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDir().getCanonicalName(), target);
//
// LFN tLFN = commander.c_api.getLFN(fullTarget, false);
//
// if(tLFN==null)
// {
// tLFN = commander.c_api.moveLFN(sLFN.getCanonicalName(), fullTarget);
// if (out.isRootPrinter())
// out.setReturnArgs(deserializeForRoot(1));
//
// }
// else
// {
// out.printErrln("File already exists.");
// if (out.isRootPrinter())
// out.setReturnArgs(deserializeForRoot(0));
// }
//
// fullSource = FileSystemUtils.getAbsolutePath(commander.user.getName(), commander.getCurrentDir().getCanonicalName(), source)
// }
// else
// {
// out.printErrln("No such directory.");
// if (out.isRootPrinter())
// out.setReturnArgs(deserializeForRoot(0));
// }
//
// }
//
// /**
// * printout the help info, none for this command
// */
// @Override
// public void printHelp() {
// out.printOutln();
// out.printOutln(helpUsage("mv"," <LFN> <newLFN> > " +
// ""));
// out.printOutln();
// }
//
// /**
// * cd can run without arguments
// * @return <code>true</code>
// */
// @Override
// public boolean canRunWithoutArguments() {
// return false;
// }
//
//
// /**
// * Constructor needed for the command factory in commander
// * @param commander
// * @param out
// *
// * @param alArguments
// * the arguments of the command
// */
// public JAliEnCommandmv(JAliEnCOMMander commander, UIPrintWriter out, final ArrayList<String> alArguments){
// super(commander, out,alArguments);
// try {
// final OptionParser parser = new OptionParser();
//
// final OptionSet options = parser.parse(alArguments
// .toArray(new String[] {}));
//
// if (options.nonOptionArguments().size() != 2) {
// printHelp();
// return;
// }
//
// source = options.nonOptionArguments().get(0);
// target = options.nonOptionArguments().get(1);
//
// } catch (OptionException e) {
// printHelp();
// throw e;
// }
// }
// }