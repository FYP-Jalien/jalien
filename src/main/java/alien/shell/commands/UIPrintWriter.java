package alien.shell.commands;

/**
 * @author ron
 * @since July 15, 2011
 */
public abstract class UIPrintWriter {

	/**
	 * Print set output black'n white
	 */
	abstract protected void blackwhitemode();

	/**
	 * Print set output mode to color
	 */
	abstract protected void colourmode();

	/**
	 * Print get the color output mode
	 *
	 * @return state of the color mode
	 */
	abstract protected boolean colour();

	/**
	 * Add this line as it is
	 *
	 * @param line
	 */
	abstract protected void printOut(String line);

	/**
	 * Print empty stdout line
	 */
	final protected void printOutln() {
		printOut("\n");
	}

	/**
	 * Print stdout after appending line feed
	 *
	 * @param line
	 */
	final protected void printOutln(final String line) {
		printOut(line + "\n");
	}

	/**
	 * Print stderr line
	 *
	 * @param line
	 */
	abstract protected void printErr(String line);

	/**
	 * Print empty stderr line
	 */
	final protected void printErrln() {
		printErr("\n");
	}

	/**
	 * Print stderr after appending line feed
	 *
	 * @param line
	 */
	final protected void printErrln(final String line) {
		printErr(line + "\n");
	}

	/**
	 * Set the env for the client (needed for gapi)
	 *
	 * @param cDir
	 * @param user
	 */
	abstract protected void setenv(String cDir, String user);

	/**
	 * Flush a set of lines as one transaction
	 */
	abstract protected void flush();

	/**
	 *
	 */
	abstract protected void pending();

	/**
	 * identify the RootPrinter from above
	 *
	 * @return if it is a RootPrinter
	 */
	@SuppressWarnings("static-method")
	protected boolean isRootPrinter() {
		return false;
	}

	/**
	 * dummy for RootPrinter
	 *
	 * @param args
	 */
	protected void setReturnArgs(final String args) {
		// void
	}

	/**
	 * Move to the next result
	 */
	abstract protected void nextResult();

	/**
	 * Set the value for one field
	 * 
	 * @param key
	 * @param value
	 */
	abstract public void setField(final String key, final String value);

	/**
	 * Set command exit code
	 * 
	 * @param exitCode
	 * @param errorMessage
	 */
	abstract public void setReturnCode(final int exitCode, final String errorMessage);

	/**
	 * Get the exit code of the command
	 * 
	 * @return the exit code
	 */
	abstract public int getReturnCode();

	/**
	 * Set metadata information
	 * 
	 * @param key
	 * @param value
	 */
	abstract public void setMetaInfo(String key, String value);

	/**
	 * Get a value from metainfo
	 *
	 * @param key the field you are interested in
	 */
	abstract public String getMetaInfo(String key);

	/**
	 * Get the command's error message if any
	 * 
	 * @return the error string
	 */
	abstract public String getErrorMessage();
}
