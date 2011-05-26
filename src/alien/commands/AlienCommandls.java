package alien.commands;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import lazyj.Format;
import lazyj.Log;

import alien.catalogue.LFN;
import alien.catalogue.LFNUtils;
import alien.user.AliEnPrincipal;
/**
 * @author Alina Grigoras
 * @since May 10, 2011
 * implements AliEn ls command
 * */
public class AlienCommandls extends AlienCommand {
	/**
	 * ls command arguments : -help/l/a
	 */
	private static ArrayList<String> lsArguments = new ArrayList<String>();

	static{
		lsArguments.add("help");
		lsArguments.add("l");
		lsArguments.add("a");
	}

	/**
	 * marker for -help argument 
	 */
	private boolean bHelp =  false;
	
	/**
	 * marker for -l argument 
	 */
	private boolean bL = false;
	
	/**
	 * marker for -a argument
	 */
	@SuppressWarnings("unused")
	private boolean bA = false;

	/**
	 * @param AliEn principal received from https request
	 * @param all arguments received from SOAP request, contains user, current directory and command
	 * @throws Exception
	 */
	public AlienCommandls(final AliEnPrincipal p, final ArrayList<Object> al) throws Exception {
		super(p, al);
	}

	/**
	 * @param AliEn principal received from https request
	 * @param username received from SOAP request, can be different than the one from the https request is the user make a su
	 * @param the directory from the user issued the command
	 * @param the command requested through the SOAP request
	 * @param command arguments, can be size 0 or null
	 * @throws Exception
	 */
	public AlienCommandls (final AliEnPrincipal p, final String sUsername, final String sCurrentDirectory, final String sCommand, final List<?> alArguments) throws Exception {
		super(p, sUsername, sCurrentDirectory, sCommand, alArguments);
	}

	/**
	 * @return a map of <String, List<String>> with only 2 keys
	 * 	<ul>
	 * 		<li>rcvalues - file list</li>
	 * 		<li>rcmessages - file list with an extra \n at the end of the file name</li>
	 * 	</ul>
	 */
	@Override
	public HashMap<String, ArrayList<String>> executeCommand() {
		HashMap<String, ArrayList<String>> hmReturn = new HashMap<String, ArrayList<String>>();

		ArrayList<String> alrcValues = new ArrayList<String>();
		ArrayList<String> alrcMessages = new ArrayList<String>();

		ArrayList<String> alPaths = new ArrayList<String>();

		//we got arguments for ls
		if(this.alArguments != null && this.alArguments.size() > 0){

			for(Object oArg: this.alArguments){
				String sArg = (String) oArg;

				//we got an argument
				if(sArg.startsWith("-")){
					if(sArg.length() == 1){
						alrcMessages.add("Expected argument after \"-\" \n ls -help for more help\n");
					}
					else{
						String sLocalArg = sArg.substring(1);

						if("help".equals(sLocalArg)){
							bHelp = true;
						}
						else{
							char[] sLetters = sLocalArg.toCharArray();

							for(char cLetter : sLetters){

								if(!lsArguments.contains(cLetter+"")){
									alrcMessages.add("Unknown argument "+cLetter+"! \n ls -help for more help\n");
								}
								else{
									if("l".equals(cLetter+""))
										bL = true;

									if("a".equals(cLetter+""))
										bA = true;

								}
							}
						}}
				}
				else{
					//we got paths
					alPaths.add(sArg);
				}
			}
		}
		else{
			alPaths.add(this.sCurrentDirectory);
		}

		if(!bHelp){

			int iDirs = alPaths.size();

			if(iDirs == 0)
				alPaths.add(this.sCurrentDirectory);

			for(String sPath: alPaths){
				//listing current directory
				if(!sPath.startsWith("/"))
					sPath = this.sCurrentDirectory+sPath;

				Log.log(Log.INFO, "Spath = \""+sPath+"\"");

				final LFN entry = LFNUtils.getLFN(sPath);

				//what message in case of error?
				if (entry != null){

					List<LFN> lLFN;

					if (entry.type=='d'){
						lLFN = entry.list();
					}
					else
						lLFN = Arrays.asList(entry);

					if(iDirs != 1){
						alrcMessages.add(sPath+"\n");
					}

					for(LFN localLFN : lLFN){
//						alrcValues.add(bL ? localLFN.getName()) : Format.escHtml(localLFN.getFileName()));
						alrcMessages.add( bL ? Format.escHtml(localLFN.getName()+"\n") : Format.escHtml(localLFN.getFileName()+"\n"));
					}
				}
				else{
					alrcMessages.add("No such file or directory\n");
				}
			}
		}
		else{
			alrcMessages.add("This is ls help. You should write all the crap here\n");
		}

		hmReturn.put("rcvalues", alrcValues);
		hmReturn.put("rcmessages", alrcMessages);

		return hmReturn;
	}

}
