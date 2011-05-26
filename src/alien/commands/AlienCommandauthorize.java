package alien.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import lazyj.Log;

import alien.soap.services.AuthenEngine;
import alien.user.AliEnPrincipal;

/**
 * @author Alina Grigoras
 * @since May 25, 2011
 * implements AliEn "authorize" command 
 * */
public class AlienCommandauthorize extends AlienCommand {
	/**
	 * @param AliEn principal received from the https request
	 * @param SOAP arguments received from the http request
	 * @throws Exception
	 */
	public AlienCommandauthorize(final AliEnPrincipal p, final ArrayList<Object> al) throws Exception {
		super(p, al);
	}

	/**
	 * @param AliEn principal received from the https request
	 * @param username received from SOAP request. It can be a different user than the user received through the AliEn principal (the user can su into a different user)
	 * @param current directory when the command was issued
	 * @param the command requested by the user
	 * @param the arguments to the commnad, can be null or empty
	 * @throws Exception
	 */
	public AlienCommandauthorize (final AliEnPrincipal p, final String sUsername, final String sCurrentDirectory, final String sCommand, final List<?> alArguments) throws Exception {
		super(p, sUsername, sCurrentDirectory, sCommand, alArguments);
	}

	/**
	 * execute authorize command <br>
	 * the list of arguments 
	 * 		<ul>
	 * 			<li>first argument must contain the access string: 
	 * 				write/read/mirror/register/delete/registerenvs 
	 * 			</li>
	 * 			<li>second argument can be an array list if access is "registerenvs" or a map for the rest </li>
	 * 			<li>third arguments appears only in the case of map and it is the job id </li>
	 * 		</ul>
	 * @return 	 the response is a map with the keys: 
	 * 		<ul>
	 * 			<li>rcvalues - the actual values used by the command </li> 
	 * 			<li>rcmessages - the printed logs </li>
	 * 		</ul>
	 */
	@Override
	public HashMap<String, ArrayList<String>> executeCommand() throws Exception{
		Log.log(Log.FINER, "Entering authorize command");
		
		HashMap<String, ArrayList<String>> hmReturn = new HashMap<String, ArrayList<String>>();

		ArrayList<String> alrcValues = new ArrayList<String>();
		ArrayList<String> alrcMessages = new ArrayList<String>();
		
		boolean bDebug = false;

		alrcMessages.add("This is just a simple log\n");

		//we need to have at least 2 parameters
		if(this.alArguments != null && this.alArguments.size() >= 2){
			//first argument must be access string
			String sAccess = (String) this.alArguments.get(0);
			Log.log(Log.FINER, "Authorize access = "+sAccess);
			
			String sJobId = null;

			if(this.alArguments.size() == 3){
				sJobId = (String) this.alArguments.get(2);
				
				if(sJobId.startsWith("-debug")) {
					bDebug = true;
					sJobId = "0";
				}
			}
			
			Log.log(Log.FINER, "Authorize Job id = "+sJobId);

			if("registerenvs".equals(sAccess)){
				@SuppressWarnings({ "unused", "unchecked" })
				ArrayList<String> alInfo = (ArrayList<String>) this.alArguments.get(1);
		
			}
			else{
				@SuppressWarnings("unchecked")
				HashMap<String, String> hmInfo = (HashMap<String, String>) this.alArguments.get(1);
				
				AuthenEngine au = new AuthenEngine();
				alrcValues = (ArrayList<String>) au.authorizeEnvelope(this.pAlienUser, this.sUsername, this.sCurrentDirectory , sAccess, hmInfo, sJobId);
			}

		}
		else{
			throw new Exception("Invalid authorize command arguments");		
		}

		if(!bDebug) alrcMessages.clear();

		hmReturn.put("rcvalues", alrcValues);
		hmReturn.put("rcmessages", alrcMessages);

		Log.log(Log.FINER, "Existing authorize command");
		
		return hmReturn;
	}

}
