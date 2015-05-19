package alien.api.taskQueue;

import alien.api.Request;
import alien.quotas.FileQuota;
import alien.quotas.QuotaUtilities;
import alien.taskQueue.TaskQueueUtils;
import alien.user.AliEnPrincipal;

public class SetFileQuota extends Request {

	private static final long serialVersionUID = 1286883117531333434L;
	private boolean succeeded;
	private String field;
	private String value;
	private String username;
	
	/**
	 * @param user 
	 * @param role 
	 * @param queueId
	 */
	public SetFileQuota(final AliEnPrincipal user, String fld, String val) {
		this.field = fld;
		this.value = val;
		this.username = user.getName();
	}
	
	@Override
	public void run() {
		if( !AliEnPrincipal.roleIsAdmin( getEffectiveRequester().getName() ) )
			throw new SecurityException( "Only administrators can do it" );
		
		this.succeeded = QuotaUtilities.saveFileQuota( this.username, 
														this.field,
														this.value);		
	}
	
	public boolean getSucceeded(){
		return this.succeeded;
	}
}
