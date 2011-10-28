package alien.api.taskQueue;

import alien.api.Request;
import alien.taskQueue.TaskQueueFakeUtils;
import alien.taskQueue.Job;
import alien.taskQueue.TaskQueueUtils;
import alien.user.AliEnPrincipal;

/**
 * Get a JDL object
 * 
 * @author ron
 * @since Jun 05, 2011
 */
public class GetJob extends Request {



	/**
	 * 
	 */
	private static final long serialVersionUID = -3575992501982425989L;
	
	private Job job;
	
	private final int queueId;
	private final boolean loadJDL;
	
	/**
	 * @param user 
	 * @param role 
	 * @param queueId 
	 * @param loadJDL 
	 */
	public GetJob(final AliEnPrincipal user, final String role, final int queueId, final boolean loadJDL){
		setRequestUser(user);
		setRoleRequest(role);
		this.queueId = queueId;
		this.loadJDL = loadJDL;
	}
	
	/**
	 * @param user 
	 * @param role 
	 * @param queueId 
	 */
	public GetJob(final AliEnPrincipal user, final String role, final int queueId){
		setRequestUser(user);
		setRoleRequest(role);
		this.queueId = queueId;
		this.loadJDL = false;
	}
	
	@Override
	public void run() {
		this.job = TaskQueueUtils.getJob(queueId, loadJDL);
	}
	
	/**
	 * @return the Job
	 */
	public Job getJob(){
		return this.job;
	}
	
	@Override
	public String toString() {
		return "Asked for Job :  reply is: "+this.job;
	}
}
