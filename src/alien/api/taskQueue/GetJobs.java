package alien.api.taskQueue;

import java.util.ArrayList;
import java.util.List;

import alien.api.Request;
import alien.taskQueue.TaskQueueFakeUtils;
import alien.taskQueue.Job;
import alien.taskQueue.TaskQueueUtils;
import alien.user.AliEnPrincipal;

/**
 * Get a JDL object
 * 
 * @author ron
 * @since Oct 28, 2011
 */
public class GetJobs extends Request {


	
	private List<Job> jobs;
	
	private final List<Integer> queueIds;
	
	/**
	 * @param user 
	 * @param role 
	 * @param queueIds
	 */
	public GetJobs(final AliEnPrincipal user, final String role, List<Integer> queueIds){
		setRequestUser(user);
		setRoleRequest(role);
		this.queueIds = queueIds;
	}
	
	@Override
	public void run() {
		jobs = new ArrayList<Job>(queueIds.size());
		for(int qId: queueIds)
			jobs.add(TaskQueueUtils.getJob(qId));
	}
	
	/**
	 * @return the Jobs
	 */
	public List<Job> getJobs(){
		return this.jobs;
	}
	
	@Override
	public String toString() {
		return "Asked for Jobs :  reply is: "+this.jobs;
	}
}
