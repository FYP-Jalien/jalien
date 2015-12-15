package alien.api.taskQueue;

import alien.api.Request;
import alien.taskQueue.TaskQueueUtils;

/**
 * Put a job log
 * 
 * @author mmmartin
 * @since Dec 15, 2015
 */
public class PutJobLog extends Request {
	/**
	 * 
	 */
	private static final long serialVersionUID = -6330031807464568555L;
	private final int jobnumber;
	private final String tag;
	private final String message;
	
	/**
	 * @param jobnumber 
	 * @param status 
	 */
	public PutJobLog(int jobnumber, String tag, String message){
		this.jobnumber = jobnumber;
		this.tag = tag;
		this.message = message;
	}
	
	@Override
	public void run() {
		TaskQueueUtils.putJobLog(jobnumber, tag, message, null);
	}

	
	@Override
	public String toString() {
		return "Asked to put joblog ["+this.tag+"-"+this.message+"] for job: "+this.jobnumber;
	}
}
