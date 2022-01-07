package alien.api.taskQueue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import alien.api.Request;
import alien.taskQueue.JobStatus;
import alien.taskQueue.TaskQueueUtils;

/**
 * Get a JDL object
 *
 * @author ron
 * @since Jun 05, 2011
 */
public class SetJobStatus extends Request {
	/**
	 *
	 */
	private static final long serialVersionUID = -6330031807464568209L;
	private final long jobnumber;
	private final int resubmission;
	private final JobStatus status;
	private final HashMap<String, Object> extrafields;

	/**
	 * @param jobnumber
	 * @param resubmission
	 * @param status
	 */
	public SetJobStatus(final long jobnumber, final int resubmission, final JobStatus status) {
		this.jobnumber = jobnumber;
		this.resubmission = resubmission;
		this.status = status;
		this.extrafields = null;
	}

	/**
	 * @param jobnumber
	 * @param resubmission
	 * @param status
	 * @param extrafields
	 */
	public SetJobStatus(final long jobnumber, final int resubmission, final JobStatus status, final HashMap<String, Object> extrafields) {
		this.jobnumber = jobnumber;
		this.resubmission = resubmission;
		this.status = status;
		this.extrafields = extrafields;
	}

	@Override
	public List<String> getArguments() {
		return Arrays.asList(String.valueOf(jobnumber), status != null ? status.toString() : null, extrafields != null ? extrafields.toString() : null);
	}

	@Override
	public void run() {
		if (TaskQueueUtils.getResubmission(Long.valueOf(this.jobnumber)) != resubmission) {
			setException(new JobKilledException("This job is not supposed to be running any more", null));
			return;
		}

		TaskQueueUtils.setJobStatus(this.jobnumber, this.status, null, this.extrafields);

		if (this.extrafields != null)
			this.extrafields.clear();
	}

	@Override
	public String toString() {
		return "Asked to set job [" + this.jobnumber + "] to status: " + this.status;
	}
}
