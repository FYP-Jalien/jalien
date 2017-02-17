package alien.site.supercomputing.titan;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.InvalidParameterException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedList;
import java.util.List;

import lia.util.Utils;

public class TitanBatchInfo{
	public final Long pbsJobId;
	public final String dbName;
	public final String clearDbName;
	private final String monitoringDbName;
	public final String jobWorkdir;
	public Integer origTtl;
	public Integer numCores;
	public Long startTimestamp;

	private static final String dbFilename = "jobagent.db";
	private static final String dbProtocol = "jdbc:sqlite:";
	private static final String monitoringDbSuffix = ".monitoring";

	public TitanBatchInfo(Long jobid, String workdir) throws Exception{
		pbsJobId = jobid;
		jobWorkdir = workdir;
		dbName = dbProtocol + jobWorkdir + "/" + dbFilename;
		clearDbName = jobWorkdir + "/" + dbFilename;
		monitoringDbName = dbName + monitoringDbSuffix;

		if(!readBatchInfo()){
			System.out.println("No need to reinitialize batch " + pbsJobId);
			return;
		}

		if(!isRunning()){
			cleanup();
			//throw new InvalidParameterException("");
		}

		initializeDb();
		initializeMonitoringDb();
	}


	/* indicates whether it is necessary to reinitialize db according to data read */
	private boolean readBatchInfo() throws Exception{
		try{
			Connection connection = DriverManager.getConnection(dbName);
			Statement statement = connection.createStatement();
			ResultSet rs = statement.executeQuery("SELECT ttl, cores, started FROM jobagent_info");
			if(rs.next()){
				origTtl = rs.getInt("ttl");
				numCores = rs.getInt("cores");
				numCores /= 400;
				startTimestamp = rs.getLong("started");
			}
			else{
				throw new IllegalArgumentException("No batch info provided in the databases");
			}
			rs.close();
			rs = statement.executeQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='alien_jobs'");
			if(rs.next()){
				rs.close();
				return false;
			}

			connection.close();
		} catch(SQLException e){
			System.err.println("Reading wrapper info failed: " + e.getMessage());
			throw e;
		}

		return true;
	}

	public boolean isRunning(){
		ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", "qstat " + pbsJobId 
				+ " 2>/dev/null | tail -n 1 | awk '{print $5}'");
		try{
			Process p = pb.start();
			BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line = null;
			while ( (line = reader.readLine()) != null) {
				System.out.println("Qstat line: '" + line + "'");
				if(line.equals("R"))
					return true;
			}
		}
		catch(Exception e){
			System.err.println("Exception checking whether batch is running: " + e.getMessage());
			return false;
		}
		return false;
	}

	public void cleanup(){
		Utils.getOutput("rm -rf " + jobWorkdir);
	}

	private void initializeDb(){
		try{
			Connection connection = DriverManager.getConnection(dbName);
			Statement statement = connection.createStatement();
			//statement.executeUpdate("DROP TABLE IF EXISTS alien_jobs");
			statement.executeUpdate("PRAGMA journal_mode = TRUNCATE");
			statement.executeUpdate("CREATE TABLE alien_jobs (rank INTEGER NOT NULL, " +
					"queue_id VARCHAR(20), " + 
					"user VARCHAR(20), " + 
					"masterjob_id VARCHAR(20), " + 
					"job_folder VARCHAR(256) NOT NULL, " +
					"status CHAR(1), " +
					"executable VARCHAR(256), " +
					"validation VARCHAR(256),"+
					"environment TEXT," +
					"exec_code INTEGER DEFAULT -1, val_code INTEGER DEFAULT -1)");
			statement.executeUpdate("CREATE TEMPORARY TABLE numbers(n INTEGER)");
			statement.executeUpdate("INSERT INTO numbers " +
					"select 1 " +
					"from (" +
					"select 0 union select 1 union select 2 " +
					") a, (" +
					"select 0 union select 1 union select 2 union select 3 " +
					"union select 4 union select 5 union select 6 " +
					"union select 7 union select 8 union select 9" +
					") b, (" +
					"select 0 union select 1 union select 2 union select 3 " +
					"union select 4 union select 5 union select 6 " +
					"union select 7 union select 8 union select 9" +
					") c, (" +
					"select 0 union select 1 union select 2 union select 3 " +
					"union select 4 union select 5 union select 6 " +
					"union select 7 union select 8 union select 9" +
					") d, (" +
					"select 0 union select 1 union select 2 union select 3 " +
					"union select 4 union select 5 union select 6 " +
					"union select 7 union select 8 union select 9" +
					") e, (" +
					"select 0 union select 1 union select 2 union select 3 " +
					"union select 4 union select 5 union select 6 " +
					"union select 7 union select 8 union select 9" +
					") f");
			//statement.executeUpdate(String.format("INSERT INTO alien_jobs SELECT rowid-1, 0, '', " +
			//			"0, '', 'I', '', '', '', 0, 0 FROM numbers LIMIT %d", numCores));
			statement.executeUpdate( String.format("INSERT INTO alien_jobs "+
						"SELECT rowid-1, " +
						"replace(substr(quote(zeroblob((20 + 1)/2)), 3, 20),'0','X')," +
						"replace(substr(quote(zeroblob((20 + 1)/2)), 3, 20),'0','X')," +
						"replace(substr(quote(zeroblob((20 + 1)/2)), 3, 20),'0','X')," +
						"replace(substr(quote(zeroblob((256 + 1)/2)), 3, 256),'0','X')," +
						"'I', "+
						"replace(substr(quote(zeroblob((256 + 1)/2)), 3, 256),'0','X')," +
						"replace(substr(quote(zeroblob((256 + 1)/2)), 3, 256),'0','X')," +
						"'', 0, 0 " + 
						"FROM numbers LIMIT %d", numCores));
			statement.executeUpdate("DROP TABLE numbers");
			connection.close();
		} 
		catch(SQLException e){
			System.err.println(e);
		}
	}

	private void initializeMonitoringDb(){
		try{	
			Connection connection = DriverManager.getConnection(monitoringDbName);
			Statement statement = connection.createStatement();
			statement.executeUpdate("DROP TABLE IF EXISTS alien_jobs_monitoring");
			statement.executeUpdate("CREATE TABLE alien_jobs_monitoring (queue_id VARCHAR(20), resources VARCHAR(100))");
			connection.close();
		} 
		catch(SQLException e){
			System.err.println(e);
		}
	}

	public List<TitanJobStatus> getIdleRanks() throws Exception{
		LinkedList<TitanJobStatus> idleRanks = new LinkedList<TitanJobStatus>();
		if( !(new File(clearDbName).isFile()))
			return idleRanks;
		try{
			Connection connection = DriverManager.getConnection(dbName);
			Statement statement = connection.createStatement();
			ResultSet rs = statement.executeQuery("SELECT rank, queue_id, job_folder, status, exec_code, val_code FROM alien_jobs WHERE status='D' OR status='I'");
			while(rs.next()){
				idleRanks.add(new TitanJobStatus(rs.getInt("rank"), 
							rs.getLong("queue_id"), rs.getString("job_folder"), 
							rs.getString("status"), rs.getInt("exec_code"), 
							rs.getInt("val_code"), this));
			}

			connection.close();
		} catch(SQLException e){
			System.err.println("Getting free slots failed: " + e.getMessage());
			throw e;
		}

		return idleRanks;
	}

	public List<TitanJobStatus> getRunningRanks() throws Exception{
		LinkedList<TitanJobStatus> runningRanks = new LinkedList<TitanJobStatus>();
		if( !(new File(clearDbName).isFile()) )
			return runningRanks;
		try{
			Connection connection = DriverManager.getConnection(dbName);
			Statement statement = connection.createStatement();
			ResultSet rs = statement.executeQuery("SELECT rank, queue_id, job_folder, status, exec_code, val_code FROM alien_jobs WHERE status='R'");
			while(rs.next()){
				runningRanks.add(new TitanJobStatus(rs.getInt("rank"), rs.getLong("queue_id"), rs.getString("job_folder"), 
							rs.getString("status"), rs.getInt("exec_code"), rs.getInt("val_code"), this));
			}

			connection.close();
		} catch(SQLException e){
			System.err.println("Getting free slots failed: " + e.getMessage());
			throw e;
		}

		return runningRanks;
	}

	public Long getTtlLeft(Long currentTimestamp){
		return origTtl - (currentTimestamp - startTimestamp);
	}

	public final List<ProcInfoPair> getMonitoringData(){
		List<ProcInfoPair> l = new LinkedList<>();
		try{
			// open db
			Connection connection = DriverManager.getConnection(monitoringDbName);
			Statement statement = connection.createStatement();
			ResultSet rs = statement.executeQuery("SELECT * FROM alien_jobs_monitoring");
			// read all
			while(rs.next()){
				l.add(new ProcInfoPair( rs.getString("queue_id"), rs.getString("resources")));
			}
			// delete all
			statement.executeUpdate("DELETE FROM alien_jobs_monitoring");
			// close database
			connection.close();
		}
		catch(SQLException e){
			System.err.println("Unable to get monitoring data: " + e.getMessage());
		}
		return l;
	}

	/* public boolean save(final TitanJobStatus js){
	   try{
	   Connection connection = DriverManager.getConnection(dbName);
	   Statement statement = connection.createStatement();
	//ResultSet rs = statement.executeQuery("SELECT rank, queue_id, job_folder, status, exec_code, val_code FROM alien_jobs WHERE status='D' OR status='I'");
	ResultSet rs = statement.executeUpdate(String.format("UPDATE alien_jobs SET status='%s', job_folder='%s', exec_code=0, val_code=0, queue_id=", ));

	statement.executeUpdate(String.format("UPDATE alien_jobs SET queue_id=%d, job_folder='%s', status='%s', executable='%s', validation='%s', environment='%s' " + 
	"WHERE rank=%d", 
	queueId, tempDir, "Q", 
	getLocalCommand(jdl.gets("Executable"), jdl.getArguments()),
	validationCommand!=null ? getLocalCommand(validationCommand, null) : "",
	"", current_rank ));
	connection.close();
	} catch(SQLException e){
	System.err.println("Job status update failed: " + e.getMessage());
	return false;
	}

	return true;
	} */
}
