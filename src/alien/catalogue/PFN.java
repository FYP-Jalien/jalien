package alien.catalogue;

import java.io.Serializable;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

import alien.catalogue.access.AccessTicket;
import alien.catalogue.access.XrootDEnvelope;
import alien.config.ConfigUtils;
import alien.monitoring.Monitor;
import alien.monitoring.MonitorFactory;
import alien.se.SE;

import lazyj.DBFunctions;

/**
 * Wrapper around a G*L_PFN row
 * 
 * @author costing
 *
 */
public class PFN implements Serializable, Comparable<PFN>{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 3854116042004576123L;

	/**
	 * Logger
	 */
	static transient final Logger logger = ConfigUtils.getLogger(PFN.class.getCanonicalName());
	
	/**
	 * Monitoring component
	 */
	static transient final Monitor monitor = MonitorFactory.getMonitor(PFN.class.getCanonicalName());
	
	/**
	 * guidID
	 */
	public int guidId;
	
	/**
	 * PFN 
	 */
	public String pfn;
	
	/**
	 * SE number
	 */
	public int seNumber;
	
	/**
	 * index
	 */
	public int host;
	
	/**
	 * table name
	 */
	public int tableNumber;
	
	/**
	 * GUID references
	 */
	private UUID uuid;
	
	/**
	 * GUID
	 * @see #getGuid()
	 */
	private GUID guid;
	
	private Set<PFN> realPFNs = null;

	/**
	 * Access ticket, if needed
	 */
	public AccessTicket ticket = null;
	

	/**
	 * XrootDEnvelope, if needed
	 */
	public XrootDEnvelope envelope = null;
	
	/**
	 * @param db
	 * @param host
	 * @param tableNumber
	 */
	PFN(final DBFunctions db, final int host, final int tableNumber){
		this.host = host;
		this.tableNumber = tableNumber;
		
		init(db);
	}
	
	private void init(final DBFunctions db){
		guidId = db.geti("guidId");
		
		pfn = db.gets("pfn");
		
		seNumber = db.geti("seNumber");
	}
	
	/**
	 * Generate a new PFN
	 * 
	 * @param guid
	 * @param se
	 */
	public PFN(final GUID guid, final SE se){
		this.guidId = guid.guidId;
		this.pfn = se.generatePFN(guid);
		this.seNumber = se.seNumber;
		this.host = guid.host;
		this.tableNumber = guid.tableName;
	}
	
	
	@Override
	public String toString() {
		return "PFN: guidId\t: "+guidId+"\n"+
		       "pfn\t\t: "+pfn+"\n"+
		       "seNumber\t: "+seNumber;
	}
	
	/**
	 * @return the physical locations
	 */
	public Set<PFN> getRealPFNs(){
		if (realPFNs!=null)
			return realPFNs;
		
		if (pfn.startsWith("guid://")){
			int idx = 7;
			
			String sUuid;
			
			while (pfn.charAt(idx)=='/' && idx<pfn.length()-1)
				idx++;
			
			int idx2 = pfn.indexOf('?', idx);
			
			if (idx2<0)
				sUuid = pfn.substring(idx);
			else
				sUuid = pfn.substring(idx, idx2);
			
			final GUID archiveGuid = GUIDUtils.getGUID(UUID.fromString(sUuid));
			
			if (archiveGuid!=null)
				realPFNs = archiveGuid.getPFNs();
			else
				realPFNs = null;
		}
		else{
			realPFNs = new LinkedHashSet<PFN>(1);
			realPFNs.add(this);
		}
		
		return realPFNs;
	}
	
	/**
	 * Set the UUID, when known, to avoid reading from database
	 * 
	 * @param uid
	 */
	void setUUID(final UUID uid){
		uuid = uid;
	}
	
	/**
	 * Set the GUID, when known, to avoid reading from database
	 * 
	 * @param guid
	 */
	void setGUID(final GUID guid){
		this.guid = guid;
	}

	/**
	 * @return get the UUID associated to the GUID of which this entry is a replica
	 */
	public UUID getUUID(){
		if (uuid==null){
			if (guid!=null){
				uuid = guid.guid;
			}
			else{
				getGuid();
			}
		}
		
		return uuid;
	}
	
	/**
	 * @return the GUID for this PFN
	 */
	public GUID getGuid(){
		if (guid==null){
			if (uuid!=null){
				guid = GUIDUtils.getGUID(uuid);
			}
			else{
				final Host h = CatalogueUtils.getHost(host);
			
				if (h==null)
					return null;
			
				final DBFunctions db = h.getDB();
			
				if (db==null)
					return null;
			
				if (monitor!=null){
					monitor.incrementCounter("GUID_db_lookup");
				}
				
				db.query("SELECT * FROM G"+tableNumber+"L WHERE guidId="+guidId);
				
				if (db.moveNext()){
					guid = new GUID(db, host, tableNumber);
					uuid = guid.guid;
				}
			}
		}
		
		return guid;
	}
	
	@Override
	public int compareTo(final PFN o) {
		return pfn.compareTo(o.pfn);
	}
	
	@Override
	public boolean equals(final Object obj) {
		if (! (obj instanceof PFN))
			return false;
		
		return compareTo((PFN) obj) == 0;
	}
	
	@Override
	public int hashCode() {
		return pfn.hashCode();
	}
	
}
