package alien.api;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.cert.X509Certificate;

import alien.catalogue.access.AuthorizationFactory;
import alien.config.ConfigUtils;
import alien.user.AliEnPrincipal;

/**
 * @author costing
 * @since 2011-03-04
 */
public abstract class Request implements Serializable, Runnable {
	
	/**
	 * Logger
	 */
	static transient final Logger logger = ConfigUtils.getLogger(Request.class.getCanonicalName());

	/**
	 * 
	 */
	private static final long serialVersionUID = -8044096743871226167L;

	/**
	 * Unique identifier of the VM, for communication purposes
	 */
	private static final UUID VM_UUID = UUID.randomUUID();

	/**
	 * Sequence number, for dispatching asynchronous messages
	 */
	private static final AtomicLong ID_SEQUENCE = new AtomicLong(0);

	/**
	 * @return this VM's unique identifier
	 */
	public static final UUID getVMID() {
		return VM_UUID;
	}

	/**
	 * @return current sequence number (number of requests created since VM
	 *         startup)
	 */
	public static final Long getCurrentSequenceNumber() {
		return Long.valueOf(ID_SEQUENCE.get());
	}

	/**
	 * Unique identifier of the VM that made the request
	 */
	private final UUID vm_uuid = VM_UUID;

	/**
	 * Request ID in the VM
	 */
	private final Long requestID = Long.valueOf(ID_SEQUENCE.incrementAndGet());

	/**
	 * The default identity of the VM
	 */
	private final AliEnPrincipal requester_uid = AuthorizationFactory
			.getDefaultUser();

	/**
	 * Effective identity (the user on behalf of whom the request came)
	 */
	private AliEnPrincipal requester_euid = requester_uid;

	/**
	 * Requested identity (the user on behalf of whom the request should be executed)
	 */
	private AliEnPrincipal requester_ruid = requester_uid;

	/**
	 * Effective role (the role which will be considered while authorizing the execution)
	 */
	private String requester_erid = requester_uid.getName();
	
	/**
	 * Requested role (the role that is requested)
	 */
	private String requester_rrid = requester_uid.getName();
	
	/**
	 * Set on receiving a request over the network
	 */
	private transient AliEnPrincipal partner_identity = null;

	/**
	 * Set on receiving a request over the network
	 */
	private transient X509Certificate[] partner_certificate = null;

	
	/**
	 * Set on receiving a request over the network
	 */
	private transient InetAddress partner_address = null;

	/**
	 * @return the unique identifier of the VM that generated the request
	 */
	public final UUID getVMUUID() {
		return vm_uuid;
	}

	/**
	 * @return sequence number within the VM that generated the request
	 */
	public final Long getRequestID() {
		return requestID;
	}

	/**
	 * @return requester identity (default identity of the VM)
	 */
	public final AliEnPrincipal getRequesterIdentity() {
		return requester_uid;
	}

	/**
	 * @return effective user on behalf of whom the request is executed
	 */
	public final AliEnPrincipal getEffectiveRequester() {
		return requester_euid;
	}
	

	/**
	 * @return effective role that is considered while the request is executed
	 */
	public final String getEffectiveRequesterRole() {
		return requester_erid;
	}

	/**
	 * @return identity of the partner, set on receiving a request over the wire
	 */
	public final AliEnPrincipal getPartnerIdentity() {
		return partner_identity;
	}

	/**
	 * @return certificate of the partner, set on receiving a request over the wire
	 */
	public final X509Certificate[] getPartnerCertificate() {
		return partner_certificate;
	}
	
	/**
	 * @param id
	 *            identity of the partner. This is called on receiving a request
	 *            over the wire.
	 */
	protected final void setPartnerIdentity(final AliEnPrincipal id) {
		if (partner_identity != null)
			throw new IllegalAccessError(
					"You are not allowed to overwrite this field!");

		partner_identity = id;
	}
	

	/**
	 * @param cert 
	 *            certificate of the partner. This is called on receiving a request
	 *            over the wire.
	 */
	protected final void setPartnerCertificate(final X509Certificate[]  cert) {
		if (partner_certificate != null)
			throw new IllegalAccessError(
					"You are not allowed to overwrite this field!");

		partner_certificate = cert;
	}

	
	/**
	 * let the request run with a different user name
	 * 
	 * @param user
	 */
	protected final void setRequestUser(AliEnPrincipal user){
			requester_ruid = user;
	}
	
	/**
	 * let the request run with a different role
	 * 
	 * @param role
	 */
	protected final void setRoleRequest(String role){
			requester_rrid = role;
	}

	/**
	 * get the requester role
	 * @return selected role
	 */
	protected final String getRoleRequest(){
		return requester_rrid;
	}
	
	/**
	 *  Authorize a role change 
	 * @return permission for role change
	 */
	protected final boolean authorizeUserAndRole() {

//		System.err.println("uid: "+requester_uid);
//		System.err.println("ruid: "+requester_ruid);
//		System.err.println("rrid: "+requester_rrid);
		
		// first the user
		if(requester_uid !=null && requester_ruid!=null){
			if(requester_ruid.getName()!=null){
				if(requester_uid.canBecome(requester_ruid.getName())){
					requester_euid = requester_ruid;
					
					// now the role
					
					if(requester_rrid!=null && requester_uid.hasRole(requester_rrid)){
						requester_erid = requester_rrid;
						
						if (logger.isLoggable(Level.FINE))
							logger.log(Level.FINE, "Successfully switched from '"+requester_euid.getName()+"' to '"+ requester_erid +"'.");

						return true;
					}
					
					logger.log(Level.WARNING, "User '"+requester_euid.getName()+"' doesn't have the role '"+ requester_rrid +"'.");
				}
			}
		}
		
		logger.log(Level.WARNING, "User '"+requester_euid.getName()+"' was denied role switching action.");
		
		return false;
	}
	
	
	/**
	 * @return partner's IP address
	 */
	public InetAddress getPartnerAddress() {
		return partner_address;
	}

	/**
	 * @param ip
	 *            partner's address
	 */
	public final void setPartnerAddress(final InetAddress ip) {
		if (this.partner_address != null)
			throw new IllegalAccessError("You are not allowed to overwrite this field!");

		this.partner_address = ip;
	}
	
	private ServerException exception = null;
	
	/**
	 * In case of an execution problem set the exception flag to the underlying cause
	 * 
	 * @param exception
	 */
	public final void setException(final ServerException exception){
		this.exception = exception;
	}
	
	/**
	 * @return the server side exception, if any
	 */
	public final ServerException getException(){
		return exception;
	}
}
