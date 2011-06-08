package alien.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

import lazyj.cache.ExpirationCache;

import alien.api.catalogue.LFNfromString;
import alien.communications.SimpleClient;
import alien.config.ConfigUtils;

/**
 * @author costing
 * @since 2011-03-04
 */
public class Dispatcher {

	private static final ExpirationCache<String, Request> cache = new ExpirationCache<String, Request>(10240);

	/**
	 * @param r request to execute
	 * @return the processed request
	 * @throws IOException exception thrown by the processing
	 */
	public static Request execute(final Request r) throws IOException{
		return execute(r,false);
	}
	
	/**
	 * @param r request to execute
	 * @param forceRemote request to force remote execution
	 * @return the processed request
	 * @throws IOException exception thrown by the processing
	 */
	public static Request execute(final Request r, boolean forceRemote) throws IOException{
		if (ConfigUtils.isCentralService() && !forceRemote){
			//System.out.println("Running centrally: " + r.toString());
			r.run();
			return r;
		}

		if (r instanceof Cacheable){
			final Cacheable c = (Cacheable) r;
			
			final String key = r.getClass().getCanonicalName()+"#"+c.getKey();
			
			Request ret = cache.get(key);
			
			if (ret!=null)
				return ret;
			
			ret = dispatchRequest(r);
			
			if (ret!=null && (ret instanceof Cacheable)){
				final Cacheable retc = (Cacheable) ret;
				
				cache.put(key, ret, retc.getTimeout());
			}
			
			return ret;
		}
		
		return dispatchRequest(r);
	}
	
	private static Request dispatchRequest(final Request r) throws IOException {
		return SimpleCatalogueApiClient.dispatchRequest(r);
	}

	/**
	 * Debug method
	 * 
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		LFNfromString request = new LFNfromString("/alice/cern.ch/user/g/grigoras/myNewFile", false);
		
		LFNfromString response = (LFNfromString) execute(request);
		
		System.out.println("We received: " + response.getLFN().getFileName()  );
		
		long lStart = System.currentTimeMillis();
		
		for (int i=0; i<100; i++){
			request = new LFNfromString("/alice/cern.ch/user/g/grigoras/myNewFile", false);
			
			response = (LFNfromString) execute(request);
		
			//System.err.println(response);
		}
		
		System.err.println("Lasted : "+(System.currentTimeMillis() - lStart)+", "+SimpleClient.lSerialization);
		
		// dry run
		
		final long lStartDry = System.currentTimeMillis();
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		
		for (int i=0; i<100; i++){
			request = new LFNfromString("/alice/cern.ch/user/g/grigoras/myNewFile", false);
			
			oos.writeObject(request);
			oos.flush();
			baos.flush();
		}
		
		oos.close();
		
		System.err.println("Dry run took "+(System.currentTimeMillis() - lStartDry));
	}
	
}
