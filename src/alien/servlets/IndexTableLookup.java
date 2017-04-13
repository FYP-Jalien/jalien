package alien.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import alien.catalogue.CatalogueUtils;
import alien.catalogue.IndexTableEntry;
import alien.monitoring.Monitor;
import alien.monitoring.MonitorFactory;

/**
 * IndexTable lookups, based on cached indextable content
 *
 * @author costing
 * @since 2017-04-13
 */
public class IndexTableLookup extends HttpServlet {

	/**
	 *
	 */
	private static final long serialVersionUID = 1599249953957590702L;

	static transient final Monitor monitor = MonitorFactory.getMonitor(IndexTableLookup.class.getCanonicalName());

	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		final long start = System.nanoTime();

		final String lfn = req.getParameter("lfn");

		if (lfn != null && lfn.length() > 0) {
			final IndexTableEntry entry = CatalogueUtils.getClosestMatch(lfn);

			try (ServletOutputStream os = resp.getOutputStream()) {
				final StringBuilder sb = new StringBuilder(128);

				sb.append("$VAR1=[{'hostIndex'=>'").append(entry.hostIndex).append("','indexId'=>'").append(entry.indexId).append("','tableName'=>'").append(entry.tableName).append("','lfn'=>'")
						.append(entry.lfn).append("'}];\n");

				os.print(sb.toString());
			}
		}
		else {
			final String refresh = req.getParameter("refresh");

			if (refresh != null && refresh.length() > 0)
				CatalogueUtils.invalidateIndexTableCache();
		}

		if (monitor != null) {
			final long duration = System.nanoTime() - start;
			monitor.addMeasurement("ms_to_answer", duration / 1000000d);
		}
	}
}
