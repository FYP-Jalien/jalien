package alien.priority;

import alien.config.ConfigUtils;
import alien.monitoring.Monitor;
import alien.monitoring.MonitorFactory;
import alien.monitoring.Timing;
import alien.optimizers.DBSyncUtils;
import alien.optimizers.priority.PriorityRapidUpdater;
import alien.taskQueue.TaskQueueUtils;
import lazyj.DBFunctions;

import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Jorn-Are Flaten
 * @since 2023-12-04
 */
public class CalculateComputedPriority {
    /**
     * Logger
     */
    static final Logger logger = ConfigUtils.getLogger(PriorityRapidUpdater.class.getCanonicalName());

    /**
     * Monitoring component
     */
    static final Monitor monitor = MonitorFactory.getMonitor(PriorityRapidUpdater.class.getCanonicalName());

    /**
     * Update the computed priority for users
     */
    public static void updateComputedPriority(boolean onlyActiveUsers) {
        StringBuilder registerLog = new StringBuilder();
        try (DBFunctions db = TaskQueueUtils.getQueueDB(); DBFunctions dbdev = TaskQueueUtils.getProcessesDevDB()) {
            if (db == null) {
                logger.log(Level.SEVERE, "CalculatePriority could not get a DB connection");
                return;
            }

            if (dbdev == null) {
                logger.log(Level.SEVERE, "CalculatePriority(processesDev) could not get a DB connection");
                return;
            }

            db.setQueryTimeout(60);
            dbdev.setQueryTimeout(60);

            String q;
            if (onlyActiveUsers) {
                q = "SELECT userId, priority, running, maxParallelJobs, totalRunningTimeLast24h, maxTotalRunningTime from PRIORITY where totalRunningTimeLast24h > 0";
            } else {
                q = "SELECT userId, priority, running, maxParallelJobs, totalRunningTimeLast24h, maxTotalRunningTime from PRIORITY";
            }

            Map<Integer, PriorityDto> dtos = new HashMap<>();
            try (Timing t = new Timing(monitor, "calculateComputedPriority")) {
                logger.log(Level.INFO, "Calculating computed priority");
                db.setTransactionIsolation(Connection.TRANSACTION_READ_UNCOMMITTED);
                db.query(q);

                while (db.moveNext()) {
                    Integer userId = Integer.valueOf(db.geti("userId"));
                    dtos.computeIfAbsent(
                            userId,
                            k -> new PriorityDto(db));

                    updateComputedPriority(dtos.get(userId));
                }
                registerLog.append("Calculating computed priority for ")
                        .append(dtos.size())
                        .append(" users.\n")
                        .append(" Updated userload and computedPriority values will be written to the PRIORITY table in processesdev DB.\n ");

                logger.log(Level.INFO, "Finished calculating, preparing to update " + dtos.size() + " elements in the PRIORITY table...");
                executeUpdateQuery(dbdev, dtos, registerLog);

                DBSyncUtils.registerLog(CalculateComputedPriority.class.getCanonicalName(), registerLog.toString());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Exception thrown while calculating computedPriority", e);
            }
        }
    }

    private static void executeUpdateQuery(DBFunctions dbdev, Map<Integer, PriorityDto> dtos, StringBuilder registerLog) {
        try (Timing t = new Timing(monitor, "TQ_update_computed_priority_ms")) {
            t.startTiming();
            dtos.forEach((id, dto) -> {
                Timing t2 = new Timing(monitor, "TQ_single_row_update_ms");
                String query = "UPDATE PRIORITY SET userload = ?, computedPriority = ? WHERE userId = ?;";
                dbdev.query(query, false, dto.getUserload(), dto.getComputedPriority(), id);
                t2.endTiming();
                logger.log(Level.INFO, "Updating PRIORITY row for user " + id + " completed in " + t2.getMillis() + " ms");
            });

            t.endTiming();
            logger.log(Level.INFO, "Finished updating PRIORITY table row by row, took " + t.getMillis() + " ms");
            registerLog.append("Updating PRIORITY table row by row completed in ").append(t.getMillis()).append(" ms\n");
        }
    }

    private static void updateComputedPriority(PriorityDto dto) {
        if (isQuotaExceeded(dto)) {
            return;
        } else {
            int activeCpuCores = dto.getRunning();
            int maxCpuCores = dto.getMaxParallelJobs();
            long historicalUsage = dto.getTotalRunningTimeLast24h() / dto.getMaxTotalRunningTime();

            if (activeCpuCores < maxCpuCores) {
                double coreUsageCost = activeCpuCores == 0 ? 1 : (activeCpuCores * Math.exp(-historicalUsage));
                float userLoad = (float) activeCpuCores / maxCpuCores;
                dto.setUserload(userLoad);
                double adjustedPriorityFactor = (2.0 - userLoad) * (dto.getPriority() / coreUsageCost);

                if (adjustedPriorityFactor > 0) {
                    dto.setComputedPriority((float) (50.0 * adjustedPriorityFactor));
                } else {
                    dto.setComputedPriority(1);
                }
            } else {
                dto.setComputedPriority(1);
            }
        }
    }

    private static boolean isQuotaExceeded(PriorityDto dto) {
        if (dto.getTotalRunningTimeLast24h() > dto.getMaxTotalRunningTime()) {
            dto.setComputedPriority(-1);
            logger.log(Level.INFO, "User " + dto.getUserId() + " has exceeded the total running time quota");
            return true;
        }
        if (dto.getRunning() > dto.getMaxParallelJobs()) {
            dto.setComputedPriority(-1);
            logger.log(Level.INFO, "User " + dto.getUserId() + " has exceeded the maximum parallel jobs quota");
            return true;
        }
        return false;
    }
}
