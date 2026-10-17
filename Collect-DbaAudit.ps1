#requires -Version 5.1
<#
Collect SQL Server metadata using a securely prompted SQL Server login.
Database commands come exclusively from the embedded fixed SELECT query packs.
This script writes a local JSON report; it does not change SQL Server configuration.
#>
[CmdletBinding()]
param(
    [string]$Server = [Environment]::MachineName,
    [ValidateRange(1,65535)][int]$Port = 1433,
    [switch]$TrustServerCertificate,
    [string[]]$Databases = @(),
    [ValidateRange(1,300)][int]$QueryTimeoutSeconds = 15,
    [ValidateRange(0,60)][int]$CpuSampleMinutes = 16,
    [ValidateRange(1,500)][int]$MaxDatabases = 50,
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('UserProfile')) ('DbaAudit-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.json'))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Data

function New-AuditConnection {
    param([string]$DatabaseName)
    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = 'tcp:' + $Server + ',' + $Port
    $builder['Initial Catalog'] = $DatabaseName
    $builder['Integrated Security'] = $false
    $builder['Encrypt'] = $true
    # Certificate validation is bypassed only when explicitly requested.
    $builder['TrustServerCertificate'] = ($TrustServerCertificate.IsPresent)
    $builder['Pooling'] = $false
    $builder['Connect Timeout'] = 30
    $builder['Application Name'] = 'ReadOnly DBA Audit'
    if ($null -eq $script:AuditSqlCredential) {
        throw 'SQL login credentials have not been supplied.'
    }
    $sqlConnection = New-Object System.Data.SqlClient.SqlConnection($builder.ConnectionString)
    $sqlConnection.Credential = $script:AuditSqlCredential
    return $sqlConnection
}

function Invoke-AuditQuery {
    param($Connection, $Definition, [string]$DatabaseName)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $command = $null
    $reader = $null
    $rows = New-Object 'System.Collections.Generic.List[object]'
    try {
        $command = $Connection.CreateCommand()
        $command.CommandTimeout = $QueryTimeoutSeconds
        $command.CommandText = [string]$Definition.sql
        $reader = $command.ExecuteReader()
        while ($reader.Read()) {
            $row = [ordered]@{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $value = $reader.GetValue($i)
                if ($value -is [DBNull]) { $value = $null }
                elseif ($value -is [DateTime]) { $value = $value.ToString('o') }
                elseif ($value -is [byte[]]) { $value = [Convert]::ToBase64String($value) }
                $row[$reader.GetName($i)] = $value
            }
            $rows.Add([pscustomobject]$row)
        }
        return [pscustomobject][ordered]@{
            name = $Definition.name; database = $DatabaseName; status = 'collected'
            description = $Definition.description; caveat = $Definition.caveat
            collected_at_utc = [DateTime]::UtcNow.ToString('o')
            duration_ms = $timer.ElapsedMilliseconds; row_count = $rows.Count
            rows = @($rows.ToArray()); error = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            name = $Definition.name; database = $DatabaseName; status = 'not_assessed'
            description = $Definition.description; caveat = $Definition.caveat
            collected_at_utc = [DateTime]::UtcNow.ToString('o')
            duration_ms = $timer.ElapsedMilliseconds; row_count = 0; rows = @()
            error = $_.Exception.GetBaseException().Message
        }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $command) { $command.Dispose() }
        $timer.Stop()
    }
}

function Get-LocalHostEvidence {
    param($Identity)
    $result = [ordered]@{
        status = 'not_assessed'; reason = 'SQL Server host identity could not be verified.'
        physical_machine_name = $env:COMPUTERNAME
        disks = @(); operating_system = @(); sql_process_cpu_samples = @()
        cpu_assessment = 'not_assessed'; errors = @()
    }
    if ($null -eq $Identity -or [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { return [pscustomobject]$result }
    $hostName = [string]$Identity.physical_machine_name
    if ([string]::IsNullOrWhiteSpace($hostName)) { $hostName = [string]$Identity.machine_name }
    if (-not [string]::Equals($hostName, $env:COMPUTERNAME, [StringComparison]::OrdinalIgnoreCase)) {
        $result.reason = 'Collector is not running on the verified SQL Server physical host. Local metrics are not attributed to the target.'
        return [pscustomobject]$result
    }
    $result.status = 'collected'
    $result.reason = 'Local host name matches SQL Server physical host. OS evidence supplements database metadata.'
    try {
        $result.disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
            $percent = $null; $severity = 'unknown'
            if ($_.Size -gt 0 -and $null -ne $_.FreeSpace -and $_.FreeSpace -ge 0 -and $_.FreeSpace -le $_.Size) {
                $rawPercent = 100.0 * ($_.Size - $_.FreeSpace) / $_.Size
                $percent = [math]::Round($rawPercent, 2)
                $severity = 'within_threshold'
                if ($rawPercent -gt 95) { $severity = 'critical' }
                elseif ($rawPercent -gt 85) { $severity = 'warning' }
            }
            [pscustomobject]@{volume=$_.DeviceID; size_bytes=$_.Size; free_bytes=$_.FreeSpace; used_percent=$percent; threshold_status=$severity}
        })
    } catch { $result.errors += ('Disk metrics: ' + $_.Exception.GetBaseException().Message) }
    try {
        $result.operating_system = @(Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory, LastBootUpTime)
    } catch { $result.errors += ('OS metrics: ' + $_.Exception.GetBaseException().Message) }

    if ($CpuSampleMinutes -eq 0) {
        $result.reason += ' CPU sampling was explicitly skipped.'
        if ($result.errors.Count -gt 0) { $result.status = 'partial' }
        return [pscustomobject]$result
    }
    $samples = $null
    try {
        $sqlProcessId = [int]$Identity.process_id
        if ($sqlProcessId -le 0) { throw 'SQL Server process ID is unavailable.' }
        $cpuCount = [int](Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors
        if ($cpuCount -le 0) { throw 'Logical processor count is unavailable.' }
        $samples = New-Object 'System.Collections.Generic.List[object]'
        $sampleClock = [Diagnostics.Stopwatch]::StartNew()
        $durationSeconds = $CpuSampleMinutes * 60
        Write-Host ('Sampling the SQL Server process CPU for ' + $CpuSampleMinutes + ' minutes...')
        while ($true) {
            $processSample = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -Filter ('IDProcess=' + $sqlProcessId))
            if ($processSample.Count -ne 1) { throw 'SQL Server process CPU counter is unavailable or ambiguous.' }
            if ($processSample[0].Name -notlike 'sqlservr*') { throw 'The identified process is no longer SQL Server; CPU attribution stopped.' }
            $rawCpuPercent = [double]$processSample[0].PercentProcessorTime / $cpuCount
            $cpuPercent = [math]::Round($rawCpuPercent, 2)
            $samples.Add([pscustomobject]@{sample_utc=[DateTime]::UtcNow.ToString('o'); elapsed_seconds=[math]::Round($sampleClock.Elapsed.TotalSeconds,2); sql_instance_cpu_percent=$cpuPercent; raw_sql_instance_cpu_percent=$rawCpuPercent})
            if ($sampleClock.Elapsed.TotalSeconds -ge $durationSeconds) { break }
            $secondsToNext = [math]::Max(1, [math]::Min(60, [math]::Ceiling($durationSeconds - $sampleClock.Elapsed.TotalSeconds)))
            Start-Sleep -Seconds $secondsToNext
        }
        $result.sql_process_cpu_samples = @($samples.ToArray())
        $maxHighRunSeconds = 0.0; $runStart = $null; $previousSecond = $null; $hasSampleGap = $false
        foreach ($sample in $samples) {
            if ($null -ne $previousSecond -and ($sample.elapsed_seconds - $previousSecond) -gt 90) {
                $runStart = $null
                $hasSampleGap = $true
            }
            if ($sample.raw_sql_instance_cpu_percent -gt 80) {
                if ($null -eq $runStart) { $runStart = $sample.elapsed_seconds }
                $maxHighRunSeconds = [math]::Max($maxHighRunSeconds, $sample.elapsed_seconds - $runStart)
            } else { $runStart = $null }
            $previousSecond = $sample.elapsed_seconds
        }
        if ($maxHighRunSeconds -gt 900) { $result.cpu_assessment = 'warning_sampled_cpu_above_80_percent_for_over_15_minutes' }
        elseif ($hasSampleGap) {
            $result.cpu_assessment = 'not_assessed_due_to_sampling_gaps'
            $result.status = 'partial'
            $result.reason += ' Gaps over 90 seconds prevented assessment of the sustained CPU threshold.'
        }
        elseif ($CpuSampleMinutes -le 15) { $result.cpu_assessment = 'insufficient_sampling_duration_for_over_15_minute_threshold' }
        else { $result.cpu_assessment = 'no_sustained_threshold_breach_observed_in_samples' }
        $result.reason += ' CPU uses the identified SQL Server process divided by host logical CPU count. Samples cannot exclude shorter spikes or establish host saturation relative to CPU affinity/cgroup limits.'
        $sampleClock.Stop()
    } catch {
        $result.errors += ('CPU sampling: ' + $_.Exception.GetBaseException().Message)
        if ($null -ne $samples) { $result.sql_process_cpu_samples = @($samples.ToArray()) }
    }
    if ($result.errors.Count -gt 0) { $result.status = 'partial' }
    return [pscustomobject]$result
}

$outputFile = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $outputFile) { throw 'Output file already exists. Choose a different -OutputPath.' }
$outputDirectory = Split-Path -Parent $outputFile
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) { throw 'Output directory does not exist.' }
$serverQueries = @(ConvertFrom-Json -InputObject @'
[
{"name":"identity","description":"Instance identity, local process identity, SQL Server version and server clock evidence.","sql":"SELECT CONVERT(nvarchar(128), @@SERVERNAME) AS server_name, CONVERT(nvarchar(128), SERVERPROPERTY('MachineName')) AS machine_name, CONVERT(nvarchar(128), SERVERPROPERTY('ComputerNamePhysicalNetBIOS')) AS physical_machine_name, CONVERT(int, SERVERPROPERTY('ProcessID')) AS process_id, CONVERT(nvarchar(128), SERVERPROPERTY('InstanceName')) AS instance_name, CONVERT(nvarchar(128), @@SERVICENAME) AS service_name, CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS product_version, CONVERT(int, PARSENAME(CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')), 4)) AS sql_version_major, CONVERT(nvarchar(128), SERVERPROPERTY('ProductLevel')) AS product_level, CONVERT(nvarchar(128), SERVERPROPERTY('Edition')) AS edition, CONVERT(int, SERVERPROPERTY('EngineEdition')) AS engine_edition, CONVERT(int, SERVERPROPERTY('IsClustered')) AS is_clustered, CONVERT(int, SERVERPROPERTY('IsHadrEnabled')) AS is_hadr_enabled, CASE CONVERT(int, SERVERPROPERTY('IsIntegratedSecurityOnly')) WHEN 1 THEN N'Windows authentication only' WHEN 0 THEN N'Mixed authentication' ELSE N'Unknown' END AS auth_mode, SYSUTCDATETIME() AS sample_utc, SYSDATETIMEOFFSET() AS server_time_with_offset, GETDATE() AS server_local_time;","caveat":"One row. Null instance_name normally denotes the default instance. Unsupported SERVERPROPERTY values can be NULL. Compare physical_machine_name and process_id to the local Windows host before attributing OS metrics to this instance. Mixed authentication requires an approved identity policy before classifying it as a finding. Clock accuracy itself is not verified."},
{"name":"permissions","description":"Current login identity and metadata/telemetry permission indicators.","sql":"SELECT ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS effective_login, IS_SRVROLEMEMBER(N'sysadmin') AS is_sysadmin, HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW SERVER STATE') AS has_view_server_state, HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW SERVER PERFORMANCE STATE') AS has_view_server_performance_state, HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW SERVER SECURITY STATE') AS has_view_server_security_state, HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW ANY DEFINITION') AS has_view_any_definition, HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW ANY SECURITY DEFINITION') AS has_view_any_security_definition, HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW ANY DATABASE') AS has_view_any_database, HAS_PERMS_BY_NAME(NULL, NULL, N'ALTER ANY LOGIN') AS has_alter_any_login;","caveat":"One row. Newer permission names return NULL on older versions. Permissions required by DMVs changed in SQL Server 2022. Successful queries can still return only metadata visible to the current principal; absence of rows never establishes complete security coverage. No permission changes are performed."},
{"name":"accessible_databases","description":"Visible databases above ID 4, including offline or inaccessible databases.","sql":"SELECT TOP (1000) database_id, name, state_desc, user_access_desc, is_read_only, recovery_model_desc, log_reuse_wait_desc, source_database_id, HAS_DBACCESS(name) AS has_dbaccess FROM sys.databases WHERE database_id > 4 ORDER BY database_id;","caveat":"At most 1000 visible rows. Offline databases can be hidden from low-privilege logins. A NULL or zero has_dbaccess is not an empty database. Only online accessible databases should receive per-database queries; preserve all other database rows as coverage gaps. Database IDs above 4 can include replication distribution databases and snapshots."},
{"name":"service_status","description":"SQL Server and Agent service states visible through the instance.","sql":"SELECT TOP (32) servicename, startup_type_desc, status_desc, process_id, last_startup_time FROM sys.dm_server_services ORDER BY servicename;","caveat":"At most 32 rows. Requires server-state or server-security-state permission depending on version. SQL Server Express has no SQL Server Agent. Agent requirements depend on the intended job scheduler. These rows do not establish remote reachability or the health of jobs."},
{"name":"volumes","description":"Capacity and free space for volumes containing visible SQL Server database files.","sql":"SELECT DISTINCT TOP (128) v.volume_id, v.volume_mount_point, v.logical_volume_name, v.file_system_type, v.total_bytes, v.available_bytes, CONVERT(decimal(6,2), 100.0 * (v.total_bytes - v.available_bytes) / NULLIF(v.total_bytes, 0)) AS volume_used_percent FROM sys.master_files AS f CROSS APPLY sys.dm_os_volume_stats(f.database_id, f.file_id) AS v ORDER BY v.volume_mount_point, v.volume_id;","caveat":"At most 128 distinct volume rows, not one capacity allocation per file. Metadata visibility can limit coverage. Mounted volumes without database files are outside scope. Filesystem capacity differs from database file allocation and transaction-log utilization. Unsupported or inaccessible volumes must remain unassessed."},
{"name":"memory_system","description":"Host physical memory and operating-system low-memory indicators.","sql":"SELECT SYSUTCDATETIME() AS sample_utc, total_physical_memory_kb, available_physical_memory_kb, total_page_file_kb, available_page_file_kb, system_high_memory_signal_state, system_low_memory_signal_state, system_memory_state_desc FROM sys.dm_os_sys_memory;","caveat":"One instantaneous host-memory snapshot. It does not establish sustained pressure or the SQL Server process share. Server-state/performance-state permissions are version dependent."},
{"name":"memory_process","description":"SQL Server process memory and internal low-memory flags.","sql":"SELECT SYSUTCDATETIME() AS sample_utc, physical_memory_in_use_kb, large_page_allocations_kb, locked_page_allocations_kb, virtual_address_space_reserved_kb, virtual_address_space_committed_kb, virtual_address_space_available_kb, page_fault_count, memory_utilization_percentage, process_physical_memory_low, process_virtual_memory_low FROM sys.dm_os_process_memory;","caveat":"One instantaneous process snapshot. memory_utilization_percentage is a SQL process-memory indicator, not total host RAM utilization. Page-fault counts are cumulative and include soft faults. No sustained-pressure conclusion follows from one sample."},
{"name":"memory_config","description":"Configured SQL Server memory limits.","sql":"SELECT name, CONVERT(bigint, value) AS configured_value_mb, CONVERT(bigint, value_in_use) AS value_in_use_mb FROM sys.configurations WHERE name IN (N'min server memory (MB)', N'max server memory (MB)') ORDER BY name;","caveat":"At most two rows. max server memory does not cap every SQL Server allocation. Appropriate limits depend on host RAM, other instances, workload and operating-system needs."},
{"name":"ple_bufferpool","description":"Raw buffer-pool, memory-grant and memory-target performance counters.","sql":"SELECT TOP (128) SYSUTCDATETIME() AS sample_utc, object_name, instance_name, counter_name, cntr_value, cntr_type FROM sys.dm_os_performance_counters WHERE (RTRIM(object_name) LIKE N'%:Buffer Manager' OR RTRIM(object_name) LIKE N'%:Buffer Node' OR RTRIM(object_name) LIKE N'%:Memory Manager') AND counter_name IN (N'Page life expectancy', N'Database pages', N'Free pages', N'Target Server Memory (KB)', N'Total Server Memory (KB)', N'Memory Grants Pending', N'Memory Grants Outstanding', N'Buffer cache hit ratio', N'Buffer cache hit ratio base') ORDER BY object_name, instance_name, counter_name;","caveat":"At most 128 raw counter rows. Buffer pages use 8 KB pages. Ratio counters require their base and counter-type interpretation. NUMA-node PLE should be evaluated separately. A PLE of 300 seconds is a heuristic requiring workload and memory context, not a universal failure boundary. Missing counters are unassessed."},
{"name":"cpu_ring_buffer","description":"Recent scheduler-monitor CPU samples without exporting raw ring-buffer XML.","sql":"WITH recent AS (SELECT TOP (60) rb.[timestamp] AS sample_ticks, CONVERT(xml, rb.record) AS record_xml FROM sys.dm_os_ring_buffers AS rb WHERE rb.ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR' AND rb.record LIKE N'%<SystemHealth>%' ORDER BY rb.[timestamp] DESC) SELECT TOP (60) DATEADD(second, CONVERT(int, (r.sample_ticks - s.ms_ticks) / 1000), SYSUTCDATETIME()) AS estimated_sample_utc, r.sample_ticks, r.record_xml.value('(/Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]', 'int') AS sql_process_cpu_percent, r.record_xml.value('(/Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]', 'int') AS system_idle_percent FROM recent AS r CROSS JOIN sys.dm_os_sys_info AS s WHERE r.record_xml.exist('/Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization') = 1 AND r.record_xml.exist('/Record/SchedulerMonitorEvent/SystemHealth/SystemIdle') = 1 ORDER BY r.sample_ticks DESC;","caveat":"At most 60 retained samples. This internal scheduler-ring-buffer format is version/platform dependent. Timestamps are approximate offsets from the current server clock. Missing, irregular or old samples cannot prove sustained CPU over 15 minutes. Use timestamped, locally attributed OS/cloud samples as the primary sustained-CPU evidence."},
{"name":"wait_stats","description":"Largest cumulative instance wait totals, including signal-wait components.","sql":"SELECT TOP (50) wait_type, waiting_tasks_count, wait_time_ms, max_wait_time_ms, signal_wait_time_ms FROM sys.dm_os_wait_stats WHERE waiting_tasks_count > 0 ORDER BY wait_time_ms DESC, wait_type;","caveat":"At most 50 rows. Counters are cumulative since startup or their last reset and include normal idle/background waits. Delta samples and workload context are required to identify current pressure. This query does not reset statistics."},
{"name":"instance_uptime","description":"Instance start time and scheduler/CPU topology for interpreting cumulative metrics.","sql":"SELECT sqlserver_start_time, cpu_count, hyperthread_ratio, scheduler_count, ms_ticks, SYSUTCDATETIME() AS sample_utc FROM sys.dm_os_sys_info;","caveat":"One row. Start time uses the server's local clock. CPU topology can differ from the process's effective CPU entitlement under affinity, containers or virtualization. Individual cumulative statistics can also have been reset after startup."},
{"name":"active_requests","description":"Bounded active user requests and blocking indicators without query text or plans.","sql":"SELECT TOP (100) r.session_id, r.request_id, r.database_id, DB_NAME(r.database_id) AS database_name, r.status, r.command, r.start_time, r.total_elapsed_time AS elapsed_ms, r.cpu_time AS cpu_ms, r.wait_type, r.wait_time AS current_wait_ms, r.blocking_session_id, r.open_transaction_count, r.reads, r.writes, r.logical_reads, r.percent_complete FROM sys.dm_exec_requests AS r LEFT JOIN sys.dm_exec_sessions AS s ON s.session_id = r.session_id WHERE r.session_id <> @@SPID AND (s.is_user_process = 1 OR r.blocking_session_id <> 0) ORDER BY CASE WHEN r.blocking_session_id <> 0 THEN 0 ELSE 1 END, r.total_elapsed_time DESC, r.session_id;","caveat":"At most 100 request rows at one instant. Sleeping sessions do not appear. Negative blocking_session_id values denote special owners, not ordinary session IDs. Request CPU is cumulative per request, not a utilization percentage. Viewing other sessions requires version-appropriate server telemetry permission."},
{"name":"blockers","description":"Current blocked-to-blocker edges, including sleeping blocker-session indicators.","sql":"SELECT TOP (100) r.session_id AS blocked_session_id, r.request_id, r.database_id, DB_NAME(r.database_id) AS database_name, r.blocking_session_id, r.wait_type, r.wait_time AS current_wait_ms, r.wait_resource, s.status AS blocker_session_status, s.open_transaction_count AS blocker_open_transaction_count, s.last_request_end_time AS blocker_last_request_end_time FROM sys.dm_exec_requests AS r LEFT JOIN sys.dm_exec_sessions AS s ON s.session_id = r.blocking_session_id WHERE r.blocking_session_id <> 0 AND r.session_id <> @@SPID ORDER BY r.wait_time DESC, r.session_id;","caveat":"At most 100 current blocking edges. Negative blocker IDs have special meanings and need separate interpretation. Snapshots may miss short-lived blocking; they do not establish deadlock history or a complete chain if output is capped. No sessions are terminated."},
{"name":"long_transactions","description":"Oldest currently visible user transactions and their associated session states.","sql":"SELECT TOP (100) t.transaction_id, t.transaction_begin_time, DATEDIFF(second, t.transaction_begin_time, GETDATE()) AS transaction_age_seconds, t.transaction_type, t.transaction_state, st.session_id, s.status AS session_status, s.open_transaction_count, s.last_request_start_time, s.last_request_end_time, st.is_local, st.is_enlisted FROM sys.dm_tran_active_transactions AS t INNER JOIN sys.dm_tran_session_transactions AS st ON st.transaction_id = t.transaction_id LEFT JOIN sys.dm_exec_sessions AS s ON s.session_id = st.session_id WHERE st.is_user_transaction = 1 AND st.session_id <> @@SPID ORDER BY t.transaction_begin_time, t.transaction_id, st.session_id;","caveat":"At most 100 transaction/session associations. A transaction can map to multiple sessions. A sleeping session with an open transaction warrants investigation, but SQL Server has no PostgreSQL idle-in-transaction status. Long transaction duration alone does not prove harmful blocking. Server-local timestamps are used consistently for age."},
{"name":"locks_summary","description":"Aggregated lock counts by session, database, resource type, mode and request status.","sql":"SELECT TOP (100) request_session_id, resource_database_id AS database_id, DB_NAME(resource_database_id) AS database_name, resource_type, request_mode, request_status, COUNT_BIG(*) AS lock_count FROM sys.dm_tran_locks WHERE request_session_id <> @@SPID GROUP BY request_session_id, resource_database_id, resource_type, request_mode, request_status ORDER BY COUNT_BIG(*) DESC, request_session_id;","caveat":"At most 100 aggregate rows. This is an instantaneous lock inventory, not proof of deadlocks. Aggregating the lock DMV can be expensive when lock counts are extreme; retain the command timeout and report a timeout as unassessed."},
{"name":"backups","description":"Latest recorded full, differential and log backup metadata per visible non-temp database.","sql":"SELECT TOP (300) d.database_id, d.name AS database_name, d.recovery_model_desc, k.backup_type, b.backup_start_date, b.backup_finish_date, b.is_copy_only, b.has_backup_checksums, b.is_damaged, b.backup_size, b.compressed_backup_size, b.database_guid AS backup_database_guid FROM sys.databases AS d CROSS JOIN (VALUES (CONVERT(char(1), 'D')), (CONVERT(char(1), 'I')), (CONVERT(char(1), 'L'))) AS k(backup_type) OUTER APPLY (SELECT TOP (1) bs.backup_start_date, bs.backup_finish_date, bs.is_copy_only, bs.has_backup_checksums, bs.is_damaged, bs.backup_size, bs.compressed_backup_size, bs.database_guid FROM msdb.dbo.backupset AS bs WHERE bs.database_name = d.name AND bs.type = k.backup_type AND bs.backup_finish_date IS NOT NULL ORDER BY bs.backup_finish_date DESC, bs.backup_set_id DESC) AS b WHERE d.database_id <> 2 AND d.source_database_id IS NULL ORDER BY d.database_id, k.backup_type;","caveat":"At most 300 rows, normally three rows per database. D/I/L mean full/differential/log. This is local msdb history matched by database name; it may be purged, incomplete for replicas/external backup products, or associated with an earlier database of the same name. is_damaged must be checked. Copy-only full backups do not establish a differential base. History does not prove backup media availability, an intact restore chain, successful restore, or RPO compliance. RPO and backup policy remain required inputs."},
{"name":"admin_roles","description":"Visible direct server-role memberships, including fixed and custom server roles.","sql":"SELECT TOP (500) r.name AS server_role, m.principal_id AS member_principal_id, m.name AS member_name, m.type_desc AS member_type, m.is_disabled AS member_is_disabled, r.is_fixed_role FROM sys.server_role_members AS rm LEFT JOIN sys.server_principals AS r ON r.principal_id = rm.role_principal_id LEFT JOIN sys.server_principals AS m ON m.principal_id = rm.member_principal_id WHERE r.name <> N'public' OR r.name IS NULL ORDER BY r.name, m.name, rm.member_principal_id;","caveat":"At most 500 direct membership rows. Metadata visibility may hide memberships or principal names without producing an error. Windows/AD group membership, nested roles and role ownership require additional interpretation. An approved administrator inventory is needed to classify memberships as excessive. This query does not inspect password hashes."},
{"name":"server_permissions","description":"Visible explicit server permissions and grants, including grants to roles.","sql":"SELECT TOP (500) p.grantee_principal_id, grantee.name AS grantee_name, grantee.type_desc AS grantee_type, p.state_desc, p.permission_name, p.class_desc, p.major_id AS securable_major_id, grantor.name AS grantor_name FROM sys.server_permissions AS p LEFT JOIN sys.server_principals AS grantee ON grantee.principal_id = p.grantee_principal_id LEFT JOIN sys.server_principals AS grantor ON grantor.principal_id = p.grantor_principal_id ORDER BY grantee.name, p.class_desc, p.permission_name, p.major_id;","caveat":"At most 500 explicit permission rows. Fixed-server-role powers are not fully represented here. Effective privileges also depend on role nesting, Windows groups, ownership, grants/denials and metadata visibility. Absence of explicit grants does not establish least privilege."},
{"name":"surface_config","description":"Configured and active values for selected SQL Server surface-area features.","sql":"SELECT TOP (32) name, CONVERT(int, value) AS configured_value, CONVERT(int, value_in_use) AS value_in_use, is_dynamic, is_advanced FROM sys.configurations WHERE name IN (N'xp_cmdshell', N'Ole Automation Procedures', N'Ad Hoc Distributed Queries', N'cross db ownership chaining', N'contained database authentication', N'remote access', N'clr enabled', N'clr strict security', N'external scripts enabled', N'scan for startup procs', N'remote admin connections', N'filestream access level') ORDER BY name;","caveat":"At most 32 configuration rows. Some options do not exist on older versions or particular platforms. Missing options are unsupported/unassessed, not disabled. Enabled features need an approved business justification and permissions review; they do not prove exploitation. Pending configured values can differ from value_in_use."},
{"name":"transport","description":"Authentication and transport properties of this collector's current database connection.","sql":"SELECT TOP (1) connection_id, session_id, connect_time, net_transport, protocol_type, auth_scheme, encrypt_option, client_net_address, local_net_address, local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID;","caveat":"At most one current-connection row. Encryption of this connection does not prove server-wide TLS enforcement. NTLM versus Kerberos describes this session only. Shared-memory connections do not test network TLS. Addresses and a listening port do not establish public exposure. The collector must separately validate certificates when using TCP."},
{"name":"tls_policy","description":"Visible SQL Server registry policy indicators for forced transport encryption.","sql":"SELECT TOP (16) registry_key, value_name, CONVERT(nvarchar(128), value_data) AS value_data FROM sys.dm_server_registry WHERE registry_key LIKE N'%SuperSocketNetLib' AND value_name IN (N'ForceEncryption', N'ForceStrictEncryption') ORDER BY registry_key, value_name;","caveat":"At most 16 filtered policy rows. Platform/version/permission differences can leave no rows; that means enforcement is unverified. Policy values do not prove certificate trust, protocol/cipher compliance, all active sessions, endpoint reachability or internet exposure. No registry changes or stored procedures are used."},
{"name":"encryption","description":"Visible database TDE metadata without key material or certificate hashes.","sql":"SELECT TOP (1000) d.database_id, d.name AS database_name, d.state_desc, d.is_encrypted, e.encryption_state, e.percent_complete, e.key_algorithm, e.key_length FROM sys.databases AS d LEFT JOIN sys.dm_database_encryption_keys AS e ON e.database_id = d.database_id WHERE d.database_id <> 2 ORDER BY d.database_id;","caveat":"At most 1000 database rows. TDE state 3 denotes encrypted; other states include transitions or unencrypted databases. Missing DMV rows can reflect key absence or restricted visibility. TDE is separate from transport encryption, backup encryption and application/column encryption. A sensitive-data inventory and policy are required before reporting a compliance failure."},
{"name":"ag_replicas","description":"Availability-group replica roles, connectivity and synchronization-health indicators.","sql":"SELECT TOP (200) g.name AS availability_group, a.replica_server_name, a.availability_mode_desc, a.failover_mode_desc, s.is_local, s.role_desc, s.operational_state_desc, s.connected_state_desc, s.recovery_health_desc, s.synchronization_health_desc, s.last_connect_error_number, s.last_connect_error_timestamp FROM sys.availability_replicas AS a INNER JOIN sys.availability_groups AS g ON g.group_id = a.group_id LEFT JOIN sys.dm_hadr_availability_replica_states AS s ON s.group_id = a.group_id AND s.replica_id = a.replica_id ORDER BY g.name, a.replica_server_name;","caveat":"At most 200 replica rows. Requires an AG-capable version/platform and appropriate metadata/telemetry permissions. A secondary may expose only local state; some remote state columns can be NULL. Zero rows can mean standalone, disabled AGs or limited visibility. Expected topology and sync mode are required before declaring replication healthy or unhealthy."},
{"name":"ag_databases","description":"Availability-group database synchronization states and send/redo queue metrics.","sql":"SELECT TOP (500) g.name AS availability_group, a.replica_server_name, c.database_name, s.is_local, s.database_state_desc, s.synchronization_state_desc, s.synchronization_health_desc, s.is_suspended, s.suspend_reason_desc, s.log_send_queue_size AS log_send_queue_kb, s.log_send_rate AS log_send_rate_kb_per_sec, s.redo_queue_size AS redo_queue_kb, s.redo_rate AS redo_rate_kb_per_sec, s.last_sent_time, s.last_received_time, s.last_hardened_time, s.last_redone_time FROM sys.dm_hadr_database_replica_states AS s INNER JOIN sys.availability_groups AS g ON g.group_id = s.group_id INNER JOIN sys.availability_replicas AS a ON a.replica_id = s.replica_id AND a.group_id = s.group_id LEFT JOIN sys.availability_databases_cluster AS c ON c.group_database_id = s.group_database_id ORDER BY g.name, c.database_name, a.replica_server_name;","caveat":"At most 500 database/replica rows. Visibility depends on the queried replica and permissions. Queue sizes and active rates are snapshots; they do not establish a guaranteed recovery-point objective. Idle/NULL timestamps and asynchronous replicas require topology and workload context. This does not inspect other replication technologies or log shipping."},
{"name":"existing_deadlock_summary","description":"Timestamp and structural counts for retained system_health ring-buffer deadlock events.","sql":"WITH target_xml AS (SELECT CONVERT(xml, t.target_data) AS target_xml FROM sys.dm_xe_session_targets AS t INNER JOIN sys.dm_xe_sessions AS s ON s.address = t.event_session_address WHERE s.name = N'system_health' AND t.target_name = N'ring_buffer') SELECT TOP (50) e.event_xml.value('(@timestamp)[1]', 'nvarchar(64)') AS event_timestamp_utc, e.event_xml.value('count(data/value/deadlock/victim-list/victimProcess)', 'int') AS victim_count, e.event_xml.value('count(data/value/deadlock/process-list/process)', 'int') AS process_count, e.event_xml.value('count(data/value/deadlock/resource-list/*)', 'int') AS resource_count FROM target_xml AS t CROSS APPLY t.target_xml.nodes('/RingBufferTarget/event[@name=''xml_deadlock_report'']') AS e(event_xml) ORDER BY event_timestamp_utc DESC;","caveat":"At most 50 retained event summaries, without SQL text, input buffers or raw XML. system_health can be absent/stopped, its ring buffer can roll over or truncate, and events can exist only in its file target. Zero returned rows does not prove no deadlocks during the reporting period. No event session is created, changed or started."},
{"name":"missing_indexes","description":"Bounded visible missing-index DMV suggestions without executable index definitions.","sql":"SELECT TOP (30) d.database_id, DB_NAME(d.database_id) AS database_name, d.object_id, OBJECT_SCHEMA_NAME(d.object_id, d.database_id) AS schema_name, OBJECT_NAME(d.object_id, d.database_id) AS object_name, d.index_handle, d.equality_columns, d.inequality_columns, d.included_columns, s.user_seeks, s.user_scans, s.last_user_seek, s.last_user_scan, s.avg_total_user_cost, s.avg_user_impact FROM sys.dm_db_missing_index_details AS d INNER JOIN sys.dm_db_missing_index_groups AS g ON g.index_handle = d.index_handle INNER JOIN sys.dm_db_missing_index_group_stats AS s ON s.group_handle = g.index_group_handle WHERE d.database_id > 4 ORDER BY s.avg_total_user_cost * s.avg_user_impact * (CONVERT(float, s.user_seeks) + CONVERT(float, s.user_scans)) DESC, d.index_handle;","caveat":"At most 30 optimizer suggestions from a limited, resettable DMV cache. Estimated impact is not measured benefit. Suggestions can overlap, omit existing-index context and impose write/storage costs. Metadata visibility can hide object names. They require workload/index review; do not generate or execute index DDL automatically."},
{"name":"cached_queries","description":"Highest cumulative CPU cached statement metrics identified only by query and plan hashes.","sql":"SELECT TOP (30) CONVERT(varchar(18), query_hash, 1) AS query_hash, CONVERT(varchar(18), query_plan_hash, 1) AS query_plan_hash, creation_time, last_execution_time, execution_count, total_worker_time AS total_worker_time_microseconds, total_elapsed_time AS total_elapsed_time_microseconds, total_logical_reads, total_logical_writes, total_physical_reads, min_worker_time AS min_worker_time_microseconds, max_worker_time AS max_worker_time_microseconds, last_worker_time AS last_worker_time_microseconds, CONVERT(decimal(20,3), CONVERT(decimal(28,3), total_worker_time) / NULLIF(execution_count, 0) / 1000.0) AS mean_worker_time_ms FROM sys.dm_exec_query_stats ORDER BY total_worker_time DESC, last_execution_time DESC;","caveat":"At most 30 cached statement entries, without SQL text or plans. Entries are not aggregated by query hash and can have multiple plans. Statistics cover completed executions since each cache entry was compiled; eviction, recompilation and restart remove history. Totals are not current CPU percentages, and this snapshot cannot establish a sudden plan regression."}
]
'@ | ForEach-Object { $_ }
)
$databaseQueries = @(ConvertFrom-Json -InputObject @'
[
{"name":"database_configuration","description":"Current database configuration relevant to integrity, recovery, and security.","sql":"SELECT d.name AS database_name, d.state_desc, d.compatibility_level, d.recovery_model_desc, d.user_access_desc, d.is_read_only, d.is_auto_close_on, d.is_auto_shrink_on, d.page_verify_option_desc, d.is_trustworthy_on, d.is_db_chaining_on, d.is_encrypted, d.containment_desc, d.log_reuse_wait_desc FROM sys.databases AS d WHERE d.database_id = DB_ID();","caveat":"A configuration snapshot cannot establish recovery readiness or compliance. Backup RPOs and sensitive-data inventory have not been supplied. is_encrypted indicates database encryption status and does not establish connection encryption or column-level protection. Metadata visibility depends on the caller's permissions."},
{"name":"data_file_allocation","description":"Allocated and used data-file space, plus file growth settings, from database metadata.","sql":"SELECT TOP (200) DB_NAME() AS database_name, f.file_id, f.name AS logical_file_name, f.state_desc, CONVERT(decimal(19,2), f.size / 128.0) AS allocated_mb, CONVERT(decimal(19,2), FILEPROPERTY(f.name, 'SpaceUsed') / 128.0) AS used_mb, CONVERT(decimal(19,2), (CONVERT(bigint, f.size) - FILEPROPERTY(f.name, 'SpaceUsed')) / 128.0) AS free_inside_file_mb, f.is_percent_growth, CASE WHEN f.is_percent_growth = 1 THEN CONVERT(decimal(19,2), f.growth) END AS growth_percent, CASE WHEN f.is_percent_growth = 0 THEN CONVERT(decimal(19,2), f.growth / 128.0) END AS growth_mb, f.max_size AS max_size_pages FROM sys.database_files AS f WHERE f.type = 0 ORDER BY f.file_id;","caveat":"Limited to the first 200 ROWS data files; a full 200-row result may be truncated. FILEPROPERTY can return NULL where metadata is unavailable. Free space is inside allocated files, not free space on the Windows volume. max_size_pages = -1 means growth is allowed to the engine's limit; 0 means no growth. FILESTREAM and other file types are excluded."},
{"name":"log_file_allocation","description":"Allocated transaction-log file space and growth settings.","sql":"SELECT TOP (200) DB_NAME() AS database_name, f.file_id, f.name AS logical_file_name, f.state_desc, CONVERT(decimal(19,2), f.size / 128.0) AS allocated_mb, f.is_percent_growth, CASE WHEN f.is_percent_growth = 1 THEN CONVERT(decimal(19,2), f.growth) END AS growth_percent, CASE WHEN f.is_percent_growth = 0 THEN CONVERT(decimal(19,2), f.growth / 128.0) END AS growth_mb, f.max_size AS max_size_pages FROM sys.database_files AS f WHERE f.type = 1 ORDER BY f.file_id;","caveat":"Limited to the first 200 log files; a full 200-row result may be truncated. This shows allocation, not active log usage. Windows volume free space and capacity forecasts require separate host telemetry. max_size_pages = -1 means growth is allowed to the engine's limit; 0 means no growth."},
{"name":"live_log_space_usage","description":"Current combined transaction-log usage for this database.","sql":"SELECT DB_NAME() AS database_name, CONVERT(decimal(19,2), total_log_size_in_bytes / 1048576.0) AS total_log_mb, CONVERT(decimal(19,2), used_log_space_in_bytes / 1048576.0) AS used_log_mb, CONVERT(decimal(19,2), (total_log_size_in_bytes - used_log_space_in_bytes) / 1048576.0) AS free_inside_log_mb, CONVERT(decimal(9,4), used_log_space_in_percent) AS used_log_percent FROM sys.dm_db_log_space_usage;","caveat":"SQL Server 2012 or later. This is an instantaneous database-wide value, not per-file occupancy or Windows disk free space. Access can require VIEW SERVER STATE on earlier releases or VIEW SERVER PERFORMANCE STATE on SQL Server 2022 and later; restricted visibility or an unsupported version must be reported as unavailable."},
{"name":"virtual_log_file_summary","description":"Transaction-log virtual log file count, activity, and size distribution.","sql":"SELECT DB_NAME() AS database_name, COUNT_BIG(*) AS vlf_count, SUM(CONVERT(bigint, CASE WHEN vlf_status = 2 THEN 1 ELSE 0 END)) AS active_vlf_count, CONVERT(decimal(19,2), SUM(vlf_size_mb)) AS total_vlf_mb, CONVERT(decimal(19,2), MIN(vlf_size_mb)) AS smallest_vlf_mb, CONVERT(decimal(19,2), MAX(vlf_size_mb)) AS largest_vlf_mb FROM sys.dm_db_log_info(DB_ID());","caveat":"sys.dm_db_log_info requires SQL Server 2016 SP2 or later and appropriate state/performance-state permissions. Older versions and permission failures are independent unavailable checks; do not substitute DBCC or change permissions. A VLF count alone does not establish a performance problem or justify a shrink operation."},
{"name":"direct_db_owner_members","description":"Direct membership of the current database's db_owner fixed role.","sql":"SELECT TOP (500) DB_NAME() AS database_name, r.name AS role_name, m.name AS member_name, m.type_desc AS member_type, m.authentication_type_desc, m.is_fixed_role AS member_is_fixed_role FROM sys.database_role_members AS rm INNER JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id INNER JOIN sys.database_principals AS m ON m.principal_id = rm.member_principal_id WHERE r.name = N'db_owner' ORDER BY m.name;","caveat":"Limited to the first 500 direct members; a full 500-row result may be truncated. Nested roles, Windows/AD group membership, inherited privileges, dbo ownership, sysadmin access, and effective access are not fully evaluated. Metadata visibility can hide memberships. Approved administrative identities have not been supplied, so listed identities are not automatically unauthorized."},
{"name":"database_role_memberships","description":"Direct database role membership edges for access review.","sql":"SELECT TOP (1000) DB_NAME() AS database_name, r.name AS role_name, r.is_fixed_role, m.name AS member_name, m.type_desc AS member_type, m.authentication_type_desc FROM sys.database_role_members AS rm INNER JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id INNER JOIN sys.database_principals AS m ON m.principal_id = rm.member_principal_id ORDER BY r.name, m.name;","caveat":"Limited to the first 1,000 membership edges; a full 1,000-row result may be truncated. This is a direct membership inventory, not a recursive or effective-permissions calculation. Nested/inherited roles and Windows/AD group expansion are not fully evaluated. Every database user implicitly belongs to public; that implicit membership is not represented by these rows. Metadata visibility can limit results."},
{"name":"guest_public_explicit_permissions","description":"Explicit cataloged permissions for guest and public, including grants, denies, and securable identifiers.","sql":"SELECT TOP (1000) DB_NAME() AS database_name, grantee.name AS grantee_name, p.state_desc, p.permission_name, p.class_desc, p.major_id, p.minor_id, CASE WHEN p.class = 0 THEN DB_NAME() WHEN p.class = 3 THEN SCHEMA_NAME(p.major_id) WHEN p.class = 1 THEN OBJECT_SCHEMA_NAME(p.major_id) + N'.' + OBJECT_NAME(p.major_id) END AS securable_name, CASE WHEN p.class = 1 AND p.minor_id > 0 THEN COL_NAME(p.major_id, p.minor_id) END AS column_name, grantor.name AS grantor_name FROM sys.database_permissions AS p INNER JOIN sys.database_principals AS grantee ON grantee.principal_id = p.grantee_principal_id LEFT JOIN sys.database_principals AS grantor ON grantor.principal_id = p.grantor_principal_id WHERE grantee.name IN (N'guest', N'public') ORDER BY grantee.name, p.class, p.major_id, p.minor_id, p.permission_name;","caveat":"Limited to the first 1,000 explicit permission rows; a full 1,000-row result may be truncated. These are cataloged entries, not effective access. Fixed-role permissions, ownership chains, module signing, nested memberships, inherited access, and broader server permissions are not fully evaluated. Guest CONNECT and system-object grants require database-specific interpretation; a row alone is not a security loophole. Metadata visibility may hide rows or names."},
{"name":"database_scope_explicit_permissions","description":"Explicit permissions granted or denied at database scope.","sql":"SELECT TOP (1500) DB_NAME() AS database_name, grantee.name AS grantee_name, grantee.type_desc AS grantee_type, p.state_desc, p.permission_name, grantor.name AS grantor_name FROM sys.database_permissions AS p INNER JOIN sys.database_principals AS grantee ON grantee.principal_id = p.grantee_principal_id LEFT JOIN sys.database_principals AS grantor ON grantor.principal_id = p.grantor_principal_id WHERE p.class = 0 ORDER BY grantee.name, p.permission_name, p.state_desc;","caveat":"Limited to the first 1,500 explicit database-scope rows; a full 1,500-row result may be truncated. Includes permissions such as CONTROL, ALTER, EXECUTE, UNMASK, and state visibility when present. Fixed-role permissions and effective access are not fully represented in sys.database_permissions. Nested/inherited memberships, ownership chains, server roles, and Windows/AD groups are not fully evaluated. Approved identities and sensitive-data inventory are absent."},
{"name":"principal_and_schema_high_impact_permissions","description":"Explicit impersonation and ownership/control permissions below database scope.","sql":"SELECT TOP (1000) DB_NAME() AS database_name, grantee.name AS grantee_name, grantee.type_desc AS grantee_type, p.state_desc, p.permission_name, p.class_desc, p.major_id, CASE WHEN p.class = 3 THEN SCHEMA_NAME(p.major_id) WHEN p.class = 4 THEN USER_NAME(p.major_id) WHEN p.class = 1 THEN OBJECT_SCHEMA_NAME(p.major_id) + N'.' + OBJECT_NAME(p.major_id) END AS securable_name, grantor.name AS grantor_name FROM sys.database_permissions AS p INNER JOIN sys.database_principals AS grantee ON grantee.principal_id = p.grantee_principal_id LEFT JOIN sys.database_principals AS grantor ON grantor.principal_id = p.grantor_principal_id WHERE p.class <> 0 AND p.permission_name IN (N'IMPERSONATE', N'CONTROL', N'ALTER', N'TAKE OWNERSHIP', N'UNMASK') ORDER BY grantee.name, p.class, p.major_id, p.permission_name;","caveat":"Limited to the first 1,000 matching explicit rows; a full 1,000-row result may be truncated. This selected permission inventory is not a complete effective-access audit. Metadata visibility can hide securables or principals. Nested roles, inherited access, Windows/AD group membership, ownership chains, signed modules, and sysadmin access are not fully evaluated."},
{"name":"row_level_security_summary","description":"Visible RLS policy and predicate counts for the current database.","sql":"SELECT DB_NAME() AS database_name, (SELECT COUNT_BIG(*) FROM sys.security_policies) AS visible_policy_count, (SELECT COUNT_BIG(*) FROM sys.security_policies WHERE is_enabled = 1) AS visible_enabled_policy_count, (SELECT COUNT_BIG(*) FROM sys.security_predicates) AS visible_predicate_count;","caveat":"Requires SQL Server 2016 or later. Catalog counts reflect visible metadata and do not prove complete inventory or enforcement for all identities. Sensitive databases/tables and required row-access rules have not been supplied; zero policies cannot by itself establish a policy violation, and policies do not establish adequacy of their predicates."},
{"name":"row_level_security_policy_details","description":"RLS policy status and protected object metadata, excluding predicate expressions.","sql":"SELECT TOP (1000) DB_NAME() AS database_name, ps.name AS policy_schema, sp.name AS policy_name, sp.is_enabled, sp.is_schema_bound, pr.security_predicate_id, pr.predicate_type_desc, pr.operation_desc, OBJECT_SCHEMA_NAME(pr.target_object_id) AS target_schema, OBJECT_NAME(pr.target_object_id) AS target_object FROM sys.security_policies AS sp INNER JOIN sys.schemas AS ps ON ps.schema_id = sp.schema_id LEFT JOIN sys.security_predicates AS pr ON pr.object_id = sp.object_id ORDER BY ps.name, sp.name, pr.security_predicate_id;","caveat":"Requires SQL Server 2016 or later. Limited to the first 1,000 policy/predicate rows; a full 1,000-row result may be truncated. Predicate SQL is deliberately excluded. Metadata visibility and missing sensitive-table classification limit conclusions. Disabled policies warrant context-specific review, but policy presence alone does not prove protection or resistance to privileged bypass."},
{"name":"masked_column_inventory","description":"Visible dynamic data masking column inventory without reading column values or masking expressions.","sql":"SELECT TOP (1000) DB_NAME() AS database_name, s.name AS schema_name, t.name AS table_name, c.column_id, c.name AS column_name, ty.name AS data_type_name, c.is_nullable, c.is_masked FROM sys.masked_columns AS c INNER JOIN sys.tables AS t ON t.object_id = c.object_id INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id INNER JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id WHERE c.is_masked = 1 AND t.is_ms_shipped = 0 ORDER BY s.name, t.name, c.column_id;","caveat":"Requires SQL Server 2016 or later. Limited to the first 1,000 masked columns; a full 1,000-row result may be truncated. Sensitive-data inventory has not been supplied, so masking coverage cannot be judged. Masking is not encryption and can be bypassed by identities with appropriate privileges; effective UNMASK and other access are not fully evaluated. Metadata visibility can limit results."},
{"name":"query_store_existing_configuration","description":"Existing Query Store state, capture configuration, and storage limits; leaves settings unchanged.","sql":"SELECT DB_NAME() AS database_name, desired_state_desc, actual_state_desc, readonly_reason, current_storage_size_mb, max_storage_size_mb, flush_interval_seconds, interval_length_minutes, stale_query_threshold_days, size_based_cleanup_mode_desc, query_capture_mode_desc, max_plans_per_query FROM sys.database_query_store_options;","caveat":"Requires SQL Server 2016 or later and appropriate metadata/state permissions. Query Store is not enabled or reconfigured by this collector. OFF, READ_ONLY, errors, or an empty result limit historical performance coverage. Retention and capture settings can omit relevant executions; existing Query Store state does not establish a complete workload history."},
{"name":"query_store_plan_aggregates_24h","description":"Top 100 existing Query Store plan/execution-type aggregates in intervals overlapping the preceding 24 hours, without workload SQL text, plan XML, or hashes.","sql":"WITH capture_window AS (SELECT DATEADD(hour, -24, SYSUTCDATETIME()) AS window_start_utc, SYSUTCDATETIME() AS window_end_utc), plan_totals AS (SELECT qp.query_id, rs.plan_id, rs.execution_type_desc, SUM(CONVERT(bigint, rs.count_executions)) AS execution_count, SUM(CONVERT(float, rs.avg_duration) * rs.count_executions) / 1000.0 AS total_duration_ms, SUM(CONVERT(float, rs.avg_cpu_time) * rs.count_executions) / 1000.0 AS total_cpu_ms, SUM(CONVERT(float, rs.avg_logical_io_reads) * rs.count_executions) AS total_logical_reads_pages, SUM(CONVERT(float, rs.avg_logical_io_writes) * rs.count_executions) AS total_logical_writes_pages, MAX(rs.max_duration) / 1000.0 AS maximum_duration_ms, MIN(rs.first_execution_time) AS first_execution_time, MAX(rs.last_execution_time) AS last_execution_time, MIN(i.start_time) AS first_included_interval_start, MAX(i.end_time) AS last_included_interval_end FROM sys.query_store_runtime_stats AS rs INNER JOIN sys.query_store_runtime_stats_interval AS i ON i.runtime_stats_interval_id = rs.runtime_stats_interval_id INNER JOIN sys.query_store_plan AS qp ON qp.plan_id = rs.plan_id CROSS JOIN capture_window AS w WHERE i.end_time > w.window_start_utc AND i.start_time < w.window_end_utc GROUP BY qp.query_id, rs.plan_id, rs.execution_type_desc) SELECT TOP (100) DB_NAME() AS database_name, w.window_start_utc, w.window_end_utc, p.query_id, p.plan_id, p.execution_type_desc, p.execution_count, p.total_duration_ms, p.total_duration_ms / NULLIF(p.execution_count, 0) AS weighted_average_duration_ms, p.maximum_duration_ms, p.total_cpu_ms, p.total_cpu_ms / NULLIF(p.execution_count, 0) AS weighted_average_cpu_ms, p.total_logical_reads_pages, p.total_logical_reads_pages / NULLIF(p.execution_count, 0) AS weighted_average_logical_reads_pages, p.total_logical_writes_pages, p.first_execution_time, p.last_execution_time, p.first_included_interval_start, p.last_included_interval_end FROM plan_totals AS p CROSS JOIN capture_window AS w ORDER BY p.total_duration_ms DESC, p.query_id, p.plan_id, p.execution_type_desc;","caveat":"Requires SQL Server 2016 or later, existing captured Query Store data, and appropriate permissions. Limited to the 100 plan/execution-type groups with highest accumulated duration; a full 100-row result may be truncated. Entire overlapping runtime intervals are included, so boundary intervals may contain executions before the 24-hour window. Multiple active-interval statistics rows are aggregated and averages are execution-count weighted. Durations and CPU use milliseconds; logical I/O uses 8-KB pages. Captured history may be incomplete or stale. These aggregates do not establish a regression, sustained CPU pressure, a baseline comparison, or an index recommendation. No query text, plan XML, hashes, or application row values are collected."},
{"name":"table_storage_metadata","description":"Largest 100 visible user tables by reserved allocation, using partition metadata only.","sql":"SELECT TOP (100) DB_NAME() AS database_name, s.name AS schema_name, t.name AS table_name, SUM(CASE WHEN p.index_id IN (0, 1) THEN p.row_count ELSE CONVERT(bigint, 0) END) AS approximate_row_count, CONVERT(decimal(19,2), SUM(p.reserved_page_count) / 128.0) AS reserved_mb_including_indexes, CONVERT(decimal(19,2), SUM(p.used_page_count) / 128.0) AS used_mb_including_indexes FROM sys.dm_db_partition_stats AS p INNER JOIN sys.tables AS t ON t.object_id = p.object_id INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id WHERE t.is_ms_shipped = 0 GROUP BY s.name, t.name, t.object_id ORDER BY SUM(p.reserved_page_count) DESC, s.name, t.name;","caveat":"Limited to the 100 largest visible user tables; a full 100-row result may be truncated. Row counts are approximate metadata; application rows are not read. Permission requirements vary by SQL Server version. Memory-optimized and other special storage may not be fully represented. This is an allocation inventory, not a fragmentation/bloat measurement or sufficient evidence for an index recommendation."}
]
'@ | ForEach-Object { $_ }
)
# Fail before connecting if PowerShell has wrapped a JSON query array.
if ($serverQueries.Count -ne 28 -or $databaseQueries.Count -ne 16) {
    throw 'Query loading failed: expected 28 separate server checks and 16 separate database checks.'
}
foreach ($queryDefinition in ($serverQueries + $databaseQueries)) {
    if ($null -eq $queryDefinition -or $queryDefinition -is [System.Array]) {
        throw 'Query loading failed: nested query definitions are not supported.'
    }
    if ($queryDefinition.name -isnot [string] -or
        $queryDefinition.sql -isnot [string] -or
        [string]::IsNullOrWhiteSpace($queryDefinition.name) -or
        [string]::IsNullOrWhiteSpace($queryDefinition.sql)) {
        throw 'Query loading failed: every check must have one name and one SQL statement.'
    }
}

$results = New-Object 'System.Collections.Generic.List[object]'
$report = [ordered]@{
    format_version = 1; started_at_utc = [DateTime]::UtcNow.ToString('o'); completed_at_utc = $null
    target = [ordered]@{server=$Server; port=$Port; authentication='SQL Server login (prompted securely)'; transport=$(if ($TrustServerCertificate.IsPresent) { 'TCP; encryption required; certificate validation bypassed by explicit request' } else { 'TCP; encryption required; certificate validation enabled' })}
    collection_options = [ordered]@{requested_databases=@($Databases);max_databases=$MaxDatabases;query_timeout_seconds=$QueryTimeoutSeconds;cpu_sample_minutes=$CpuSampleMinutes}
    status = 'collecting'; connection_error = $null; queries = @(); skipped_databases = @(); host_evidence = $null
    limitations = @(
        'Collected rows are evidence, not pass/fail compliance verdicts. Empty results and incomplete metadata visibility do not establish absence.'
        'SQL Server permissions, version support, and query timeouts may leave checks unassessed. Errors remain in the report.'
        'No application rows, query text, password hashes, or SQL state changes are requested. Use DBA-approved least privilege.'
        'Firewall/public exposure, authorized administrator inventory, sensitive-table inventory, backup RPOs, restore testing, and a CIS benchmark profile require external evidence.'
        'Backup timestamps are server-local history, not proof of backup availability, chain integrity, or recoverability. Wait/cache counters are cumulative.'
        'Replication requirements and acceptable lag need the expected topology and RPO. Query Store/cache evidence alone does not prove a regression.'
        'This is a manual collection. No persistent 24-hour scheduler has been installed.'
        $(if ($TrustServerCertificate.IsPresent) { 'Server certificate validation is bypassed for this target by explicit request. Encryption is required, but certificate chain/name validation is not established. Record this trust exception in the security audit.' } else { 'Server certificate validation remains enabled for this target.' })
    )
}
$connection = $null
$secureSqlPassword = $null
$script:AuditSqlCredential = $null
try {
    $sqlLoginName = Read-Host ('SQL Server login for ' + $Server + ':' + $Port)
    if ([string]::IsNullOrWhiteSpace($sqlLoginName)) {
        throw 'A SQL Server login name is required.'
    }
    $secureSqlPassword = Read-Host 'SQL Server password' -AsSecureString
    $secureSqlPassword.MakeReadOnly()
    $script:AuditSqlCredential = New-Object System.Data.SqlClient.SqlCredential(
        $sqlLoginName, $secureSqlPassword
    )
    $connection = New-AuditConnection -DatabaseName 'master'
    try { $connection.Open() } catch {
        $report.status = 'connection_failed'
        $report.connection_error = $_.Exception.Message
    }
    if ($connection.State -eq [Data.ConnectionState]::Open) {
        foreach ($definition in $serverQueries) {
            Write-Host ('Collecting server/' + $definition.name)
            $results.Add((Invoke-AuditQuery -Connection $connection -Definition $definition -DatabaseName 'master'))
        }
        $databaseListResult = @($results | Where-Object {$_.name -eq 'accessible_databases' -and $_.status -eq 'collected'})
        if ($databaseListResult.Count -eq 1) {
            $dbCandidates = @($databaseListResult[0].rows | Where-Object {$_.state_desc -eq 'ONLINE' -and $_.has_dbaccess -eq 1})
            if ($Databases.Count -gt 0) { $dbCandidates = @($dbCandidates | Where-Object {$Databases -contains $_.name}) }
            foreach ($dbRow in $databaseListResult[0].rows) {
                if ($Databases.Count -gt 0 -and $Databases -notcontains $dbRow.name) { continue }
                if ($dbRow.state_desc -ne 'ONLINE' -or $dbRow.has_dbaccess -ne 1) {
                    $report.skipped_databases += [pscustomobject]@{name=$dbRow.name;reason='Database is not ONLINE or current identity cannot access it.'}
                }
            }
            foreach ($requestedName in $Databases) {
                if (@($databaseListResult[0].rows | Where-Object {$_.name -eq $requestedName}).Count -eq 0) {
                    $report.skipped_databases += [pscustomobject]@{name=$requestedName;reason='Requested database was not visible in user-database enumeration.'}
                }
            }
            foreach ($dbRow in @($dbCandidates | Select-Object -Skip $MaxDatabases)) {
                $report.skipped_databases += [pscustomobject]@{name=$dbRow.name;reason='MaxDatabases collection limit reached; rerun with an explicit selection or higher limit.'}
            }
            foreach ($dbRow in @($dbCandidates | Select-Object -First $MaxDatabases)) {
                $dbConnection = $null
                try {
                    $dbConnection = New-AuditConnection -DatabaseName $dbRow.name
                    $dbConnection.Open()
                    foreach ($definition in $databaseQueries) {
                        Write-Host ('Collecting database ' + $dbRow.name + '/' + $definition.name)
                        $results.Add((Invoke-AuditQuery -Connection $dbConnection -Definition $definition -DatabaseName $dbRow.name))
                    }
                } catch {
                    $report.skipped_databases += [pscustomobject]@{name=$dbRow.name;reason=$_.Exception.GetBaseException().Message}
                } finally { if ($null -ne $dbConnection) { $dbConnection.Dispose() } }
            }
        } else { $report.limitations += 'User-database enumeration failed; database-scoped collection was not assessed.' }
        $identityResult = @($results | Where-Object {$_.name -eq 'identity' -and $_.status -eq 'collected'})
        $identity = $null
        if ($identityResult.Count -eq 1 -and $identityResult[0].row_count -eq 1) { $identity = $identityResult[0].rows[0] }
        $report.host_evidence = Get-LocalHostEvidence -Identity $identity
        $report.status = 'collected_with_unverified_external_checks'
        if (@($results | Where-Object {$_.status -ne 'collected'}).Count -gt 0 -or $report.skipped_databases.Count -gt 0 -or $report.host_evidence.status -ne 'collected') { $report.status = 'partial' }
    }
} catch {
    $report.status = 'partial'
    $report.limitations += ('Collector exception: ' + $_.Exception.GetBaseException().Message)
} finally {
    if ($null -ne $connection) { $connection.Dispose() }
    if ($null -ne $secureSqlPassword) { $secureSqlPassword.Dispose() }
    $script:AuditSqlCredential = $null
    $report.queries = @($results.ToArray())
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    $json = $report | ConvertTo-Json -Depth 20
    $stream = [IO.File]::Open($outputFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    Write-Host ('Audit evidence saved to ' + $outputFile + ' (' + $report.status + ').')
}
if ($report.status -eq 'connection_failed') { exit 2 }
if ($report.status -eq 'partial') { exit 3 }
