# GPT-AI-Agent

A read-only SQL Server collector for daily infrastructure and security reviews. Collect diagnostic evidence on Windows, then use the [report template](docs/report-template.md) to record findings and coverage gaps.

## Run the collector

1. Download this repository with **Code → Download ZIP**, extract it to a writable folder, and open **Windows PowerShell 5.1** in that folder.
2. Run the complete [Collect-DbaAudit.ps1](Collect-DbaAudit.ps1) script:

   ```powershell
   powershell.exe -NoProfile -File .\Collect-DbaAudit.ps1
   ```

3. Enter an existing SQL Server login and its password when prompted. The password input is masked. SQL authentication must already be enabled and the login must have appropriate monitoring permissions.
4. Allow at least **16 minutes** for CPU sampling, plus time for the database checks. The script prints the path of the resulting `DbaAudit-*.json` file.

The default target is the current Windows computer on TCP port **1433**. Run on the SQL Server computer to collect local Windows disk, memory, and process CPU evidence. Those metrics are attributed to the target only when the local computer name matches the server identity returned by SQL Server.

The default output folder is your Windows user profile. Existing output files are never overwritten. Results contain server, database, object, and login metadata; review them before sharing. Default `DbaAudit-*.json` files and files under `audit-output/` are excluded from Git. Keep custom-named audit output outside the checkout or add a local ignore rule before collecting it there.

### Connection examples

Use a hostname covered by a trusted SQL Server certificate:

```powershell
.\Collect-DbaAudit.ps1 -Server 'sql01.example.com' -Port 1433
```

For a local development server where SSMS connects with **Trust Server Certificate** selected, explicitly use the matching option:

```powershell
.\Collect-DbaAudit.ps1 -TrustServerCertificate
```

Encryption is required in both cases. `-TrustServerCertificate` skips validation of the server certificate and identity; the collector records this exception in the report. Certificate validation is enabled by default.

Choose specific user databases or an output location:

```powershell
.\Collect-DbaAudit.ps1 -Databases 'ExampleDb','ReportingDb' -OutputPath "$env:USERPROFILE\DbaAudit-selected.json"
```

Use the actual TCP port for a named instance. The collector does not discover dynamic ports through SQL Server Browser.

For a quick connection and metadata diagnostic, skip CPU sampling:

```powershell
.\Collect-DbaAudit.ps1 -CpuSampleMinutes 0
```

Skipping CPU sampling leaves sustained CPU usage unassessed. A collection shorter than 16 minutes cannot assess the alert for CPU above 80% for over 15 minutes.

### Options

| Parameter | Default | Purpose |
|---|---|---|
| `Server` | Current computer name | SQL Server hostname |
| `Port` | `1433` | SQL Server TCP port |
| `Databases` | All visible, online, accessible user databases | Limit database-scoped collection |
| `MaxDatabases` | `50` | Cap the number of user databases queried |
| `QueryTimeoutSeconds` | `15` | Timeout for each SQL check |
| `CpuSampleMinutes` | `16` | Local process CPU observation window; `0` skips it |
| `OutputPath` | Timestamped JSON in the user profile | Output file; parent folder must exist |
| `TrustServerCertificate` | Off | Explicitly bypass server certificate validation |

## What it collects

The collector runs **28 instance checks** and **16 checks per selected user database**. They cover:

- Instance identity, permissions, services, disks, memory, CPU evidence, and cumulative waits.
- Active requests, blocking, open transactions, locks, and retained deadlock summaries.
- Backup history, file and log allocation, VLF counts, and availability-group state.
- Server and database privileges, selected surface-area settings, encryption, RLS, and masking metadata.
- Existing Query Store aggregates, cached query metrics, missing-index suggestions, and table allocation metadata.

Database statements are fixed metadata `SELECT` queries. The collector does not read application row values, query text, execution-plan XML, or password hashes. It does not change SQL Server settings, create indexes, grant permissions, or run remediation. Local host checks use Windows CIM reads.

SQL credentials are prompted once and kept in memory for the run using `SqlCredential` and `SecureString`. The script does not put the password into the connection string or JSON output. Use a dedicated monitoring login with DBA-reviewed permissions. Different SQL Server versions require different permissions; restricted or unsupported checks are preserved as unassessed with their errors.

## Read the results

The JSON contains the target, collection options, timestamps, per-query rows and errors, skipped databases, local host evidence, and limitations. Use the [daily report template](docs/report-template.md) to distinguish observations from policy findings.

| Exit code | Meaning |
|---|---|
| `0` | Collection completed; external checks and policy inputs remain unverified |
| `2` | Initial SQL connection failed |
| `3` | Partial collection or collector error; inspect errors and coverage gaps |

Successful execution is not a security or recovery certification. Empty result sets do not establish that a feature, risk, or incident is absent. Some results are capped, metadata visibility can hide rows, and cumulative counters need a baseline or interval comparison.

Backup history does not verify backup files, restore chains, restore success, or an RPO. Security conclusions need approved administrator and sensitive-data inventories. Firewall exposure, certificate trust, expected replication topology, and a CIS benchmark assessment require additional evidence. Point-in-time checks and retained event buffers do not establish a full day's health.

This is a **manual collection**. Interactive credentials require a person to run it; no daily scheduler or unattended credential storage is installed. PostgreSQL collection is not implemented.

## Troubleshooting

- **Connection timeout:** Verify the SQL Server service and the actual TCP listening port. Test it with `Test-NetConnection -ComputerName 'sql01.example.com' -Port 1433`.
- **Untrusted certificate:** Configure a certificate and chain trusted by the client, with a name matching `-Server`. The explicit development exception above matches SSMS's trust option and is recorded as a security limitation.
- **Login failed:** Verify SQL authentication and the selected login with the DBA. Do not paste passwords into issues or commit them.
- **Partial results:** Inspect `connection_error`, query `error` fields, `skipped_databases`, and host evidence. Do not interpret missing metrics as zero activity.
- **Script execution blocked:** Follow your organization's PowerShell execution policy. The collector does not change that policy.

## Validation

Run the mocked regression checks from the repository folder with Windows PowerShell:

```powershell
powershell.exe -NoProfile -File .\tests\Test-Collector.ps1
```

If PowerShell 7 is installed, run them there too:

```powershell
pwsh -NoProfile -File .\tests\Test-Collector.ps1
```

These checks validate collector behavior without a live SQL Server connection. They do not establish live permissions, connectivity, certificate trust, or database health. Live validation requires running the collector against an authorized instance and reviewing its output.
