#requires -Version 5.1
<#
Dependency-free collector tests. All fixtures are synthetic.
SQL connections, host metrics, prompts, and sleeps are intercepted; no server
or credentials are required. Run with powershell.exe or pwsh -NoProfile -File.
#>
[CmdletBinding()]
param(
    [string]$CollectorPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Collect-DbaAudit.ps1')
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
$script:FixtureLogin = 'SyntheticAuditLogin'
$script:FixturePassword = 'SyntheticFixtureOnly-NotARealPassword'
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('dba-audit-tests-' + [guid]::NewGuid().ToString('N'))

function Assert-Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        $script:Passed++
        Write-Host ('PASS: ' + $Message)
    } else {
        $script:Failed++
        Write-Host ('FAIL: ' + $Message)
    }
}

function Read-CollectorAst {
    param([string]$Path)
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw ('Collector parse failed: ' + $parseErrors[0].Message)
    }
    return $ast
}

$fixtureTypes = @'
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Security;
public static class DbaAuditTestState {
    public const string FixtureLogin = "SyntheticAuditLogin";
    public const string FixturePassword = "SyntheticFixtureOnly-NotARealPassword";
    public static Dictionary<string,string> QueryNames = new Dictionary<string,string>();
    public static string FailQuery;
    public static bool EmulatePs5;
    public static bool FailOpen;
    public static int PromptCount;
    public static int SecurePromptCount;
    public static int OpenCount;
    public static int CommandCount;
    public static int DisposedConnections;
    public static int ServerPackCount;
    public static int DatabasePackCount;
    public static int CollectorExitCode;
    public static SecureString LastPassword;
    public static void Reset(bool ps5, string fail, bool failOpen) {
        EmulatePs5=ps5; FailQuery=fail; FailOpen=failOpen;
        PromptCount=0; SecurePromptCount=0; OpenCount=0; CommandCount=0;
        DisposedConnections=0; ServerPackCount=0; DatabasePackCount=0;
        CollectorExitCode=0; LastPassword=null;
    }
    public static DataTable Read(string sql, string database) {
        CommandCount++;
        string name;
        if (!QueryNames.TryGetValue(sql, out name))
            throw new InvalidOperationException("Mock rejected an unknown SQL command.");
        if (name == FailQuery)
            throw new InvalidOperationException("Synthetic permission denial for " + name);
        var table = new DataTable();
        if (name == "identity") {
            table.Columns.Add("physical_machine_name", typeof(string));
            table.Columns.Add("machine_name", typeof(string));
            table.Columns.Add("process_id", typeof(int));
            table.Rows.Add("SYNTHETIC-TESTPC", "SYNTHETIC-TESTPC", 123);
        } else if (name == "accessible_databases") {
            table.Columns.Add("name", typeof(string));
            table.Columns.Add("state_desc", typeof(string));
            table.Columns.Add("has_dbaccess", typeof(int));
            table.Rows.Add("SyntheticAppOne", "ONLINE", 1);
            table.Rows.Add("SyntheticAppTwo", "ONLINE", 1);
        } else {
            table.Columns.Add("synthetic_query", typeof(string));
            table.Columns.Add("synthetic_database", typeof(string));
            table.Rows.Add(name, database);
        }
        return table;
    }
}
public sealed class DbaAuditTestConnection : IDisposable {
    public string DatabaseName { get; set; }
    public object Credential { get; set; }
    public ConnectionState State { get; private set; }
    public void Open() {
        DbaAuditTestState.OpenCount++;
        if (DbaAuditTestState.FailOpen)
            throw new InvalidOperationException("Synthetic connection failure");
        State=ConnectionState.Open;
    }
    public DbaAuditTestCommand CreateCommand() {
        return new DbaAuditTestCommand { DatabaseName=DatabaseName };
    }
    public void Dispose() {
        DbaAuditTestState.DisposedConnections++; State=ConnectionState.Closed;
    }
}
public sealed class DbaAuditTestCommand : IDisposable {
    public string DatabaseName { get; set; }
    public string CommandText { get; set; }
    public int CommandTimeout { get; set; }
    public DbDataReader ExecuteReader() {
        return DbaAuditTestState.Read(CommandText, DatabaseName).CreateDataReader();
    }
    public void Dispose() {}
}
'@

# Windows PowerShell's compiler needs explicit framework references.
if ($PSVersionTable.PSVersion.Major -le 5) {
    Add-Type -TypeDefinition $fixtureTypes -ReferencedAssemblies @('System.Data', 'System.Xml')
} else {
    Add-Type -TypeDefinition $fixtureTypes
}

function Read-Host {
    param([string]$Prompt, [switch]$AsSecureString)
    [DbaAuditTestState]::PromptCount++
    if ($AsSecureString) {
        [DbaAuditTestState]::SecurePromptCount++
        $password = New-Object Security.SecureString
        foreach ($character in [DbaAuditTestState]::FixturePassword.ToCharArray()) {
            $password.AppendChar($character)
        }
        [DbaAuditTestState]::LastPassword = $password
        return $password
    }
    return [DbaAuditTestState]::FixtureLogin
}

function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    switch ($ClassName) {
        'Win32_LogicalDisk' {
            [pscustomobject]@{DeviceID='C:'; Size=10000; FreeSpace=9000}
        }
        'Win32_OperatingSystem' {
            [pscustomobject]@{TotalVisibleMemorySize=1000; FreePhysicalMemory=500; LastBootUpTime=[datetime]'2020-01-01'}
        }
        default { throw ('Unexpected CIM call in CPU=0 tests: ' + $ClassName) }
    }
}

function Start-Sleep { throw 'Collector tests must not sleep.' }

function ConvertFrom-Json {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)][string]$InputObject)
    process {
        $parsed = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject
        if ([DbaAuditTestState]::EmulatePs5 -and $parsed -is [array]) {
            return ,$parsed
        }
        return $parsed
    }
}

function Test-PasswordDisposed {
    try {
        $null = [DbaAuditTestState]::LastPassword.IsReadOnly()
        return $false
    } catch {
        return ($_.Exception.GetBaseException() -is [ObjectDisposedException])
    }
}

function Invoke-CollectorCase {
    param(
        [string]$Name,
        [bool]$Ps5,
        [string]$FailQuery = '',
        [switch]$TrustCertificate,
        [switch]$FailOpen,
        [switch]$BreakLoaders
    )
    [DbaAuditTestState]::Reset($Ps5, $FailQuery, $FailOpen.IsPresent)
    $source = [IO.File]::ReadAllText($CollectorPath)
    $changes = New-Object 'System.Collections.Generic.List[object]'
    $connectionFunction = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-AuditConnection'
    }, $false))
    if ($connectionFunction.Count -ne 1) { throw 'Expected one connection function.' }

    # Substitute only the connection factory. No real SqlConnection.Open runs.
    $fakeFunction = @'
function New-AuditConnection {
    param([string]$DatabaseName)
    $fake = New-Object DbaAuditTestConnection
    $fake.DatabaseName = $DatabaseName
    $fake.Credential = $script:AuditSqlCredential
    return $fake
}
'@
    $changes.Add([pscustomobject]@{
        start=$connectionFunction[0].Extent.StartOffset
        end=$connectionFunction[0].Extent.EndOffset
        text=$fakeFunction
    })
    $resultsAssignment = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$results'
    })
    if ($resultsAssignment.Count -ne 1) { throw 'Expected one results initialization.' }
    $instrumentation = @'
[DbaAuditTestState]::ServerPackCount = @($serverQueries).Count
[DbaAuditTestState]::DatabasePackCount = @($databaseQueries).Count

'@
    $changes.Add([pscustomobject]@{
        start=$resultsAssignment[0].Extent.StartOffset
        end=$resultsAssignment[0].Extent.StartOffset
        text=$instrumentation
    })
    $exitStatements = $ast.FindAll({param($node) $node -is [Management.Automation.Language.ExitStatementAst]}, $false)
    foreach ($exitStatement in $exitStatements) {
        if ($exitStatement.Extent.Text -notmatch '^exit ([23])$') { throw 'Unexpected exit statement.' }
        $changes.Add([pscustomobject]@{
            start=$exitStatement.Extent.StartOffset
            end=$exitStatement.Extent.EndOffset
            text=('[DbaAuditTestState]::CollectorExitCode = ' + $Matches[1])
        })
    }
    foreach ($change in @($changes | Sort-Object start -Descending)) {
        $source = $source.Substring(0, $change.start) + $change.text + $source.Substring($change.end)
    }
    if ($BreakLoaders) {
        # Reproduce the old loader bug without storing another collector copy.
        $source = $source.Replace('| ForEach-Object { $_ }', '')
    }
    $testScript = Join-Path $testDirectory ($Name + '.ps1')
    $output = Join-Path $testDirectory ($Name + '.json')
    [IO.File]::WriteAllText($testScript, $source)
    $null = Read-CollectorAst -Path $testScript
    $caughtError = $null
    try {
        & $testScript -Server 'synthetic-host.invalid' -Port 1433 -CpuSampleMinutes 0 -OutputPath $output -TrustServerCertificate:$TrustCertificate.IsPresent 6>$null
    } catch {
        $caughtError = $_.Exception.GetBaseException().Message
        if (-not $BreakLoaders) { throw }
    }
    if ($BreakLoaders) {
        return [pscustomobject]@{error=$caughtError; output_exists=(Test-Path -LiteralPath $output)}
    }
    return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($output)))
}

function Assert-CompleteReport {
    param($Report, [string]$Case, [bool]$ExpectedFailure, [bool]$TrustCertificate)
    Assert-Check ([DbaAuditTestState]::ServerPackCount -eq 28 -and [DbaAuditTestState]::DatabasePackCount -eq 16) ($Case + ': loaders contain 28 and 16 individual definitions')
    Assert-Check ($Report.queries.Count -eq 60 -and [DbaAuditTestState]::CommandCount -eq 60) ($Case + ': main executes all 60 checks for two databases')
    Assert-Check (@($Report.queries | Where-Object {$_.name -isnot [string]}).Count -eq 0) ($Case + ': every report query name is scalar')
    Assert-Check (@($Report.queries | Where-Object {$_.database -eq 'SyntheticAppOne'}).Count -eq 16 -and @($Report.queries | Where-Object {$_.database -eq 'SyntheticAppTwo'}).Count -eq 16) ($Case + ': both database loops finish')
    Assert-Check ($null -ne $Report.host_evidence -and $Report.host_evidence.status -eq 'collected' -and $Report.host_evidence.cpu_assessment -eq 'not_assessed') ($Case + ': host identity reaches collection and CPU=0 stays unassessed')
    Assert-Check ([DbaAuditTestState]::PromptCount -eq 2 -and [DbaAuditTestState]::SecurePromptCount -eq 1 -and [DbaAuditTestState]::OpenCount -eq 3 -and [DbaAuditTestState]::DisposedConnections -eq 3) ($Case + ': one secure prompt pair and all fake connections disposed')
    Assert-Check (Test-PasswordDisposed) ($Case + ': prompted SecureString is disposed')
    $json = $Report | ConvertTo-Json -Depth 20
    Assert-Check ($json -notmatch [regex]::Escape($script:FixturePassword) -and $json -notmatch 'AuditSqlCredential|secureSqlPassword') ($Case + ': password and credential objects are absent from report')
    if ($TrustCertificate) {
        Assert-Check ($Report.target.transport -match 'bypassed' -and ($Report.limitations -join ' ') -match 'trust exception') ($Case + ': explicit certificate bypass is reported')
    } else {
        Assert-Check ($Report.target.transport -match 'validation enabled') ($Case + ': default report records certificate validation')
    }
    $failures = @($Report.queries | Where-Object {$_.status -ne 'collected'})
    if ($ExpectedFailure) {
        Assert-Check ($Report.status -eq 'partial' -and [DbaAuditTestState]::CollectorExitCode -eq 3 -and $failures.Count -eq 1 -and $failures[0].name -eq 'wait_stats' -and $failures[0].error -match 'Synthetic permission denial') ($Case + ': independent query failure is preserved and status is partial')
    } else {
        Assert-Check ($Report.status -eq 'collected_with_unverified_external_checks' -and [DbaAuditTestState]::CollectorExitCode -eq 0 -and $failures.Count -eq 0) ($Case + ': complete status is supported by all results')
    }
}

function Test-ConnectionConstruction {
    # Exercise the real factory but never call Open on its connections.
    $factory = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-AuditConnection'
    }, $false))
    if ($factory.Count -ne 1) { throw 'Expected one real connection factory.' }
    . ([scriptblock]::Create($factory[0].Extent.Text))
    $Server = 'synthetic-host.invalid'
    $Port = 1433
    [switch]$TrustServerCertificate = $false
    $secureSqlPassword = New-Object Security.SecureString
    foreach ($character in $script:FixturePassword.ToCharArray()) { $secureSqlPassword.AppendChar($character) }
    $secureSqlPassword.MakeReadOnly()
    $script:AuditSqlCredential = New-Object System.Data.SqlClient.SqlCredential($script:FixtureLogin, $secureSqlPassword)
    $connection = $null
    $secondConnection = $null
    try {
        $connection = New-AuditConnection -DatabaseName 'master'
        $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder($connection.ConnectionString)
        Assert-Check ($builder.Encrypt -and -not $builder.TrustServerCertificate -and -not $builder.IntegratedSecurity -and -not $builder.Pooling) 'Real factory requires encryption and certificate validation by default'
        Assert-Check ($builder.ConnectTimeout -eq 30 -and $connection.State -eq 'Closed') 'Construction leaves connection closed with a 30-second timeout'
        Assert-Check ($builder.UserID -eq '' -and $builder.Password -eq '' -and $connection.ConnectionString -notmatch [regex]::Escape($script:FixturePassword)) 'Connection string contains no login or password'
        Assert-Check ($connection.Credential.Password.IsReadOnly() -and [object]::ReferenceEquals($connection.Credential.Password, $secureSqlPassword)) 'Factory retains read-only SecureString through SqlCredential'
        $TrustServerCertificate = $true
        $secondConnection = New-AuditConnection -DatabaseName 'SyntheticAppOne'
        $secondBuilder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder($secondConnection.ConnectionString)
        Assert-Check ($secondBuilder.Encrypt -and $secondBuilder.TrustServerCertificate) 'Explicit certificate switch preserves encryption and enables requested bypass'
        Assert-Check ([object]::ReferenceEquals($connection.Credential, $secondConnection.Credential)) 'Database connections reuse the same prompted credential'
        $Server = 'synthetic-host;Encrypt=False;User ID=synthetic'
        $database = 'synthetic-db;Integrated Security=True;Password=synthetic'
        $TrustServerCertificate = $false
        $quotedConnection = New-AuditConnection -DatabaseName $database
        try {
            $quotedBuilder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder($quotedConnection.ConnectionString)
            Assert-Check ($quotedBuilder.DataSource -eq ('tcp:' + $Server + ',1433') -and $quotedBuilder.InitialCatalog -eq $database -and $quotedBuilder.Encrypt -and -not $quotedBuilder.IntegratedSecurity -and -not $quotedBuilder.TrustServerCertificate -and $quotedBuilder.Password -eq '') 'Connection builder quotes endpoint and database values without option injection'
        } finally { $quotedConnection.Dispose() }
    } finally {
        if ($null -ne $secondConnection) { $secondConnection.Dispose() }
        if ($null -ne $connection) { $connection.Dispose() }
        $secureSqlPassword.Dispose()
        $script:AuditSqlCredential = $null
    }
    $missingRejected = $false
    try { $null = New-AuditConnection -DatabaseName 'master' } catch {
        $missingRejected = $_.Exception.Message -eq 'SQL login credentials have not been supplied.'
    }
    Assert-Check $missingRejected 'Factory rejects construction without credentials'
}

function Test-CpuSampling {
    $hostFunction = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LocalHostEvidence'
    }, $false))
    if ($hostFunction.Count -ne 1) { throw 'Expected one host-evidence function.' }
    $source = $hostFunction[0].Extent.Text
    $clockCall = '[Diagnostics.Stopwatch]::StartNew()'
    if (($source.Split(@($clockCall), [StringSplitOptions]::None).Length - 1) -ne 1) {
        throw 'Expected one CPU stopwatch construction.'
    }
    # Keep the actual sampling and assessment code; simulate only clock/CIM.
    . ([scriptblock]::Create($source.Replace($clockCall, '(New-TestStopwatch)')))
    function New-TestStopwatch {
        $script:ClockSeconds = 0
        $clock = [pscustomobject]@{}
        $clock | Add-Member -MemberType ScriptProperty -Name Elapsed -Value {
            [timespan]::FromSeconds($script:ClockSeconds)
        }
        $clock | Add-Member -MemberType ScriptMethod -Name Stop -Value {}
        return $clock
    }
    function Start-Sleep {
        param([int]$Seconds)
        $script:ClockSeconds += $Seconds
        if ($script:InjectGap -and -not $script:GapInjected -and $script:ClockSeconds -ge 480) {
            $script:ClockSeconds += 120
            $script:GapInjected = $true
        }
    }
    function Get-CimInstance {
        param([string]$ClassName, [string]$Filter)
        switch ($ClassName) {
            'Win32_LogicalDisk' {
                [pscustomobject]@{DeviceID='C:'; Size=10000; FreeSpace=9000}
            }
            'Win32_OperatingSystem' {
                [pscustomobject]@{TotalVisibleMemorySize=1000; FreePhysicalMemory=500; LastBootUpTime=[datetime]'2020-01-01'}
            }
            'Win32_ComputerSystem' {
                [pscustomobject]@{NumberOfLogicalProcessors=4}
            }
            'Win32_PerfFormattedData_PerfProc_Process' {
                $percent = & $script:CpuFixture $script:ClockSeconds
                [pscustomobject]@{Name='sqlservr'; PercentProcessorTime=([double]$percent * 4)}
            }
            default { throw ('Unexpected synthetic CIM class: ' + $ClassName) }
        }
    }
    function Invoke-CpuFixture {
        param([scriptblock]$Percent, [int]$Minutes=16, [switch]$Gap)
        $script:CpuFixture = $Percent
        $script:InjectGap = $Gap.IsPresent
        $script:GapInjected = $false
        $CpuSampleMinutes = $Minutes
        return (Get-LocalHostEvidence -Identity ([pscustomobject]@{
            physical_machine_name='SYNTHETIC-TESTPC'
            machine_name='SYNTHETIC-TESTPC'
            process_id=123
        }) 6>$null)
    }
    $result = Invoke-CpuFixture -Percent {param($elapsed) 80.0001}
    Assert-Check ($result.status -eq 'collected' -and $result.cpu_assessment -eq 'warning_sampled_cpu_above_80_percent_for_over_15_minutes') 'Raw CPU above 80 percent for 16 simulated minutes triggers a warning'
    Assert-Check ($result.sql_process_cpu_samples.Count -eq 17 -and $result.sql_process_cpu_samples[-1].elapsed_seconds -eq 960 -and $result.sql_process_cpu_samples[0].sql_instance_cpu_percent -eq 80) 'Simulated 16-minute sampling preserves raw threshold despite display rounding'
    $result = Invoke-CpuFixture -Percent {param($elapsed) 80.0}
    Assert-Check ($result.cpu_assessment -eq 'no_sustained_threshold_breach_observed_in_samples') 'Exactly 80 percent does not breach the CPU threshold'
    $result = Invoke-CpuFixture -Percent {param($elapsed) if ($elapsed -eq 0) { 0 } else { 99 }}
    Assert-Check ($result.cpu_assessment -eq 'no_sustained_threshold_breach_observed_in_samples') 'Exactly 900 seconds above threshold does not count as over 15 minutes'
    $result = Invoke-CpuFixture -Percent {param($elapsed) 99} -Gap
    Assert-Check ($result.status -eq 'partial' -and $result.cpu_assessment -eq 'not_assessed_due_to_sampling_gaps' -and $result.reason -match 'Gaps over 90 seconds') 'A gap over 90 seconds prevents a negative CPU verdict and marks evidence partial'
    $result = Invoke-CpuFixture -Percent {param($elapsed) 99} -Minutes 15
    Assert-Check ($result.cpu_assessment -eq 'insufficient_sampling_duration_for_over_15_minute_threshold') 'A 15-minute sample is insufficient for an over-15-minute threshold'
    $result = Invoke-CpuFixture -Percent {
        param($elapsed)
        if ($elapsed -ge 420) { throw 'Synthetic CPU counter failure' }
        return 99
    }
    Assert-Check ($result.status -eq 'partial' -and $result.cpu_assessment -eq 'not_assessed' -and $result.sql_process_cpu_samples.Count -eq 7 -and $result.errors.Count -eq 1) 'CPU counter failure retains prior samples and leaves threshold unassessed'
}

$originalComputerName = $env:COMPUTERNAME
try {
    $null = New-Item -ItemType Directory -Path $testDirectory
    $ast = Read-CollectorAst -Path $CollectorPath
    $blocks = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
        $node.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuotedHereString
    }, $false))
    if ($blocks.Count -ne 2) { throw 'Expected two embedded JSON query packs.' }
    foreach ($block in $blocks) {
        $definitions = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $block.Value
        foreach ($definition in $definitions) {
            [DbaAuditTestState]::QueryNames.Add([string]$definition.sql, [string]$definition.name)
        }
    }
    $env:COMPUTERNAME = 'SYNTHETIC-TESTPC'
    Test-ConnectionConstruction

    $native = Invoke-CollectorCase -Name 'enumerated-json' -Ps5 $false
    Assert-CompleteReport -Report $native -Case 'Enumerated JSON output' -ExpectedFailure $false -TrustCertificate $false
    $ps5 = Invoke-CollectorCase -Name 'ps5-json' -Ps5 $true -TrustCertificate
    Assert-CompleteReport -Report $ps5 -Case 'Windows PS5 JSON output' -ExpectedFailure $false -TrustCertificate $true
    $failedQuery = Invoke-CollectorCase -Name 'denied-query' -Ps5 $true -FailQuery 'wait_stats'
    Assert-CompleteReport -Report $failedQuery -Case 'One denied query' -ExpectedFailure $true -TrustCertificate $false

    $failedConnection = Invoke-CollectorCase -Name 'failed-connection' -Ps5 $true -FailOpen
    Assert-Check ($failedConnection.status -eq 'connection_failed' -and $failedConnection.connection_error -match 'Synthetic connection failure' -and [DbaAuditTestState]::CollectorExitCode -eq 2) 'Connection failure remains explicit with exit code 2'
    Assert-Check ($failedConnection.queries.Count -eq 0 -and [DbaAuditTestState]::CommandCount -eq 0 -and $null -eq $failedConnection.host_evidence) 'Connection failure does not produce database or host assessments'
    Assert-Check ([DbaAuditTestState]::DisposedConnections -eq 1 -and (Test-PasswordDisposed)) 'Failed connection and prompted password are disposed'

    $broken = Invoke-CollectorCase -Name 'unflattened-json' -Ps5 $true -BreakLoaders
    Assert-Check ($broken.error -match 'Query loading failed' -and -not $broken.output_exists) 'Nested JSON regression is rejected before creating a report'
    Assert-Check ([DbaAuditTestState]::PromptCount -eq 0 -and [DbaAuditTestState]::OpenCount -eq 0) 'Loader guard fails before prompts or connections'
    Test-CpuSampling
} finally {
    $env:COMPUTERNAME = $originalComputerName
    if (Test-Path -LiteralPath $testDirectory) {
        Remove-Item -LiteralPath $testDirectory -Recurse -Force
    }
}

Write-Host ('Collector checks on PowerShell ' + $PSVersionTable.PSVersion + ': ' + $script:Passed + ' passed; ' + $script:Failed + ' failed.')
if ($script:Failed -gt 0) { exit 1 }
