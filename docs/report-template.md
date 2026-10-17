# 📋 DAILY INFRASTRUCTURE & SECURITY REPORT: [YYYY-MM-DD]

**Target Instances:** `[server]:[port]` — `[instance]`; databases `[scope]`

**Collection:** `[start]–[end] [timezone]`; source `[audit JSON filename]`

**Run Status:** `[completed / partial / connection_failed]`; `[collected / attempted checks]`

**Coverage Gaps:** `[failed checks, skipped databases, row limits, missing external evidence]`

Fill this template from the collected evidence. Replace each placeholder and label missing evidence **Not assessed**. A successful query, an empty result, or a short sampling window is not proof of security or all-day health. Reference the JSON query names or supporting evidence for each finding. Do not include passwords, private keys, or raw sensitive output.

## 🚨 CRITICAL ALERTS & SECURITY LOOPHOLES

- `[Validated finding, affected target, observed value/time, impact, and evidence reference; or state that no critical finding was observed within the assessed scope.]`
- `[Critical areas that remain unassessed.]`

## ⚠️ WARNINGS & PERFORMANCE DEGRADATIONS

- `[Warning with observed value, applicable threshold or policy, observation window, and evidence reference.]`
- `[Certificate-validation exception, excessive monitoring privileges, backup-evidence gap, or monitoring gap when supported.]`

## 📊 CORE TELEMETRY METRICS

### Microsoft SQL Server

- **CPU / Memory:** `[sampled CPU, duration and sample count; host/process memory and pressure indicators; PLE with context; or Not assessed]`.
- **Storage:** `[volume utilization and free space; database file allocation and active log usage; or Not assessed]`.
- **Service & Agent Status:** `[observed service states and startup types; or Not assessed]`.
- **Backup Verification:** `[latest recorded full/differential/log history and source; RPO policy; backup media/restore evidence; explicitly identify what remains unverified]`.
- **Concurrency:** `[current blocking, transactions and retained deadlock evidence; observation/retention limits]`.
- **Replication:** `[observed state versus expected topology and RPO; Not assessed where expectations or evidence are missing]`.

### PostgreSQL

- **Cache Hit Ratio:** `[external evidence or Not assessed; Not targeted if outside scope]`.
- **Connections:** `[external evidence or Not assessed; Not targeted if outside scope]`.
- **Storage / Bloat:** `[external evidence or Not assessed; Not targeted if outside scope]`.
- **Replication Lag:** `[external evidence or Not assessed; Not targeted if outside scope]`.

The supplied collector covers SQL Server only. PostgreSQL findings require a separate source.

## 🔒 SECURITY POLICY AUDIT SUMMARY

### Authentication & Access

- **SQL Server:** `[authentication mode; collector privileges; observed role/grant inventory compared with approved identities; visibility limits]`.
- **PostgreSQL:** `[external evidence or Not assessed; Not targeted if outside scope]`.

### Configuration & Surface Area Risk

- **SQL Server:** `[observed feature states, ownership/trust settings and transport policy; actual connection encryption and certificate validation; TDE, masking and RLS compared with sensitive-data requirements]`.
- **PostgreSQL:** `[external evidence or Not assessed; Not targeted if outside scope]`.
- **Policy coverage:** `[named policy/benchmark and scope when provided; otherwise record that a benchmark compliance verdict was not assessed]`.

## 🛠️ RECOMMENDED ACTIONS & REMEDIATION PLAYBOOK

1. **`[Priority and action]`:** `[Evidence, responsible owner, validation needed, and next step]`.
2. **`[Priority and action]`:** `[Evidence, responsible owner, validation needed, and next step]`.
3. **Close evidence gaps:** `[Required RPOs, restore-test records, approved identities, data classification, topology, network evidence, or longer sampling]`.

**Follow-up:** `[owner / next review date and timezone / evidence required]`. The collector does not execute remediation or schedule the next run.
