# vuln-exception-approver

Deterministic risk governance and vulnerability exception approval micro-agent under `@oakai-security`.

## 1. Overview & Single Responsibility Principle

`vuln-exception-approver` enforces deterministic risk acceptance criteria for vulnerability exception requests filed by `vuln-exception-requester`. In compliance with the Single Responsibility Principle (SRP):
- **Deterministic Risk Gates**: Strict algorithmic gates evaluate EPSS scores and active memory execution. The system does not delegate risk acceptance to non-deterministic LLM reasoning.
- **Tiered Expiration Scheduling**: Automatically computes time-bounded validity (30 days for Critical/High, 90 days for Medium/Low).
- **Enforced Remediation SLAs**: Automatically calculates mandatory remediation deadlines (7 days for Critical, 14 days for High, 30 days for Medium) when exceptions are rejected or revoked.
- **Active EPSS Spike Monitoring**: Regularly audits active approved exceptions against the live FIRST.org EPSS API, immediately revoking exceptions if exploit probability rises to 0.05 or higher.
- **Audit Logging & Register Updates**: Updates Markdown tickets (`tickets/EXC-XXXX.md`) and syncs `register/vulnerability_register.json` and `.md` in the dedicated `vuln-register` repository.

## 2. Governance Decision Matrix

| Condition | Verdict | Lifespan / Remediation SLA | Action |
|---|---|---|---|
| `in_memory == True` | `REJECTED` | 7-day SLA (Critical), 14-day SLA (High) | Sets ticket to `remediation_required`, emits alert |
| `epss_score >= 0.05` | `REJECTED` | 7-day SLA (Critical), 14-day SLA (High) | Sets ticket to `remediation_required`, emits alert |
| `epss_score < 0.05` AND `in_memory == False` (High/Crit) | `APPROVED` | 30 calendar days | Updates ticket to `approved`, sets expiration date |
| `epss_score < 0.05` AND `in_memory == False` (Med/Low) | `APPROVED` | 90 calendar days | Updates ticket to `approved`, sets expiration date |
| Active approval with EPSS spike to `>= 0.05` | `REVOKED` | 7-day mandatory remediation SLA | Revokes approval, flags ticket for immediate remediation |

## 3. Architecture & Interfaces

```
                           +----------------------------+
                           |  vuln-exception-requester  |
                           +--------------+-------------+
                                          |
                        Unix Domain Socket: /run/oakai/approve.sock
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                            vuln-exception-approver                                |
|                                                                                   |
|  +--------------------+    +--------------------+    +-------------------------+  |
|  |  decision_engine   |    |   sla_calculator   |    |      spike_monitor      |  |
|  |  (EPSS & /proc)    |    |  (30/90d & 7/14d)  |    |  (FIRST.org EPSS API)   |  |
|  +---------+----------+    +---------+----------+    +------------+------------+  |
|            |                         |                            |               |
|            +-------------------------+----------------------------+               |
|                                      |                                            |
|                                      v                                            |
|                        +---------------------------+                              |
|                        |     register_updater      |                              |
|                        +-------------+-------------+                              |
+--------------------------------------|--------------------------------------------+
                                       |
                         GitOps Commit & Update
                                       |
                                       v
                     +-----------------------------------+
                     |      @oakai-security/             |
                     |       vuln-register               |
                     |  - tickets/EXC-XXXX.md            |
                     |  - register/vulnerability_register|
                     +-----------------------------------+
```

## 4. CLI Usage

### Start Unix Domain Socket Daemon
```bash
vuln-exception-approver serve --socket /run/oakai/approve.sock --register-repo /repo
```

### Review Single Exception Request
```bash
vuln-exception-approver review-single -f exception_request.json
```

### Run Daily EPSS Spike Audit
```bash
vuln-exception-approver check-spikes --register-repo /repo
```

## 5. Security & Container Deployment

- **Non-Root Execution**: Runs as dedicated UID `1004` (`vuln-approver`) in GID `2000` (`oakai`).
- **Socket Permissions**: Group-accessible mode `0660` within `/run/oakai`.
- **Peer Credentials**: Validates connecting client credentials via `SO_PEERCRED`.
- **DevSecOps Pipeline**: Verified across Gitleaks, Semgrep SAST, Trivy SCA, and Pytest.
