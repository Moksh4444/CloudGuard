# CloudGuard Architecture & Technical Design

## 1. System Overview

**CloudGuard** is a production-style educational platform designed for Cloud Security Engineers, Network Operations Analysts, and Technical Consultants. It provides safe, controlled diagnostic capabilities for inspecting network connectivity, DNS resolution, HTTP/HTTPS responses, TLS certificate parameters, and AWS Security Group configurations.

The architecture emphasizes:
- **Zero-Trust SSRF Protection:** Every external network attempt is validated against restricted IPv4 and IPv6 CIDR blocks before socket binding.
- **Transparent Troubleshooting Intelligence:** A deterministic, rule-based engine categorizes symptoms, explains potential technical root causes, cites diagnostic evidence, and recommends actionable next steps.
- **Stateless Diagnostics with Persistent History:** Diagnostic runs, individual checks, findings, and cloud evaluations are persisted to SQLite via SQLAlchemy for real analytical aggregation.

---

## 2. High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Client["Presentation Layer (Browser)"]
        UI["React 18 + TypeScript + Vite Dashboard"]
        Components["Tailwind CSS + Lucide Icons + Recharts"]
    end

    subgraph API_Gateway["FastAPI Gateway (Port 8000)"]
        Router["/api/v1 Central Router"]
        SanitizedLogs["Sanitized Structured Logger (Credentials Redacted)"]
        ExceptionH["Global Exception Boundary (No Stack Traces)"]
    end

    subgraph Security_Boundary["Zero-Trust Security Controls"]
        SSRF["SSRF Guard (Blocks Loopback, RFC1918, AWS 169.254.169.254)"]
        PortFilter["Port Restrictor (Approved Diagnostic Ports)"]
        RedirectGuard["Per-Hop Redirect Validator"]
    end

    subgraph Core_Engines["Diagnostic & Intelligence Engines"]
        DNS_Svc["DNS Resolution Service (A, AAAA, CNAME, MX, NS, TXT)"]
        Port_Svc["TCP Port Handshake (SYN-ACK vs RST vs Timeout)"]
        HTTP_Svc["HTTP/HTTPS Stream Inspector (Header Allowlist, Size Limit)"]
        TLS_Svc["TLS Certificate Inspector (SAN, Expiry, Cipher)"]
        Route_Svc["Bounded Traceroute (Subprocess, shell=False, max 15 hops)"]
        SG_Analyzer["AWS Security Group Heuristic Analyzer"]
        Intel_Engine["Troubleshooting Intelligence Engine"]
    end

    subgraph Storage["Data & Reporting Persistence"]
        DB[(SQLite Store: cloudguard.db)]
        Analytics["Analytics Engine (Percentiles, Distributions, Trends)"]
        Reports["Report Generator (JSON, CSV, Printable HTML)"]
    end

    UI -->|HTTP / JSON REST API| Router
    Router --> SanitizedLogs
    Router --> ExceptionH
    Router --> SSRF
    SSRF --> Core_Engines
    Core_Engines --> Intel_Engine
    Intel_Engine --> DB
    SG_Analyzer --> DB
    DB --> Analytics
    DB --> Reports
    Analytics --> UI
    Reports --> UI
```

---

## 3. Core Architectural Components

### A. Presentation Layer (Frontend)
- **Framework:** React 18, TypeScript, Vite.
- **Styling:** Tailwind CSS with dark enterprise charcoal theme (`#070b14`).
- **Data Visualizations:** Recharts (`AreaChart`, `BarChart`, `PieChart`, `ResponsiveContainer`).
- **Pages (9 Functional Modules):**
  1. `Overview Dashboard`: Executive metrics, real database aggregations, trend charts, recent sessions.
  2. `Network Diagnostics`: DNS + TCP Port handshake + optional bounded traceroute.
  3. `HTTP/HTTPS Analyzer`: URL inspection, redirect hop visualizer, allowlisted headers, TLS vs HTTP error distinction.
  4. `DNS Lookup`: Multi-record resolution (A, AAAA, CNAME, MX, NS, TXT) with latency tracking and educational guide.
  5. `TLS Inspector`: Subject, Issuer, SANs list, expiration countdown badge, negotiated TLS protocol, and cipher suite.
  6. `Cloud Security Analyzer`: AWS Security Group JSON heuristic analyzer with severity ratings and remediation commands.
  7. `Troubleshooting Reports`: Standardized report generator (JSON, CSV, printable HTML).
  8. `Scan History & Analytics`: Filterable, searchable audit table with pagination and session inspection modal.
  9. `Settings & Portfolio`: Runtime health, SSRF boundary settings, technical consultant career context.

### B. API Gateway & Security Perimeter (Backend)
- **Framework:** FastAPI with Python 3.11+.
- **Validation:** Pydantic V2 schemas for strict request/response typing.
- **SSRF Defense:** Intercepts targets before network operations. Checks against 16 IPv4 restricted CIDRs and 8 IPv6 CIDRs. Blocks AWS metadata (`169.254.169.254`), loopbacks, and private RFC 1918 subnets.
- **Safe Subprocess Execution:** Route traceroute diagnostics invoke system utilities (`tracert` / `traceroute`) without shell invocation (`shell=False`), bounding execution to 15 hops and 10 seconds.
- **Data Redaction:** Sensitive query parameters, `Authorization` headers, and cookie data are stripped from logs and exports.

---

## 4. Database Schema (SQLAlchemy Models)

```mermaid
erDiagram
    DiagnosticRun ||--o{ DiagnosticCheck : contains
    DiagnosticRun ||--o{ TroubleshootingFinding : produces
    DiagnosticRun ||--o| ReportMetadata : exports
    CloudConfigurationAnalysis ||--o{ SecurityFinding : evaluates

    DiagnosticRun {
        string id PK
        string target
        string target_type
        string status
        text summary
        float duration_ms
        datetime created_at
    }

    DiagnosticCheck {
        string id PK
        string run_id FK
        string check_type
        string status
        float duration_ms
        text details_json
        text error_message
        datetime created_at
    }

    TroubleshootingFinding {
        string id PK
        string run_id FK
        string symptom
        string confidence
        text explanations_json
        text diagnostic_evidence
        text next_steps_json
        text limitations
        datetime created_at
    }

    CloudConfigurationAnalysis {
        string id PK
        string name
        text raw_config_json
        text summary
        int critical_count
        int high_count
        int medium_count
        int low_count
        int info_count
        datetime created_at
    }

    SecurityFinding {
        string id PK
        string analysis_id FK
        string title
        string severity
        string rule_id
        string port_range
        string protocol
        string cidr
        text evidence
        text risk_explanation
        text remediation
        string confidence
        datetime created_at
    }

    ReportMetadata {
        string id PK
        string report_uid
        string title
        string target
        string scope
        string format
        datetime generated_at
        string run_id FK
    }
```
