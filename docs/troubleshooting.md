# CloudGuard Network & Cloud Security Troubleshooting Guide

## 1. Introduction for Cloud Security Technical Consultants

When troubleshooting enterprise connectivity and security incidents, a consultant must **clearly separate observed symptoms from unverified assumptions**. A single failed connection does not automatically prove a root cause; rather, each layer in the OSI stack provides diagnostic telemetry that narrows down the failure domain.

---

## 2. Layer-by-Layer Troubleshooting Workflows

### A. DNS Layer Troubleshooting
When a domain fails to resolve:

| Symptom | Diagnostic Observation | Likely Technical Causes | Recommended Next Steps |
| :--- | :--- | :--- | :--- |
| **NXDOMAIN** | Resolver returns non-existent domain code. | Typo in hostname; expired domain registration; zone delegation error. | Verify spelling; check registration using `whois <domain>`; query authoritative nameservers with `dig @8.8.8.8 <domain> +trace`. |
| **Timeout** | UDP 53 query packet yields no answer after timeout. | Local recursive resolver down; UDP 53 egress blocked by firewall. | Test alternative public resolvers: `nslookup <domain> 1.1.1.1` or `8.8.8.8`. Verify local network egress rules. |
| **SERVFAIL** | Upstream resolver unable to complete query. | DNSSEC validation failure on zone; authoritative nameservers unreachable. | Check DNSSEC signatures using `dig +dnssec <domain>`. Verify nameserver glue records. |

---

### B. Transport Layer (TCP) Troubleshooting
When establishing a TCP connection to an approved port:

| Symptom | Diagnostic Observation | Likely Technical Causes | Recommended Next Steps |
| :--- | :--- | :--- | :--- |
| **Connection Refused** | Client receives a **TCP RST** packet immediately. | Target OS is alive and network path is clear, but **no process is listening on the port**; or host firewall rejected. | Check daemon status on host: `netstat -tulnp \| grep <port>`; verify service is bound to `0.0.0.0`, not `127.0.0.1`. |
| **Connection Timeout** | Client sends **TCP SYN**, but receives neither SYN-ACK nor RST. | Cloud security group, Network ACL, or perimeter firewall is **silently dropping packets**. | Inspect AWS Security Group ingress rules; verify client public IP is authorized; check VPC route tables and internet gateways. |

---

### C. Application Layer (HTTP / HTTPS) Troubleshooting
When inspecting web application responses:

| HTTP Status | Diagnostic Classification | Likely Technical Causes | Recommended Next Steps |
| :--- | :--- | :--- | :--- |
| **401 Unauthorized** | Missing or Invalid Credentials | Request lacks valid authorization header or API key. | Inspect `WWW-Authenticate` header; supply valid Bearer token or credentials. |
| **403 Forbidden** | Access Denied / WAF Policy Block | Web Application Firewall (WAF) rule triggered; IP blocklist; geo-restriction. | Check response headers (`Server`, `CF-Ray`, `Via`) to identify blocking proxy; check WAF security event logs. |
| **404 Not Found** | Resource Missing | Requested URI path does not exist on origin; routing error on reverse proxy. | Verify URL path and spelling; inspect Nginx / ALB reverse proxy routing blocks. |
| **429 Too Many Requests** | Rate Limiting Enforced | Client exceeded API call rate limit threshold. | Inspect `Retry-After` header; implement exponential backoff with jitter in client. |
| **502 Bad Gateway** | Upstream Service Unreachable | Reverse proxy reached, but backend web service is down or returning invalid packets. | Verify backend containers/instances in ALB target group; check application service logs and memory usage. |
| **504 Gateway Timeout** | Upstream Timeout | Backend took too long to complete request before reverse proxy timeout. | Inspect database slow queries; evaluate upstream application thread pool capacity. |

---

### D. Cryptographic Layer (TLS) Troubleshooting
When inspecting TLS certificate parameters:

| Finding | Diagnostic Observation | Likely Technical Causes | Recommended Next Steps |
| :--- | :--- | :--- | :--- |
| **Certificate Expired** | Current date exceeds `valid_until` date. | Automated renewal (Certbot, AWS ACM) failed or was not configured. | Trigger renewal pipeline; inspect ACME challenge DNS TXT or HTTP validation records. |
| **Hostname Mismatch** | Hostname requested does not match CN or SAN list. | Server missing SNI (Server Name Indication) routing; certificate issued for different domain. | Verify Subject Alternative Names via `openssl s_client -connect <host>:443 -servername <host>`; update certificate domain coverage. |
| **Untrusted Root / Self-Signed** | Chain validation fails local CA trust store. | Self-signed certificate; internal enterprise CA not in client trust store; missing intermediate bundle. | Ensure web server serves full chain (`fullchain.pem`); install corporate root CA in operating system certificate store. |

---

### E. AWS Security Group Least-Privilege Evaluation
When analyzing cloud infrastructure configurations:

| Rule Pattern | Risk Severity | Security Impact | Recommended Remediation |
| :--- | :--- | :--- | :--- |
| **TCP 22 open to `0.0.0.0/0`** | **CRITICAL** | Exposes SSH management to public automated brute-force attacks and zero-days. | Restrict port 22 to corporate VPN CIDR, or migrate to AWS Systems Manager (SSM) Session Manager. |
| **TCP 3389 open to `0.0.0.0/0`** | **CRITICAL** | Exposes Windows RDP graphical desktop to internet credential stuffing. | Restrict RDP to authorized bastion subnets or AWS Client VPN. |
| **Database (3306, 5432) to `0.0.0.0/0`** | **CRITICAL** | Exposes relational databases directly to the public internet. | Move database instances to private VPC subnets; allow ingress only from application tier security group IDs. |
| **Protocol `-1` (All Traffic) to `0.0.0.0/0`** | **CRITICAL** | Exposes all 65,535 TCP and UDP ports to the internet. | Remove protocol `-1` rule; explicitly specify required destination ports only. |
| **Port ranges > 100 ports open** | **HIGH** | Violates least-privilege principles by unnecessarily broadening the attack surface. | Narrow the port range to specific required service ports. |
| **Missing Rule Description** | **INFORMATIONAL** | Lacks owner and ticket context, creating audit debt. | Add descriptive `Description` tag referencing the service and owning team. |
