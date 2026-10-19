# CloudGuard Security Controls & SSRF Defense Architecture

## 1. Security Philosophy

As a network troubleshooting and diagnostic platform, CloudGuard by definition initiates outbound network connections on behalf of the user. Consequently, **defensive security controls and Server-Side Request Forgery (SSRF) mitigations are built directly into the core design** rather than bolted on.

---

## 2. Server-Side Request Forgery (SSRF) Defense

### A. Prohibited IP Networks & Address Spaces
CloudGuard intercepts every user-supplied hostname or IP address and evaluates all resolved IP addresses against a strict blocklist prior to creating sockets:

| Range / CIDR | Classification | Security Justification |
| :--- | :--- | :--- |
| `127.0.0.0/8`, `::1/128` | Loopback | Prevents targeting local services running on the server host (e.g., local databases, redis, internal administrative ports). |
| `169.254.0.0/16`, `fe80::/10` | Link-Local / Cloud Metadata | Blocks access to `169.254.169.254` (AWS EC2 Instance Metadata Service, GCP metadata, Azure metadata), preventing theft of IAM credentials. |
| `10.0.0.0/8` | RFC 1918 Private | Blocks scanning or pivoting into internal VPC private subnets. |
| `172.16.0.0/12` | RFC 1918 Private | Blocks scanning or pivoting into internal Docker / Kubernetes pod subnets. |
| `192.168.0.0/16` | RFC 1918 Private | Blocks targeting internal home or office gateway routers and appliances. |
| `100.64.0.0/10` | Shared Address Space (CGNAT) | Prevents routing into carrier-grade private interconnects. |
| `0.0.0.0/8`, `::/128` | Current / Unspecified | Prevents source-only binding exploitation. |
| `224.0.0.0/4`, `ff00::/8` | Multicast | Prevents unauthorized multicast flooding. |
| `240.0.0.0/4` | Reserved / Future Use | Prevents anomalies on reserved IP stacks. |

### B. DNS Rebinding Mitigation
A common bypass in naive SSRF filters is **DNS Rebinding**, where a malicious authoritative nameserver returns a public IP during the first check, but resolves to a private IP (e.g. `127.0.0.1` or `169.254.169.254`) during the actual connection attempt.

CloudGuard mitigates this by:
1. Resolving the hostname using `socket.getaddrinfo`.
2. Inspecting **every single IP address** returned in the DNS response. If *any* IP belongs to a restricted subnet, the target is rejected immediately.
3. Connecting directly to the resolved and verified IP address.

### C. Per-Hop Redirect Validation
When performing HTTP/HTTPS analysis, CloudGuard does not blindly follow HTTP 301/302 redirects.
1. Automated redirects are disabled in the HTTP client (`follow_redirects=False`).
2. The diagnostic loop reads the `Location` header manually.
3. The destination URL is passed through full SSRF and scheme validation **before each subsequent hop**.
4. If a public endpoint redirects to an internal IP (e.g., `http://public-site.com` -> `http://169.254.169.254/latest/meta-data`), CloudGuard intercepts the redirect and halts execution.

---

## 3. Subprocess Execution Hardening

For route path discovery (traceroute):
- The application executes native system binaries (`tracert` on Windows, `traceroute` on Linux).
- **`shell=False` is strictly enforced** at all times. Arguments are passed as an explicit array:
  `["tracert", "-d", "-h", "15", "-w", "1000", target]`
- Subprocess execution is strictly bounded to a **10-second timeout** and a **15-hop limit**.
- Never requires administrative or root privileges.

---

## 4. Port Restriction & Anti-Weaponization Policy

To prevent the platform from being weaponized as an unrestricted port scanner:
- The backend enforces a curated list of approved diagnostic ports (`ALLOWED_PORTS`), covering standard enterprise web, DNS, database, and proxy services.
- Range scanning (e.g. scanning ports 1 through 65535) is architecturally prohibited.
- Requests to unapproved ports are rejected at the API boundary with descriptive feedback.

---

## 5. Sensitive Data Redaction

In accordance with data minimization principles:
- URL query parameters that might carry session tokens or credentials are not recorded in history.
- Response headers allowlisting excludes `Set-Cookie` and authentication session tokens.
- Application log streams filter all messages through regex redaction patterns targeting `Authorization: Bearer`, `password`, `token`, and `api-key`.
