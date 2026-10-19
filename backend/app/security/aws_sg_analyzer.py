"""
Cloud Security Configuration Analyzer for AWS Security Groups.
Performs rule-based least-privilege analysis on security group JSON configurations.
"""
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class RuleFinding(BaseModel):
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    rule_id: Optional[str] = None
    port_range: Optional[str] = None
    protocol: Optional[str] = None
    cidr: Optional[str] = None
    evidence: str
    risk_explanation: str
    remediation: str
    confidence: str = "HIGH"


class AnalysisResult(BaseModel):
    group_name: str
    group_id: Optional[str] = None
    description: Optional[str] = None
    vpc_id: Optional[str] = None
    total_rules_evaluated: int
    findings: List[RuleFinding] = Field(default_factory=list)
    summary: Dict[str, int]
    educational_note: str


# Sensitive administrative and management ports
ADMIN_PORTS = {
    22: ("SSH (Secure Shell)", "Allows remote interactive terminal management."),
    3389: ("RDP (Remote Desktop Protocol)", "Allows remote graphical desktop management for Windows."),
    23: ("Telnet", "Insecure plaintext remote management protocol."),
    5900: ("VNC", "Virtual Network Computing remote frame buffer protocol."),
    20: ("FTP Data", "Legacy file transfer protocol."),
    21: ("FTP Control", "Legacy plaintext file transfer protocol."),
}

# Sensitive database and cache ports
DATABASE_PORTS = {
    3306: ("MySQL / MariaDB", "Relational database server."),
    5432: ("PostgreSQL", "Relational database server."),
    1433: ("Microsoft SQL Server", "Relational database server."),
    1521: ("Oracle Database", "Relational database server."),
    27017: ("MongoDB", "NoSQL document database."),
    6379: ("Redis", "In-memory key-value data store (often unauthenticated)."),
    11211: ("Memcached", "Distributed caching memory object system."),
    9200: ("Elasticsearch", "RESTful search and analytics engine."),
    9092: ("Apache Kafka", "Distributed event streaming platform."),
}

PUBLIC_INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def analyze_security_group_json(config_data: Any) -> AnalysisResult:
    """
    Parses and evaluates an AWS Security Group JSON configuration against
    cloud security least-privilege benchmarks.
    """
    if isinstance(config_data, str):
        try:
            data = json.loads(config_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {str(e)}")
    elif isinstance(config_data, dict):
        data = config_data
    else:
        raise ValueError("Configuration data must be a JSON string or dictionary.")

    # AWS describes security groups either at root or inside SecurityGroups list
    if "SecurityGroups" in data and isinstance(data["SecurityGroups"], list) and len(data["SecurityGroups"]) > 0:
        sg = data["SecurityGroups"][0]
    else:
        sg = data

    group_name = sg.get("GroupName", sg.get("GroupId", "Unnamed-SecurityGroup"))
    group_id = sg.get("GroupId", "sg-unknown")
    description = sg.get("Description", "")
    vpc_id = sg.get("VpcId", "")

    ingress_rules = sg.get("IpPermissions", [])
    egress_rules = sg.get("IpPermissionsEgress", [])

    findings: List[RuleFinding] = []
    total_rules = 0

    # 1. Evaluate Inbound (Ingress) Rules
    for idx, rule in enumerate(ingress_rules):
        total_rules += 1
        protocol = rule.get("IpProtocol", "tcp")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        ip_ranges = rule.get("IpRanges", [])
        ipv6_ranges = rule.get("Ipv6Ranges", [])

        cidrs = [r.get("CidrIp") for r in ip_ranges if r.get("CidrIp")]
        ipv6_cidrs = [r.get("CidrIpv6") for r in ipv6_ranges if r.get("CidrIpv6")]
        all_cidrs = cidrs + ipv6_cidrs

        # Check for missing description
        rule_has_desc = any(r.get("Description") for r in ip_ranges + ipv6_ranges)
        if not rule_has_desc:
            findings.append(RuleFinding(
                title="Missing Documentation or Owner Description",
                severity="INFORMATIONAL",
                rule_id=f"inbound-{idx}",
                port_range=f"{from_port}-{to_port}" if from_port is not None else "All",
                protocol=protocol,
                cidr=", ".join(all_cidrs) if all_cidrs else "None",
                evidence=json.dumps(rule, indent=2),
                risk_explanation="Security group rules without descriptive context or ticket references complicate security audits and lifecycle cleanup.",
                remediation="Add a descriptive 'Description' field explaining the authorized service, owner, and reason for this rule.",
                confidence="HIGH"
            ))

        # Check for ALL Traffic (-1) exposed to the Internet
        if str(protocol) == "-1" or protocol.lower() == "all":
            for cidr in all_cidrs:
                if cidr in PUBLIC_INTERNET_CIDRS:
                    findings.append(RuleFinding(
                        title="Unrestricted ALL Traffic Ingress from Public Internet",
                        severity="CRITICAL",
                        rule_id=f"inbound-{idx}",
                        port_range="0-65535",
                        protocol="ALL (-1)",
                        cidr=cidr,
                        evidence=json.dumps(rule, indent=2),
                        risk_explanation=f"Rule exposes all protocols and all 65,535 TCP/UDP ports to the entire Internet ({cidr}). Any listening service on the attached instance is exposed to unauthorized external exploitation.",
                        remediation="Remove protocol '-1' ingress from public CIDRs. Explicitly permit only necessary destination ports and protocols from verified source IPs or security groups.",
                        confidence="HIGH"
                    ))

        # Check port ranges
        is_all_ports = False
        if from_port is not None and to_port is not None:
            port_span = to_port - from_port + 1
            if from_port == 0 and to_port == 65535:
                is_all_ports = True
            elif port_span > 100:
                for cidr in all_cidrs:
                    if cidr in PUBLIC_INTERNET_CIDRS:
                        findings.append(RuleFinding(
                            title=f"Excessively Broad Inbound Port Range ({from_port}-{to_port})",
                            severity="HIGH",
                            rule_id=f"inbound-{idx}",
                            port_range=f"{from_port}-{to_port}",
                            protocol=protocol,
                            cidr=cidr,
                            evidence=json.dumps(rule, indent=2),
                            risk_explanation=f"Exposing a range of {port_span} ports to {cidr} violates the principle of least privilege and increases the surface area for port scanning and unmonitored service exposure.",
                            remediation="Narrow the allowed port range to only the distinct ports required by the workload.",
                            confidence="HIGH"
                        ))

        # Check for sensitive admin ports
        for port, (name, desc) in ADMIN_PORTS.items():
            if from_port is not None and to_port is not None:
                if from_port <= port <= to_port:
                    for cidr in all_cidrs:
                        if cidr in PUBLIC_INTERNET_CIDRS:
                            findings.append(RuleFinding(
                                title=f"Publicly Accessible {name} (Port {port})",
                                severity="CRITICAL",
                                rule_id=f"inbound-{idx}",
                                port_range=str(port),
                                protocol=protocol,
                                cidr=cidr,
                                evidence=json.dumps(rule, indent=2),
                                risk_explanation=f"{name} on port {port} is exposed to the entire Internet ({cidr}). {desc} This exposes the system to brute force password attacks, credential stuffing, and unauthenticated remote exploits.",
                                remediation=f"Restrict port {port} ingress to authorized corporate CIDRs, a VPN gateway, or use AWS Systems Manager Session Manager (SSM) without opening inbound ports.",
                                confidence="HIGH"
                            ))

        # Check for database ports
        for port, (name, desc) in DATABASE_PORTS.items():
            if from_port is not None and to_port is not None:
                if from_port <= port <= to_port:
                    for cidr in all_cidrs:
                        if cidr in PUBLIC_INTERNET_CIDRS:
                            findings.append(RuleFinding(
                                title=f"Publicly Accessible Database Port {name} (Port {port})",
                                severity="CRITICAL",
                                rule_id=f"inbound-{idx}",
                                port_range=str(port),
                                protocol=protocol,
                                cidr=cidr,
                                evidence=json.dumps(rule, indent=2),
                                risk_explanation=f"Database port {port} ({name}) is open to the public Internet ({cidr}). {desc} Databases should reside in private subnets and should never accept unauthenticated inbound packets from 0.0.0.0/0.",
                                remediation=f"Change source CIDR from {cidr} to application tier security group IDs or internal VPC private subnets. Place database in an isolated VPC subnet.",
                                confidence="HIGH"
                            ))

        # Standard web ports (80 HTTP, 443 HTTPS)
        if from_port in (80, 443) and to_port in (80, 443):
            for cidr in all_cidrs:
                if cidr in PUBLIC_INTERNET_CIDRS:
                    findings.append(RuleFinding(
                        title=f"Public Inbound Web Traffic Permitted ({protocol.upper()} {from_port})",
                        severity="INFORMATIONAL",
                        rule_id=f"inbound-{idx}",
                        port_range=str(from_port),
                        protocol=protocol,
                        cidr=cidr,
                        evidence=json.dumps(rule, indent=2),
                        risk_explanation=f"Port {from_port} is open to the Internet. For public ALBs and web tiers, this is normal; ensure this security group is not attached to internal microservices or database hosts.",
                        remediation="Verify that this security group is intended for public-facing reverse proxies or load balancers only, and ensure TLS redirection is enforced.",
                        confidence="HIGH"
                    ))

    # 2. Evaluate Outbound (Egress) Rules
    for idx, rule in enumerate(egress_rules):
        total_rules += 1
        protocol = rule.get("IpProtocol", "tcp")
        ip_ranges = rule.get("IpRanges", [])
        all_cidrs = [r.get("CidrIp") for r in ip_ranges if r.get("CidrIp")]

        if (str(protocol) == "-1" or protocol.lower() == "all") and any(c == "0.0.0.0/0" for c in all_cidrs):
            findings.append(RuleFinding(
                title="Unrestricted Outbound Internet Egress (0.0.0.0/0)",
                severity="LOW",
                rule_id=f"outbound-{idx}",
                port_range="All",
                protocol="ALL (-1)",
                cidr="0.0.0.0/0",
                evidence=json.dumps(rule, indent=2),
                risk_explanation="Default AWS security groups permit unrestricted egress to all destination IPs and ports. In high-security environments, unrestricted outbound traffic can allow compromised instances to establish command-and-control (C2) channels or exfiltrate data.",
                remediation="Consider restricting egress to necessary external endpoints via a forward proxy, VPC endpoints, or stateful firewall (AWS Network Firewall / Skyhigh Cloud Security Gateway).",
                confidence="HIGH"
            ))

    # Summary counts
    severity_counts = {
        "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.severity == "LOW"),
        "INFORMATIONAL": sum(1 for f in findings if f.severity == "INFORMATIONAL"),
    }

    educational_note = (
        "Educational Assessment: This analysis performs static heuristic evaluation of the supplied JSON security group configuration "
        "against AWS Well-Architected Security Pillar best practices. It evaluates rule definitions directly and does not inspect "
        "live AWS environment state, route tables, Network ACLs, or attached EC2 instances."
    )

    return AnalysisResult(
        group_name=group_name,
        group_id=group_id,
        description=description,
        vpc_id=vpc_id,
        total_rules_evaluated=total_rules,
        findings=findings,
        summary=severity_counts,
        educational_note=educational_note
    )
