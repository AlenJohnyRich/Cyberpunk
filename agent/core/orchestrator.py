"""
Main orchestrator for the AI Cybersecurity Agent
Coordinates between different security domains and makes decisions
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
from enum import Enum

from agent.core.config import AgentConfig, DEFAULT_CONFIG


class SecurityDomain(Enum):
    """Enumeration of security domains"""
    NETWORKING = "networking"
    OPERATING_SYSTEMS = "operating_systems"
    PROGRAMMING = "programming"
    WEB_SECURITY = "web_security"
    MOBILE_SECURITY = "mobile_security"
    WIRELESS_SECURITY = "wireless_security"
    CLOUD_SECURITY = "cloud_security"
    ACTIVE_DIRECTORY = "active_directory"
    CRYPTOGRAPHY = "cryptography"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    PENETRATION_TESTING = "penetration_testing"
    DIGITAL_FORENSICS = "digital_forensics"
    INCIDENT_RESPONSE = "incident_response"
    MALWARE_ANALYSIS = "malware_analysis"
    REVERSE_ENGINEERING = "reverse_engineering"
    SOC_OPERATIONS = "soc_operations"
    FRAMEWORKS = "frameworks"
    SECURITY_TOOLS = "security_tools"
    SOCIAL_ENGINEERING = "social_engineering"


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class SecurityTask:
    """Represents a security analysis task"""
    task_id: str
    task_type: str  # scan, assessment, investigation, etc.
    target: str
    domains: List[SecurityDomain]
    urgency: ThreatLevel = ThreatLevel.HIGH
    authorization_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityFinding:
    """Represents a security finding or vulnerability"""
    finding_id: str
    title: str
    description: str
    domain: SecurityDomain
    severity: ThreatLevel
    affected_component: str
    recommendation: str
    references: List[str] = field(default_factory=list)
    mitigation_steps: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    is_exploitable: bool = False


class DecisionEngine:
    """Decision making engine for the security agent"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
    
    def is_authorized_task(self, task) -> bool:
        """Check if a task is authorized"""
        if not self.config.authorization.require_authorization:
            return True
        return self.config.authorization.is_authorized()


class CybersecurityAgent:
    """Main AI Cybersecurity Agent orchestrator"""
    
    def __init__(self, config: Optional[AgentConfig] = None):
        """Initialize the cybersecurity agent"""
        self.config = config or DEFAULT_CONFIG
        self.decision_engine = DecisionEngine(self.config)
        self.findings: List[SecurityFinding] = []
        self.task_history: List[SecurityTask] = []
        
        # Validate configuration
        is_valid, errors = self.config.validate()
        if not is_valid and self.config.authorization.require_authorization:
            raise ValueError(f"Configuration validation failed: {errors}")
        
        self._initialize_domains()
    
    def _initialize_domains(self) -> None:
        """Initialize all security domain modules"""
        self.domains = {}
        
        # Map of domain names to their expert modules
        domain_map = {
            SecurityDomain.NETWORKING.value: "networking",
            SecurityDomain.OPERATING_SYSTEMS.value: "operating_systems",
            SecurityDomain.PROGRAMMING.value: "programming",
            SecurityDomain.WEB_SECURITY.value: "web_security",
            SecurityDomain.MOBILE_SECURITY.value: "mobile_security",
            SecurityDomain.WIRELESS_SECURITY.value: "wireless_security",
            SecurityDomain.CLOUD_SECURITY.value: "cloud_security",
            SecurityDomain.ACTIVE_DIRECTORY.value: "active_directory",
            SecurityDomain.CRYPTOGRAPHY.value: "cryptography",
            SecurityDomain.VULNERABILITY_ASSESSMENT.value: "vulnerability_assessment",
            SecurityDomain.PENETRATION_TESTING.value: "penetration_testing",
            SecurityDomain.DIGITAL_FORENSICS.value: "digital_forensics",
            SecurityDomain.INCIDENT_RESPONSE.value: "incident_response",
            SecurityDomain.MALWARE_ANALYSIS.value: "malware_analysis",
            SecurityDomain.REVERSE_ENGINEERING.value: "reverse_engineering",
            SecurityDomain.SOC_OPERATIONS.value: "soc_operations",
            SecurityDomain.FRAMEWORKS.value: "frameworks",
            SecurityDomain.SECURITY_TOOLS.value: "security_tools",
            SecurityDomain.SOCIAL_ENGINEERING.value: "social_engineering",
        }
        
        # Lazy-load domain modules as needed
        for domain_enum, domain_name in domain_map.items():
            self.domains[domain_enum] = {
                "name": domain_name,
                "enabled": self.config.domains_enabled.get(domain_name, True),
                "module": None  # Will be loaded on demand
            }
    
    def analyze(self, task: SecurityTask) -> Dict[str, Any]:
        """
        Execute a security analysis task
        
        Args:
            task: The security task to analyze
            
        Returns:
            Analysis results with findings and recommendations
        """
        # Check authorization
        if not self.decision_engine.is_authorized_task(task):
            return {
                "status": "unauthorized",
                "error": "Task not authorized",
                "task_id": task.task_id
            }
        
        # Record task
        self.task_history.append(task)
        
        # Execute analysis based on task type
        if task.task_type == "vulnerability_scan":
            return self._execute_vulnerability_scan(task)
        elif task.task_type == "penetration_test":
            return self._execute_penetration_test(task)
        elif task.task_type == "incident_investigation":
            return self._execute_incident_investigation(task)
        elif task.task_type == "malware_analysis":
            return self._execute_malware_analysis(task)
        elif task.task_type == "security_audit":
            return self._execute_security_audit(task)
        else:
            return self._execute_general_analysis(task)
    
    def _execute_vulnerability_scan(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute a vulnerability assessment scan"""
        findings = []
        
        # Gather findings from applicable domains
        for domain in task.domains:
            if domain.value not in self.domains:
                continue
            
            domain_info = self.domains[domain.value]
            if not domain_info["enabled"]:
                continue
            
            # Simulate domain-specific findings
            domain_findings = self._get_domain_findings(domain, task.target)
            findings.extend(domain_findings)
        
        self.findings.extend(findings)
        
        return {
            "status": "success",
            "task_id": task.task_id,
            "task_type": task.task_type,
            "timestamp": datetime.now().isoformat(),
            "target": task.target,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.name,
                    "domain": f.domain.value,
                    "recommendation": f.recommendation
                }
                for f in findings
            ],
            "summary": self._generate_summary(findings)
        }
    
    def _execute_penetration_test(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute authorized penetration testing"""
        if not self.config.enable_exploitation:
            return {
                "status": "blocked",
                "error": "Exploitation mode not enabled",
                "task_id": task.task_id
            }
        
        findings = []
        
        # Execute authorized testing
        for domain in task.domains:
            domain_findings = self._get_domain_findings(domain, task.target)
            findings.extend([f for f in domain_findings if f.is_exploitable])
        
        self.findings.extend(findings)
        
        return {
            "status": "success",
            "task_id": task.task_id,
            "task_type": task.task_type,
            "timestamp": datetime.now().isoformat(),
            "target": task.target,
            "exploitable_findings": len(findings),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.name,
                    "is_exploitable": f.is_exploitable,
                    "mitigation": f.mitigation_steps
                }
                for f in findings
            ]
        }
    
    def _execute_incident_investigation(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute incident response and investigation"""
        findings = []
        
        # Use forensics and analysis domains
        forensics_findings = self._get_domain_findings(
            SecurityDomain.DIGITAL_FORENSICS, 
            task.target
        )
        ir_findings = self._get_domain_findings(
            SecurityDomain.INCIDENT_RESPONSE,
            task.target
        )
        
        findings.extend(forensics_findings)
        findings.extend(ir_findings)
        
        self.findings.extend(findings)
        
        return {
            "status": "success",
            "task_id": task.task_id,
            "task_type": task.task_type,
            "timestamp": datetime.now().isoformat(),
            "target": task.target,
            "investigation_findings": len(findings),
            "next_steps": self._get_incident_response_steps(findings)
        }
    
    def _execute_malware_analysis(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute malware analysis"""
        findings = []
        
        malware_findings = self._get_domain_findings(
            SecurityDomain.MALWARE_ANALYSIS,
            task.target
        )
        re_findings = self._get_domain_findings(
            SecurityDomain.REVERSE_ENGINEERING,
            task.target
        )
        
        findings.extend(malware_findings)
        findings.extend(re_findings)
        
        return {
            "status": "success",
            "task_id": task.task_id,
            "task_type": task.task_type,
            "timestamp": datetime.now().isoformat(),
            "target": task.target,
            "behaviors_identified": len(findings),
            "threat_level": "HIGH" if findings else "LOW"
        }
    
    def _execute_security_audit(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute comprehensive security audit"""
        findings = []
        
        # Audit all domains
        for domain in task.domains:
            domain_findings = self._get_domain_findings(domain, task.target)
            findings.extend(domain_findings)
        
        self.findings.extend(findings)
        
        # Group findings by domain
        domain_summary = {}
        for finding in findings:
            domain = finding.domain.value
            if domain not in domain_summary:
                domain_summary[domain] = {"count": 0, "critical": 0}
            domain_summary[domain]["count"] += 1
            if finding.severity == ThreatLevel.CRITICAL:
                domain_summary[domain]["critical"] += 1
        
        return {
            "status": "success",
            "task_id": task.task_id,
            "task_type": task.task_type,
            "timestamp": datetime.now().isoformat(),
            "target": task.target,
            "total_findings": len(findings),
            "domain_summary": domain_summary,
            "compliance_status": self._assess_compliance(findings)
        }
    
    def _execute_general_analysis(self, task: SecurityTask) -> Dict[str, Any]:
        """Execute general security analysis"""
        findings = []
        
        for domain in task.domains:
            domain_findings = self._get_domain_findings(domain, task.target)
            findings.extend(domain_findings)
        
        return {
            "status": "success",
            "task_id": task.task_id,
            "task_type": task.task_type,
            "timestamp": datetime.now().isoformat(),
            "target": task.target,
            "domains_analyzed": [d.value for d in task.domains],
            "findings_count": len(findings)
        }
    
    def _get_domain_findings(self, domain: SecurityDomain, target: str) -> List[SecurityFinding]:
        """Get findings from a specific security domain"""
        # This is a placeholder - in production, this would call actual analysis tools
        # and domain-specific expertise modules
        findings = []
        
        if domain == SecurityDomain.NETWORKING:
            findings = self._analyze_networking(target)
        elif domain == SecurityDomain.WEB_SECURITY:
            findings = self._analyze_web_security(target)
        elif domain == SecurityDomain.VULNERABILITY_ASSESSMENT:
            findings = self._analyze_vulnerabilities(target)
        # ... other domains would be implemented similarly
        
        return findings
    
    def _analyze_networking(self, target: str) -> List[SecurityFinding]:
        """Analyze networking security"""
        # Placeholder implementation
        return []
    
    def _analyze_web_security(self, target: str) -> List[SecurityFinding]:
        """Analyze web application security"""
        # Placeholder implementation
        return []
    
    def _analyze_vulnerabilities(self, target: str) -> List[SecurityFinding]:
        """Analyze for vulnerabilities"""
        # Placeholder implementation
        return []
    
    def _generate_summary(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Generate summary statistics for findings"""
        summary = {
            "critical": sum(1 for f in findings if f.severity == ThreatLevel.CRITICAL),
            "high": sum(1 for f in findings if f.severity == ThreatLevel.HIGH),
            "medium": sum(1 for f in findings if f.severity == ThreatLevel.MEDIUM),
            "low": sum(1 for f in findings if f.severity == ThreatLevel.LOW),
            "info": sum(1 for f in findings if f.severity == ThreatLevel.INFO),
            "total": len(findings)
        }
        return summary
    
    def _get_incident_response_steps(self, findings: List[SecurityFinding]) -> List[str]:
        """Get recommended incident response steps"""
        return [
            "1. Containment: Isolate affected systems",
            "2. Eradication: Remove malicious artifacts",
            "3. Recovery: Restore systems from clean backups",
            "4. Analysis: Determine root cause",
            "5. Prevention: Implement preventive measures"
        ]
    
    def _assess_compliance(self, findings: List[SecurityFinding]) -> str:
        """Assess compliance status based on findings"""
        critical_count = sum(1 for f in findings if f.severity == ThreatLevel.CRITICAL)
        
        if critical_count > 5:
            return "Non-Compliant"
        elif critical_count > 0:
            return "Partially Compliant"
        else:
            return "Compliant"
    
    def get_findings(self, severity: Optional[ThreatLevel] = None) -> List[SecurityFinding]:
        """Get findings, optionally filtered by severity"""
        if severity is None:
            return self.findings
        
        return [f for f in self.findings if f.severity == severity]
    
    def export_report(self, format: str = "json") -> str:
        """Export findings as a report"""
        if format == "json":
            return self._export_json()
        elif format == "html":
            return self._export_html()
        else:
            return self._export_text()
    
    def _export_json(self) -> str:
        """Export findings as JSON"""
        data = {
            "agent": self.config.agent_name,
            "timestamp": datetime.now().isoformat(),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "description": f.description,
                    "domain": f.domain.value,
                    "severity": f.severity.name,
                    "recommendation": f.recommendation
                }
                for f in self.findings
            ]
        }
        return json.dumps(data, indent=2)
    
    def _export_html(self) -> str:
        """Export findings as HTML"""
        # Placeholder implementation
        return "<html><!-- Findings report --></html>"
    
    def _export_text(self) -> str:
        """Export findings as plain text"""
        lines = [
            f"=== {self.config.agent_name} Security Report ===",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Findings: {len(self.findings)}",
            ""
        ]
        
        for finding in self.findings:
            lines.append(f"[{finding.severity.name}] {finding.title}")
            lines.append(f"Domain: {finding.domain.value}")
            lines.append(f"Recommendation: {finding.recommendation}")
            lines.append("")
        
        return "\n".join(lines)
    
    def __repr__(self) -> str:
        return (
            f"CybersecurityAgent("
            f"name={self.config.agent_name}, "
            f"findings={len(self.findings)}, "
            f"tasks={len(self.task_history)}"
            f")"
        )