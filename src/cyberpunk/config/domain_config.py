"""Domain-specific configuration management"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)


class DomainConfig(BaseModel):
    """Base configuration for security domains"""
    
    name: str = Field(description="Domain name")
    enabled: bool = Field(default=True, description="Whether domain is enabled")
    priority: int = Field(default=0, description="Domain priority for orchestration")
    timeout: int = Field(default=300, description="Domain operation timeout in seconds")
    retry_attempts: int = Field(default=3, description="Number of retry attempts")
    
    class Config:
        """Pydantic configuration"""
        extra = "allow"


# Domain-specific configurations

class NetworkSecurityConfig(DomainConfig):
    """Network Security domain configuration"""
    
    name: str = "network_security"
    firewall_rules_path: Optional[str] = None
    monitor_ips: bool = Field(default=True, description="Monitor suspicious IPs")
    ddos_detection: bool = Field(default=True, description="Enable DDoS detection")


class CryptographyConfig(DomainConfig):
    """Cryptography domain configuration"""
    
    name: str = "cryptography"
    allowed_algorithms: list = Field(default=["AES-256", "RSA-2048", "SHA-256"])
    key_rotation_days: int = Field(default=90)
    validate_certificates: bool = Field(default=True)


class ThreatIntelligenceConfig(DomainConfig):
    """Threat Intelligence domain configuration"""
    
    name: str = "threat_intelligence"
    feeds: list = Field(default=[], description="External threat feeds")
    update_interval_hours: int = Field(default=1)
    cache_results: bool = Field(default=True)


class AccessControlConfig(DomainConfig):
    """Access Control domain configuration"""
    
    name: str = "access_control"
    enforce_mfa: bool = Field(default=True)
    password_policy: Dict[str, Any] = Field(
        default_factory=lambda: {
            "min_length": 12,
            "require_uppercase": True,
            "require_numbers": True,
            "require_special": True,
        }
    )
    session_timeout_minutes: int = Field(default=30)


class ApplicationSecurityConfig(DomainConfig):
    """Application Security domain configuration"""
    
    name: str = "application_security"
    enable_sast: bool = Field(default=True)
    enable_dast: bool = Field(default=True)
    vulnerability_threshold: str = Field(default="medium")


class CloudSecurityConfig(DomainConfig):
    """Cloud Security domain configuration"""
    
    name: str = "cloud_security"
    cloud_providers: list = Field(default=["aws", "azure", "gcp"])
    check_compliance: bool = Field(default=True)
    scan_images: bool = Field(default=True)


class IncidentResponseConfig(DomainConfig):
    """Incident Response domain configuration"""
    
    name: str = "incident_response"
    team_contact: Optional[str] = None
    escalation_enabled: bool = Field(default=True)
    auto_remediate: bool = Field(default=False)


class MalwareAnalysisConfig(DomainConfig):
    """Malware Analysis domain configuration"""
    
    name: str = "malware_analysis"
    enable_static_analysis: bool = Field(default=True)
    enable_dynamic_analysis: bool = Field(default=True)
    sandbox_enabled: bool = Field(default=True)


class WebSecurityConfig(DomainConfig):
    """Web Security domain configuration"""
    
    name: str = "web_security"
    check_owasp: bool = Field(default=True)
    scan_frequency_hours: int = Field(default=24)
    check_headers: bool = Field(default=True)


class EndpointSecurityConfig(DomainConfig):
    """Endpoint Security domain configuration"""
    
    name: str = "endpoint_security"
    enable_edr: bool = Field(default=True)
    auto_quarantine: bool = Field(default=True)
    patch_priority: str = Field(default="critical")


class IdentityAccessMgmtConfig(DomainConfig):
    """Identity & Access Management domain configuration"""
    
    name: str = "identity_access_mgmt"
    sso_enabled: bool = Field(default=True)
    sso_provider: Optional[str] = None
    mfa_required: bool = Field(default=True)


class DatabaseSecurityConfig(DomainConfig):
    """Database Security domain configuration"""
    
    name: str = "database_security"
    enable_encryption: bool = Field(default=True)
    audit_queries: bool = Field(default=True)
    check_permissions: bool = Field(default=True)


class PhysicalSecurityConfig(DomainConfig):
    """Physical Security domain configuration"""
    
    name: str = "physical_security"
    monitor_access_logs: bool = Field(default=True)
    enforce_badge_system: bool = Field(default=True)


class SocialEngineeringConfig(DomainConfig):
    """Social Engineering domain configuration"""
    
    name: str = "social_engineering"
    phishing_detection: bool = Field(default=True)
    awareness_training_required: bool = Field(default=True)
    test_frequency_days: int = Field(default=30)


class ComplianceGovernanceConfig(DomainConfig):
    """Compliance & Governance domain configuration"""
    
    name: str = "compliance_governance"
    frameworks: list = Field(default=["GDPR", "HIPAA", "PCI-DSS"])
    auto_report: bool = Field(default=True)
    audit_frequency_days: int = Field(default=30)


class SecurityArchitectureConfig(DomainConfig):
    """Security Architecture domain configuration"""
    
    name: str = "security_architecture"
    enable_zero_trust: bool = Field(default=True)
    defense_in_depth: bool = Field(default=True)


class ApiSecurityConfig(DomainConfig):
    """API Security domain configuration"""
    
    name: str = "api_security"
    enable_rate_limiting: bool = Field(default=True)
    require_api_keys: bool = Field(default=True)
    log_all_requests: bool = Field(default=True)


class SecureDevopsConfig(DomainConfig):
    """Secure DevOps domain configuration"""
    
    name: str = "secure_devops"
    scan_ci_cd: bool = Field(default=True)
    scan_iac: bool = Field(default=True)
    secrets_scanning: bool = Field(default=True)


class SocOperationsConfig(DomainConfig):
    """SOC Operations domain configuration"""
    
    name: str = "soc_operations"
    enable_monitoring: bool = Field(default=True)
    alert_threshold: str = Field(default="medium")
    auto_response: bool = Field(default=False)


# Registry of all domain configurations
DOMAIN_CONFIG_REGISTRY = {
    "network_security": NetworkSecurityConfig,
    "cryptography": CryptographyConfig,
    "threat_intelligence": ThreatIntelligenceConfig,
    "access_control": AccessControlConfig,
    "application_security": ApplicationSecurityConfig,
    "cloud_security": CloudSecurityConfig,
    "incident_response": IncidentResponseConfig,
    "malware_analysis": MalwareAnalysisConfig,
    "web_security": WebSecurityConfig,
    "endpoint_security": EndpointSecurityConfig,
    "identity_access_mgmt": IdentityAccessMgmtConfig,
    "database_security": DatabaseSecurityConfig,
    "physical_security": PhysicalSecurityConfig,
    "social_engineering": SocialEngineeringConfig,
    "compliance_governance": ComplianceGovernanceConfig,
    "security_architecture": SecurityArchitectureConfig,
    "api_security": ApiSecurityConfig,
    "secure_devops": SecureDevopsConfig,
    "soc_operations": SocOperationsConfig,
}


def get_domain_config(domain_name: str, config_dict: Dict[str, Any]) -> Optional[DomainConfig]:
    """Get domain configuration instance
    
    Args:
        domain_name: Name of the domain
        config_dict: Configuration dictionary
        
    Returns:
        DomainConfig instance or None
    """
    config_class = DOMAIN_CONFIG_REGISTRY.get(domain_name)
    if config_class is None:
        logger.warning(f"Unknown domain: {domain_name}")
        return DomainConfig(name=domain_name, **config_dict)
    
    try:
        return config_class(**config_dict)
    except Exception as e:
        logger.error(f"Error creating config for domain {domain_name}: {e}")
        return DomainConfig(name=domain_name, **config_dict)
