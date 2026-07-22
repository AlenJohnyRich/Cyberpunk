"""Core configuration management for the Cyberpunk security agent"""

from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)


class OrchestratorConfig(BaseModel):
    """Configuration for the main orchestration engine"""
    
    name: str = Field(default="Cyberpunk Agent", description="Agent name")
    version: str = Field(default="1.0.0", description="Agent version")
    max_concurrent_tasks: int = Field(default=10, description="Maximum concurrent tasks")
    timeout_seconds: int = Field(default=300, description="Task timeout in seconds")
    enable_logging: bool = Field(default=True, description="Enable detailed logging")
    log_level: str = Field(default="INFO", description="Logging level")
    
    class Config:
        """Pydantic configuration"""
        extra = "allow"


class DomainRegistryConfig(BaseModel):
    """Configuration for domain registry"""
    
    auto_load: bool = Field(default=True, description="Auto-load available domains")
    enabled_domains: List[str] = Field(
        default=[
            "network_security",
            "cryptography",
            "threat_intelligence",
            "access_control",
            "application_security",
            "cloud_security",
            "incident_response",
            "malware_analysis",
            "web_security",
            "endpoint_security",
            "identity_access_mgmt",
            "database_security",
            "physical_security",
            "social_engineering",
            "compliance_governance",
            "security_architecture",
            "api_security",
            "secure_devops",
            "soc_operations",
        ],
        description="List of enabled security domains"
    )
    
    class Config:
        """Pydantic configuration"""
        extra = "allow"


class LoggingConfig(BaseModel):
    """Configuration for logging"""
    
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string"
    )
    file_path: Optional[Path] = Field(default=None, description="Log file path")
    console_output: bool = Field(default=True, description="Output logs to console")
    
    class Config:
        """Pydantic configuration"""
        extra = "allow"


class SecurityConfig(BaseModel):
    """Main security configuration for Cyberpunk"""
    
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    domain_registry: DomainRegistryConfig = Field(default_factory=DomainRegistryConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    domains: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Domain-specific configurations"
    )
    
    @classmethod
    def from_file(cls, file_path: str) -> "SecurityConfig":
        """Load configuration from YAML file
        
        Args:
            file_path: Path to YAML configuration file
            
        Returns:
            SecurityConfig instance
        """
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"Config file not found: {file_path}, using defaults")
            return cls()
        
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {file_path}")
            return cls(**data.get("security", {}))
        except Exception as e:
            logger.error(f"Error loading config from {file_path}: {e}")
            return cls()
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "SecurityConfig":
        """Create configuration from dictionary
        
        Args:
            config_dict: Configuration dictionary
            
        Returns:
            SecurityConfig instance
        """
        return cls(**config_dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary
        
        Returns:
            Dictionary representation of configuration
        """
        return self.model_dump(exclude_none=True)
    
    def to_file(self, file_path: str) -> None:
        """Save configuration to YAML file
        
        Args:
            file_path: Path to save configuration
        """
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        config_data = {"security": self.to_dict()}
        
        with open(path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False)
        
        logger.info(f"Saved configuration to {file_path}")
    
    def get_domain_config(self, domain_name: str) -> Dict[str, Any]:
        """Get configuration for specific domain
        
        Args:
            domain_name: Name of the security domain
            
        Returns:
            Domain-specific configuration dictionary
        """
        return self.domains.get(domain_name, {})
    
    def is_domain_enabled(self, domain_name: str) -> bool:
        """Check if a domain is enabled
        
        Args:
            domain_name: Name of the security domain
            
        Returns:
            True if domain is enabled, False otherwise
        """
        return domain_name in self.domain_registry.enabled_domains
    
    class Config:
        """Pydantic configuration"""
        extra = "allow"


# Default configuration instance
DEFAULT_CONFIG = SecurityConfig()
