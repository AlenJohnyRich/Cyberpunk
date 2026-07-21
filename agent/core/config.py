"""
Configuration management for the AI Cybersecurity Agent
Handles settings, authorization checks, and operational parameters
"""

import os
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import yaml
import json


@dataclass
class AuthorizationConfig:
    """Configuration for authorization and ethical operation"""
    
    require_authorization: bool = True
    authorization_file: Optional[str] = None
    client_name: Optional[str] = None
    scope: Optional[str] = None
    authorized_targets: list = field(default_factory=list)
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    max_severity: str = "critical"
    
    def is_authorized(self) -> bool:
        """Check if authorization is valid"""
        if not self.require_authorization:
            return True
        
        if not self.authorization_file or not self.client_name:
            return False
        
        # Check date validity
        if self.start_date and datetime.fromisoformat(self.start_date) > datetime.now():
            return False
        
        if self.end_date and datetime.fromisoformat(self.end_date) < datetime.now():
            return False
        
        return True


@dataclass
class AgentConfig:
    """Main configuration for the cybersecurity agent"""
    
    # Operational settings
    agent_name: str = "CyberpunkAgent"
    debug_mode: bool = False
    verbose: bool = True
    log_file: str = "cyberpunk_agent.log"
    
    # Authorization
    authorization: AuthorizationConfig = field(default_factory=AuthorizationConfig)
    
    # Ethical constraints
    enable_exploitation: bool = False
    enable_destructive_tests: bool = False
    enable_malware_analysis: bool = True
    enable_reverse_engineering: bool = True
    
    # Tool configuration
    tools_enabled: Dict[str, bool] = field(default_factory=lambda: {
        "network_scanner": True,
        "vuln_scanner": True,
        "packet_analyzer": True,
        "web_tester": True,
        "password_auditor": False,  # Disabled by default
        "forensics": True,
        "malware_analysis": True
    })
    
    # Domain expertise settings
    domains_enabled: Dict[str, bool] = field(default_factory=lambda: {
        "networking": True,
        "operating_systems": True,
        "programming": True,
        "web_security": True,
        "mobile_security": True,
        "wireless_security": True,
        "cloud_security": True,
        "active_directory": True,
        "cryptography": True,
        "vulnerability_assessment": True,
        "penetration_testing": True,
        "digital_forensics": True,
        "incident_response": True,
        "malware_analysis": True,
        "reverse_engineering": True,
        "soc_operations": True,
        "frameworks": True,
        "security_tools": True,
        "social_engineering": True
    })
    
    # Output settings
    report_format: str = "json"  # json, html, pdf
    report_dir: str = "./reports"
    include_recommendations: bool = True
    include_references: bool = True
    
    @classmethod
    def from_file(cls, config_file: str) -> "AgentConfig":
        """Load configuration from YAML file"""
        if not os.path.exists(config_file):
            return cls()
        
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f) or {}
        
        return cls(**config_data)
    
    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Load configuration from environment variables"""
        config = cls()
        
        # Override from environment
        if os.getenv("CYBERPUNK_DEBUG"):
            config.debug_mode = os.getenv("CYBERPUNK_DEBUG").lower() == "true"
        
        if os.getenv("CYBERPUNK_VERBOSE"):
            config.verbose = os.getenv("CYBERPUNK_VERBOSE").lower() == "true"
        
        if os.getenv("CYBERPUNK_AUTH_FILE"):
            config.authorization.authorization_file = os.getenv("CYBERPUNK_AUTH_FILE")
        
        if os.getenv("CYBERPUNK_ENABLE_EXPLOIT"):
            config.enable_exploitation = os.getenv("CYBERPUNK_ENABLE_EXPLOIT").lower() == "true"
        
        return config
    
    def save_to_file(self, config_file: str) -> None:
        """Save configuration to YAML file"""
        config_dict = {
            "agent_name": self.agent_name,
            "debug_mode": self.debug_mode,
            "verbose": self.verbose,
            "log_file": self.log_file,
            "enable_exploitation": self.enable_exploitation,
            "enable_destructive_tests": self.enable_destructive_tests,
            "tools_enabled": self.tools_enabled,
            "domains_enabled": self.domains_enabled,
            "report_format": self.report_format,
            "report_dir": self.report_dir
        }
        
        os.makedirs(os.path.dirname(config_file) or ".", exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False)
    
    def validate(self) -> tuple[bool, list[str]]:
        """Validate configuration and return (is_valid, errors)"""
        errors = []
        
        if self.authorization.require_authorization:
            if not self.authorization.is_authorized():
                errors.append("Authorization is required but not valid")
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir, exist_ok=True)
        
        if self.enable_exploitation and not self.authorization.is_authorized():
            errors.append("Exploitation mode requires valid authorization")
        
        return len(errors) == 0, errors


# Default configuration instance
DEFAULT_CONFIG = AgentConfig()