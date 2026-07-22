"""Threat models for Cyberpunk security agent"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import uuid


class ThreatLevel(str, Enum):
    """Threat level classifications"""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Threat(BaseModel):
    """Threat model"""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(description="Threat name")
    description: Optional[str] = None
    level: ThreatLevel = Field(description="Threat severity level")
    source: str = Field(description="Threat source/origin")
    target: Optional[str] = Field(default=None, description="Target of the threat")
    
    # Classification
    threat_type: str = Field(description="Type of threat (malware, exploit, etc.)")
    domains: List[str] = Field(default=[], description="Related security domains")
    
    # Impact and indicators
    indicators: List[str] = Field(default=[], description="IoCs/indicators of compromise")
    affected_assets: List[str] = Field(default=[], description="Affected assets")
    
    # Timeline
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Response
    status: str = Field(default="active", description="Threat status")
    remediation: Optional[str] = None
    containment_status: Optional[str] = None
    
    # Metadata
    tags: List[str] = Field(default=[], description="Threat tags")
    references: List[str] = Field(default=[], description="Reference links")
    additional_data: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        """Pydantic configuration"""
        use_enum_values = True
    
    def get_risk_score(self) -> float:
        """Calculate risk score (0-100)
        
        Returns:
            Risk score based on threat level and impact
        """
        level_scores = {
            ThreatLevel.CRITICAL: 100,
            ThreatLevel.HIGH: 75,
            ThreatLevel.MEDIUM: 50,
            ThreatLevel.LOW: 25,
            ThreatLevel.INFO: 10,
        }
        return level_scores.get(self.level, 0)
    
    def is_active(self) -> bool:
        """Check if threat is active"""
        return self.status.lower() == "active"
    
    def add_indicator(self, indicator: str) -> None:
        """Add indicator of compromise
        
        Args:
            indicator: IoC to add
        """
        if indicator not in self.indicators:
            self.indicators.append(indicator)
    
    def add_affected_asset(self, asset: str) -> None:
        """Add affected asset
        
        Args:
            asset: Asset identifier
        """
        if asset not in self.affected_assets:
            self.affected_assets.append(asset)
    
    def mark_contained(self, containment_status: str) -> None:
        """Mark threat as contained
        
        Args:
            containment_status: Containment status
        """
        self.containment_status = containment_status
    
    def mark_remediated(self, remediation_steps: str) -> None:
        """Mark threat as remediated
        
        Args:
            remediation_steps: Remediation steps taken
        """
        self.remediation = remediation_steps
        self.status = "remediated"


class ThreatAnalysis(BaseModel):
    """Threat analysis results"""
    
    threat: Threat
    domains_analyzed: List[str] = Field(description="Domains that analyzed the threat")
    findings: Dict[str, Any] = Field(default_factory=dict, description="Domain-specific findings")
    recommendations: List[str] = Field(default=[], description="Security recommendations")
    confidence: float = Field(default=0.0, description="Confidence level (0-1)")
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        """Pydantic configuration"""
        use_enum_values = True
    
    def add_finding(self, domain: str, finding: Dict[str, Any]) -> None:
        """Add domain-specific finding
        
        Args:
            domain: Domain name
            finding: Finding data
        """
        if domain not in self.findings:
            self.findings[domain] = []
        self.findings[domain].append(finding)
    
    def add_recommendation(self, recommendation: str) -> None:
        """Add security recommendation
        
        Args:
            recommendation: Recommendation text
        """
        if recommendation not in self.recommendations:
            self.recommendations.append(recommendation)
