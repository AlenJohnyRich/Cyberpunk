"""Task models for Cyberpunk security agent"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import uuid


class TaskType(str, Enum):
    """Types of security tasks"""
    
    THREAT_ANALYSIS = "threat_analysis"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    PENETRATION_TEST = "penetration_test"
    COMPLIANCE_CHECK = "compliance_check"
    INCIDENT_INVESTIGATION = "incident_investigation"
    SECURITY_AUDIT = "security_audit"
    MALWARE_ANALYSIS = "malware_analysis"
    CONFIGURATION_REVIEW = "configuration_review"
    PATCH_ASSESSMENT = "patch_assessment"
    RISK_ASSESSMENT = "risk_assessment"


class TaskStatus(str, Enum):
    """Status of security tasks"""
    
    PENDING = "pending"
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Task(BaseModel):
    """Security task model"""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(description="Task name")
    description: Optional[str] = Field(default=None)
    task_type: TaskType = Field(description="Type of security task")
    status: TaskStatus = Field(default=TaskStatus.PENDING)
    domains: List[str] = Field(default=[], description="Domains involved")
    priority: int = Field(default=0, description="Task priority (0-10)")
    target: Optional[str] = Field(default=None, description="Target of security task")
    
    # Execution details
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_duration_seconds: Optional[int] = None
    
    # Results
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    # Metadata
    tags: List[str] = Field(default=[], description="Task tags")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    
    class Config:
        """Pydantic configuration"""
        use_enum_values = True
    
    def mark_started(self) -> None:
        """Mark task as started"""
        self.status = TaskStatus.IN_PROGRESS
        self.started_at = datetime.utcnow()
    
    def mark_completed(self, result: Optional[Dict[str, Any]] = None) -> None:
        """Mark task as completed
        
        Args:
            result: Task result data
        """
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if result:
            self.result = result
    
    def mark_failed(self, error: str) -> None:
        """Mark task as failed
        
        Args:
            error: Error message
        """
        self.status = TaskStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error = error
    
    def mark_cancelled(self) -> None:
        """Mark task as cancelled"""
        self.status = TaskStatus.CANCELLED
        self.completed_at = datetime.utcnow()
    
    def get_duration(self) -> Optional[float]:
        """Get task execution duration in seconds
        
        Returns:
            Duration in seconds or None if not completed
        """
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def is_completed(self) -> bool:
        """Check if task is completed"""
        return self.status in [
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED
        ]
    
    def is_running(self) -> bool:
        """Check if task is running"""
        return self.status in [TaskStatus.IN_PROGRESS, TaskStatus.QUEUED]
    
    @classmethod
    def create_threat_analysis_task(
        cls,
        name: str,
        threat_type: str,
        target: str,
        domains: Optional[List[str]] = None,
        **kwargs
    ) -> "Task":
        """Create a threat analysis task
        
        Args:
            name: Task name
            threat_type: Type of threat
            target: Target of threat analysis
            domains: List of domains to involve
            **kwargs: Additional task parameters
            
        Returns:
            Task instance
        """
        if domains is None:
            domains = [
                "threat_intelligence",
                "malware_analysis",
                "incident_response"
            ]
        
        return cls(
            name=name,
            task_type=TaskType.THREAT_ANALYSIS,
            target=target,
            domains=domains,
            context={"threat_type": threat_type},
            **kwargs
        )
    
    @classmethod
    def create_vulnerability_assessment_task(
        cls,
        name: str,
        asset: str,
        domains: Optional[List[str]] = None,
        **kwargs
    ) -> "Task":
        """Create a vulnerability assessment task
        
        Args:
            name: Task name
            asset: Asset to assess
            domains: List of domains to involve
            **kwargs: Additional task parameters
            
        Returns:
            Task instance
        """
        if domains is None:
            domains = [
                "application_security",
                "web_security",
                "cloud_security"
            ]
        
        return cls(
            name=name,
            task_type=TaskType.VULNERABILITY_ASSESSMENT,
            target=asset,
            domains=domains,
            **kwargs
        )
