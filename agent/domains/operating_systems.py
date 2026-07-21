"""
Operating Systems Security Domain Expert
Covers: Linux, Windows, macOS, File systems, Permissions, Command-line, Process management
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class OSType(Enum):
    """Operating system types"""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNIX = "unix"


@dataclass
class PermissionIssue:
    """OS permission security issue"""
    path: str
    current_permissions: str
    issue: str
    risk_level: str
    recommendation: str


class OperatingSystemsExpert:
    """Expert in operating systems security"""
    
    def __init__(self):
        self.critical_permissions = {
            "/etc/passwd": "644",
            "/etc/shadow": "000",
            "/etc/sudoers": "440",
            "/root/.ssh": "700",
            "/etc/ssh/sshd_config": "600"
        }
    
    def analyze_linux_security(self, hostname: str) -> Dict[str, Any]:
        """Analyze Linux system security"""
        findings = {
            "hostname": hostname,
            "os": "Linux",
            "issues": [],
            "recommendations": []
        }
        
        # Check common Linux security issues
        findings["issues"].extend(self._check_linux_user_permissions())
        findings["issues"].extend(self._check_linux_file_permissions())
        findings["issues"].extend(self._check_linux_services())
        findings["issues"].extend(self._check_linux_firewall())
        findings["issues"].extend(self._check_linux_ssh_config())
        
        findings["recommendations"] = self._generate_linux_recommendations(findings["issues"])
        
        return findings
    
    def analyze_windows_security(self, hostname: str) -> Dict[str, Any]:
        """Analyze Windows system security"""
        findings = {
            "hostname": hostname,
            "os": "Windows",
            "issues": [],
            "recommendations": []
        }
        
        # Check common Windows security issues
        findings["issues"].extend(self._check_windows_updates())
        findings["issues"].extend(self._check_windows_firewall())
        findings["issues"].extend(self._check_windows_user_permissions())
        findings["issues"].extend(self._check_windows_services())
        findings["issues"].extend(self._check_windows_antivirus())
        
        findings["recommendations"] = self._generate_windows_recommendations(findings["issues"])
        
        return findings
    
    def analyze_file_permissions(self, filepath: str, permissions: str) -> PermissionIssue:
        """Analyze file permissions for security issues"""
        expected_perm = self.critical_permissions.get(filepath)
        
        if expected_perm and permissions != expected_perm:
            return PermissionIssue(
                path=filepath,
                current_permissions=permissions,
                issue=f"Incorrect permissions: expected {expected_perm}, found {permissions}",
                risk_level="High",
                recommendation=f"Change permissions to {expected_perm}"
            )
        
        return None
    
    def check_privilege_escalation_vectors(self) -> List[str]:
        """Identify common privilege escalation vectors"""
        return [
            "SUID binaries with excessive permissions",
            "Kernel vulnerabilities (kernel exploits)",
            "Sudo misconfigurations",
            "World-writable files/directories",
            "Weak file permissions on sensitive files",
            "Unpatched software",
            "Service misconfigurations",
            "Cron job vulnerabilities",
            "Shared library hijacking",
            "Environment variable manipulation"
        ]
    
    def analyze_running_processes(self) -> Dict[str, Any]:
        """Analyze running processes for security issues"""
        return {
            "high_risk_processes": [
                {"name": "netcat", "risk": "Critical", "reason": "Potential backdoor"},
                {"name": "nc", "risk": "Critical", "reason": "Potential backdoor"},
                {"name": "wget", "risk": "Medium", "reason": "Potential malware download"},
                {"name": "curl", "risk": "Medium", "reason": "Potential data exfiltration"}
            ],
            "recommendations": [
                "Terminate suspicious processes",
                "Investigate parent process and launch arguments",
                "Check process network connections",
                "Review process file descriptors",
                "Collect process memory dump if needed"
            ]
        }
    
    def generate_hardening_guide(self, os_type: OSType) -> Dict[str, Any]:
        """Generate OS hardening guide"""
        if os_type == OSType.LINUX:
            return self._linux_hardening_guide()
        elif os_type == OSType.WINDOWS:
            return self._windows_hardening_guide()
        elif os_type == OSType.MACOS:
            return self._macos_hardening_guide()
    
    def _check_linux_user_permissions(self) -> List[str]:
        """Check Linux user permissions"""
        return [
            "Verify no users have UID 0 except root",
            "Check for empty password fields",
            "Verify no user has * or ! in password field"
        ]
    
    def _check_linux_file_permissions(self) -> List[str]:
        """Check Linux file permissions"""
        return [
            "Check /etc/passwd permissions (should be 644)",
            "Check /etc/shadow permissions (should be 000)",
            "Verify /tmp has sticky bit set",
            "Check for world-writable files"
        ]
    
    def _check_linux_services(self) -> List[str]:
        """Check Linux services"""
        return [
            "Telnet service disabled",
            "FTP service disabled",
            "HTTP (unencrypted) minimized",
            "Unnecessary services disabled"
        ]
    
    def _check_linux_firewall(self) -> List[str]:
        """Check Linux firewall configuration"""
        return [
            "UFW or iptables properly configured",
            "Default policies set appropriately",
            "Only necessary ports open"
        ]
    
    def _check_linux_ssh_config(self) -> List[str]:
        """Check SSH configuration"""
        return [
            "SSH listening on non-standard port (optional)",
            "Root login disabled",
            "Password authentication disabled",
            "Key-based authentication required",
            "X11 forwarding disabled if not needed"
        ]
    
    def _check_windows_updates(self) -> List[str]:
        """Check Windows updates"""
        return [
            "All critical Windows updates installed",
            "Windows Update service running",
            "Automatic updates configured"
        ]
    
    def _check_windows_firewall(self) -> List[str]:
        """Check Windows firewall"""
        return [
            "Windows Firewall enabled",
            "Firewall rules properly configured",
            "Inbound rules restrictive"
        ]
    
    def _check_windows_user_permissions(self) -> List[str]:
        """Check Windows user permissions"""
        return [
            "User Account Control (UAC) enabled",
            "No unnecessary users with admin rights",
            "Strong password policy enforced"
        ]
    
    def _check_windows_services(self) -> List[str]:
        """Check Windows services"""
        return [
            "Unnecessary services disabled",
            "Services running with minimum privileges",
            "Event logging enabled"
        ]
    
    def _check_windows_antivirus(self) -> List[str]:
        """Check antivirus configuration"""
        return [
            "Antivirus software installed and updated",
            "Real-time protection enabled",
            "Regular scans scheduled"
        ]
    
    def _generate_linux_recommendations(self, issues: List[str]) -> List[str]:
        """Generate Linux security recommendations"""
        return [
            "Run regular security updates",
            "Implement SELinux or AppArmor",
            "Configure auditd for logging",
            "Use fail2ban for brute-force protection",
            "Implement aide for file integrity monitoring"
        ]
    
    def _generate_windows_recommendations(self, issues: List[str]) -> List[str]:
        """Generate Windows security recommendations"""
        return [
            "Enable Windows Defender",
            "Configure Windows Update for automatic installation",
            "Enable Security Auditing",
            "Implement BitLocker encryption",
            "Configure AppLocker for application whitelisting"
        ]
    
    def _linux_hardening_guide(self) -> Dict[str, List[str]]:
        """Linux hardening guide"""
        return {
            "user_management": [
                "Remove unnecessary user accounts",
                "Set password expiration policies",
                "Use sudo instead of root",
                "Implement strong password requirements"
            ],
            "file_system": [
                "Mount /tmp with noexec,nosuid,nodev",
                "Mount /var/tmp similarly",
                "Mount /dev/shm with noexec,nosuid,nodev",
                "Set sticky bit on world-writable directories"
            ],
            "network": [
                "Disable IPv6 if not needed",
                "Configure firewall rules",
                "Disable unnecessary network services",
                "Use SSH key-based authentication"
            ],
            "logging": [
                "Configure syslog for centralized logging",
                "Enable auditd",
                "Implement log rotation",
                "Monitor log files for suspicious activity"
            ]
        }
    
    def _windows_hardening_guide(self) -> Dict[str, List[str]]:
        """Windows hardening guide"""
        return {
            "updates": [
                "Configure automatic updates",
                "Apply all critical patches immediately",
                "Test patches in non-production first"
            ],
            "access_control": [
                "Enable UAC",
                "Implement strong password policies",
                "Use Windows Credential Manager",
                "Enable BitLocker"
            ],
            "security_features": [
                "Enable Windows Firewall",
                "Deploy Windows Defender or equivalent",
                "Enable AppLocker",
                "Enable Windows Sandbox for testing"
            ],
            "auditing": [
                "Enable audit logging",
                "Monitor event logs",
                "Implement SIEM integration",
                "Regular log review"
            ]
        }
    
    def _macos_hardening_guide(self) -> Dict[str, List[str]]:
        """macOS hardening guide"""
        return {
            "updates": [
                "Enable automatic security updates",
                "Keep macOS current",
                "Update all third-party software"
            ],
            "security": [
                "Enable FileVault encryption",
                "Enable Firewall",
                "Disable unnecessary sharing services",
                "Use strong passwords"
            ],
            "privacy": [
                "Review privacy settings",
                "Disable unnecessary location services",
                "Configure app permissions",
                "Use Safari privacy features"
            ]
        }
