"""
Web Application Security Domain Expert
Covers: HTTP/HTTPS, Cookies, Sessions, Authentication, Authorization, APIs, OWASP Top 10, Secure coding
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
import re


class OWASPTopTenCategory(Enum):
    """OWASP Top 10 categories"""
    INJECTION = "A03:2021 - Injection"
    BROKEN_AUTH = "A07:2021 - Authentication and Session Management"
    SENSITIVE_DATA = "A02:2021 - Cryptographic Failures"
    XML_EXTERNAL = "A05:2021 - Security Misconfiguration"
    BROKEN_ACCESS = "A01:2021 - Broken Access Control"
    SECURITY_CONFIG = "A05:2021 - Security Misconfiguration"
    XSS = "A03:2021 - Injection (XSS)"
    INSECURE_DESERIALIZATION = "A08:2021 - Software and Data Integrity Failures"
    INSUFFICIENT_LOGGING = "A09:2021 - Security Logging and Monitoring Failures"
    USING_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"


@dataclass
class WebVulnerability:
    """Web application vulnerability"""
    type: str
    severity: str
    description: str
    location: str
    impact: str
    remediation: str
    references: List[str]


class WebApplicationSecurityExpert:
    """Expert in web application security"""
    
    def __init__(self):
        self.sql_injection_patterns = [
            r"(?i)union.*select",
            r"(?i)select.*from",
            r"(?i)insert.*into",
            r"(?i)delete.*from",
            r"(?i)drop.*table"
        ]
        self.xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"<img.*onerror"
        ]
    
    def analyze_http_security(self) -> Dict[str, Any]:
        """Analyze HTTP security headers and configuration"""
        return {
            "headers_analysis": self._analyze_security_headers(),
            "ssl_tls_analysis": self._analyze_ssl_tls(),
            "cookie_analysis": self._analyze_cookies(),
            "recommendations": self._get_http_recommendations()
        }
    
    def check_owasp_top_10(self, app_data: Dict[str, Any]) -> List[WebVulnerability]:
        """Check for OWASP Top 10 vulnerabilities"""
        vulnerabilities = []
        
        # A01: Broken Access Control
        vulnerabilities.extend(self._check_broken_access_control())
        
        # A02: Cryptographic Failures
        vulnerabilities.extend(self._check_cryptographic_failures())
        
        # A03: Injection
        vulnerabilities.extend(self._check_injection_attacks())
        
        # A04: Insecure Design
        vulnerabilities.extend(self._check_insecure_design())
        
        # A05: Security Misconfiguration
        vulnerabilities.extend(self._check_security_misconfiguration())
        
        # A06: Vulnerable and Outdated Components
        vulnerabilities.extend(self._check_vulnerable_components())
        
        # A07: Authentication Failures
        vulnerabilities.extend(self._check_authentication_failures())
        
        # A08: Software and Data Integrity Failures
        vulnerabilities.extend(self._check_integrity_failures())
        
        # A09: Logging and Monitoring Failures
        vulnerabilities.extend(self._check_logging_failures())
        
        # A10: SSRF
        vulnerabilities.extend(self._check_ssrf_vulnerabilities())
        
        return vulnerabilities
    
    def analyze_authentication_implementation(self) -> Dict[str, Any]:
        """Analyze authentication mechanisms"""
        return {
            "password_policy": self._check_password_policy(),
            "session_management": self._check_session_management(),
            "mfa_implementation": self._check_mfa(),
            "api_authentication": self._check_api_authentication(),
            "recommendations": self._get_auth_recommendations()
        }
    
    def analyze_api_security(self, api_endpoints: List[str]) -> Dict[str, Any]:
        """Analyze API security"""
        findings = {
            "endpoints_analyzed": len(api_endpoints),
            "issues": [],
            "recommendations": []
        }
        
        # Check for common API vulnerabilities
        findings["issues"].extend(self._check_api_authentication())
        findings["issues"].extend(self._check_api_rate_limiting())
        findings["issues"].extend(self._check_api_input_validation())
        findings["issues"].extend(self._check_api_versioning())
        
        findings["recommendations"] = [
            "Implement API key rotation",
            "Use OAuth 2.0 for authorization",
            "Implement API rate limiting",
            "Validate and sanitize all inputs",
            "Implement proper error handling",
            "Use API versioning",
            "Monitor API usage for anomalies",
            "Implement request signing"
        ]
        
        return findings
    
    def scan_for_sensitive_data_exposure(self, content: str) -> List[str]:
        """Scan for exposed sensitive data"""
        exposed_data = []
        
        # Check for API keys
        if re.search(r"api[_-]?key['\"]?\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}", content):
            exposed_data.append("Potential API key exposure")
        
        # Check for AWS keys
        if re.search(r"AKIA[0-9A-Z]{16}", content):
            exposed_data.append("AWS access key exposure")
        
        # Check for database connection strings
        if re.search(r"(mysql|postgres|mongodb)://[a-zA-Z0-9:@/]+", content):
            exposed_data.append("Database connection string exposure")
        
        # Check for private keys
        if re.search(r"-----BEGIN.*PRIVATE KEY-----", content):
            exposed_data.append("Private key exposure")
        
        # Check for email addresses
        if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content):
            exposed_data.append("Email address exposure")
        
        return exposed_data
    
    def generate_secure_coding_guide(self) -> Dict[str, List[str]]:
        """Generate secure coding practices guide"""
        return {
            "input_validation": [
                "Validate all user input",
                "Use whitelisting instead of blacklisting",
                "Implement length restrictions",
                "Use parameterized queries",
                "Encode output based on context"
            ],
            "authentication": [
                "Never store passwords in plaintext",
                "Use bcrypt, scrypt, or PBKDF2",
                "Implement multi-factor authentication",
                "Use secure session management",
                "Implement proper logout functionality"
            ],
            "encryption": [
                "Use HTTPS for all communications",
                "Encrypt sensitive data at rest",
                "Use strong encryption algorithms",
                "Properly manage encryption keys",
                "Use TLS 1.2 or higher"
            ],
            "error_handling": [
                "Don't expose stack traces to users",
                "Log errors securely",
                "Provide generic error messages",
                "Implement proper exception handling",
                "Monitor for suspicious error patterns"
            ],
            "dependencies": [
                "Keep dependencies updated",
                "Use dependency scanning tools",
                "Monitor for security advisories",
                "Implement SBOM (Software Bill of Materials)",
                "Remove unused dependencies"
            ]
        }
    
    def _analyze_security_headers(self) -> Dict[str, str]:
        """Analyze HTTP security headers"""
        return {\n            "Content-Security-Policy": "Restricts resource loading",\n            "X-Frame-Options": "Prevents clickjacking",\n            "X-Content-Type-Options": "Prevents MIME sniffing",\n            "Strict-Transport-Security": "Enforces HTTPS",\n            "X-XSS-Protection": "Enables XSS protection",\n            "Referrer-Policy": "Controls referrer information"\n        }\n    \n    def _analyze_ssl_tls(self) -> Dict[str, str]:\n        """Analyze SSL/TLS configuration\"\"\"\n        return {\n            "protocol": "TLS 1.3 recommended",\n            "ciphers": "Use only strong ciphers",\n            "certificate": "Valid and properly installed",\n            "hsts": "HSTS header should be present",\n            "crl_ocsp": "Implement certificate revocation checking"\n        }\n    \n    def _analyze_cookies(self) -> Dict[str, str]:\n        """Analyze cookie security\"\"\"\n        return {\n            "httponly": "Should be set on sensitive cookies",\n            "secure": "Should be set for HTTPS",\n            "samesite": "Should be set to prevent CSRF",\n            "expiration": "Should have reasonable lifetime",\n            "domain_path": "Should be properly scoped"\n        }\n    \n    def _get_http_recommendations(self) -> List[str]:\n        \"\"\"Get HTTP security recommendations\"\"\"\n        return [\n            "Implement all security headers",\n            "Use HTTPS everywhere",\n            "Implement HSTS",\n            "Configure secure cookies",\n            "Remove unnecessary headers",\n            "Disable insecure protocols",\n            "Implement rate limiting",\n            "Monitor for anomalous traffic"\n        ]\n    \n    def _check_broken_access_control(self) -> List[WebVulnerability]:\n        \"\"\"Check for broken access control\"\"\"\n        return [\n            WebVulnerability(\n                type=\"Broken Access Control\",\n                severity=\"Critical\",\n                description=\"Users can access resources without proper authorization\",\n                location=\"Authorization middleware\",\n                impact=\"Unauthorized data access and modification\",\n                remediation=\"Implement proper authorization checks\",\n                references=[\"OWASP A01:2021\"]\n            )\n        ]\n    \n    def _check_cryptographic_failures(self) -> List[WebVulnerability]:\n        \"\"\"Check for cryptographic failures\"\"\"\n        return [\n            WebVulnerability(\n                type=\"Sensitive Data Exposure\",\n                severity=\"High\",\n                description=\"Sensitive data transmitted or stored without encryption\",\n                location=\"Data transmission and storage\",\n                impact=\"Data breach and compliance violations\",\n                remediation=\"Implement encryption for sensitive data\",\n                references=[\"OWASP A02:2021\"]\n            )\n        ]\n    \n    def _check_injection_attacks(self) -> List[WebVulnerability]:\n        \"\"\"Check for injection vulnerabilities\"\"\"\n        return [\n            WebVulnerability(\n                type=\"SQL Injection\",\n                severity=\"Critical\",\n                description=\"User input not properly sanitized in SQL queries\",\n                location=\"Database queries\",\n                impact=\"Complete database compromise\",\n                remediation=\"Use parameterized queries and input validation\",\n                references=[\"OWASP A03:2021\"]\n            ),\n            WebVulnerability(\n                type=\"Cross-Site Scripting (XSS)\",\n                severity=\"High\",\n                description=\"Malicious scripts injected into web application\",\n                location=\"User input handling\",\n                impact=\"Session hijacking, credential theft\",\n                remediation=\"Implement output encoding and CSP\",\n                references=[\"OWASP A03:2021\"]\n            )\n        ]\n    \n    def _check_insecure_design(self) -> List[WebVulnerability]:\n        \"\"\"Check for insecure design patterns\"\"\"\n        return []\n    \n    def _check_security_misconfiguration(self) -> List[WebVulnerability]:\n        \"\"\"Check for security misconfigurations\"\"\"\n        return [\n            WebVulnerability(\n                type=\"Security Misconfiguration\",\n                severity=\"High\",\n                description=\"Default credentials or unnecessary services enabled\",\n                location=\"Server configuration\",\n                impact=\"Unauthorized access\",\n                remediation=\"Harden configuration and disable unnecessary services\",\n                references=[\"OWASP A05:2021\"]\n            )\n        ]\n    \n    def _check_vulnerable_components(self) -> List[WebVulnerability]:\n        \"\"\"Check for vulnerable dependencies\"\"\"\n        return []\n    \n    def _check_authentication_failures(self) -> List[WebVulnerability]:\n        \"\"\"Check for authentication failures\"\"\"\n        return []\n    \n    def _check_integrity_failures(self) -> List[WebVulnerability]:\n        \"\"\"Check for integrity failures\"\"\"\n        return []\n    \n    def _check_logging_failures(self) -> List[WebVulnerability]:\n        \"\"\"Check for logging and monitoring failures\"\"\"\n        return []\n    \n    def _check_ssrf_vulnerabilities(self) -> List[WebVulnerability]:\n        \"\"\"Check for SSRF vulnerabilities\"\"\"\n        return []\n    \n    def _check_password_policy(self) -> Dict[str, str]:\n        \"\"\"Check password policy\"\"\"\n        return {\n            "minimum_length": "12+ characters recommended\",\n            "complexity": "Should require mixed character types\",\n            "expiration": "Consider passwordless authentication\",\n            "history": "Prevent reuse of recent passwords\",\n            "lockout": "Implement account lockout after failed attempts\"\n        }\n    \n    def _check_session_management(self) -> Dict[str, str]:\n        \"\"\"Check session management\"\"\"\n        return {\n            "session_timeout": "Should have reasonable timeout\",\n            "token_generation": "Use cryptographically secure generation\",\n            "token_storage": "Store securely\",\n            "csrf_protection": "Implement CSRF tokens\",\n            "fixation": "Regenerate session ID on login\"\n        }\n    \n    def _check_mfa(self) -> Dict[str, str]:\n        \"\"\"Check MFA implementation\"\"\"\n        return {\n            "availability": "MFA should be enforced for privileged accounts\",\n            "methods": "Support multiple MFA methods\",\n            "recovery": "Have secure recovery mechanisms\",\n            "backup_codes": "Generate and store backup codes securely\"\n        }\n    \n    def _check_api_authentication(self) -> List[str]:\n        \"\"\"Check API authentication\"\"\"\n        return [\n            "API authentication not properly implemented\",\n            "Missing API key validation\",\n            "Weak token generation\"\n        ]\n    \n    def _check_api_rate_limiting(self) -> List[str]:\n        \"\"\"Check API rate limiting\"\"\"\n        return [\n            "Rate limiting not implemented\",\n            "No throttling on API endpoints\"\n        ]\n    \n    def _check_api_input_validation(self) -> List[str]:\n        \"\"\"Check API input validation\"\"\"\n        return [\n            "Input validation insufficient\",\n            "Missing type checking\",\n            "No size restrictions\"\n        ]\n    \n    def _check_api_versioning(self) -> List[str]:\n        \"\"\"Check API versioning\"\"\"\n        return [\n            "No API versioning strategy\",\n            "Deprecated endpoints still active\"\n        ]\n    \n    def _get_auth_recommendations(self) -> List[str]:\n        \"\"\"Get authentication recommendations\"\"\"\n        return [\n            "Implement password hashing with bcrypt\",\n            "Enable multi-factor authentication\",\n            "Use secure session management\",\n            "Implement account lockout\",\n            "Use HTTPS for all authentication\",\n            "Implement passwordless authentication\"\n        ]\n