"""
Payload Quality Control System
Implements comprehensive quality control for custom payloads, reverse shells, and scripts
"""

import re
import hashlib
import json
import ast
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

@dataclass
class QualityMetric:
    """Quality metric definition"""
    name: str
    weight: float
    min_score: float
    max_score: float
    description: str

@dataclass
class QualityResult:
    """Quality assessment result"""
    overall_score: float
    grade: str
    metrics: Dict[str, float]
    issues: List[str]
    recommendations: List[str]
    evasion_rating: str
    stability_rating: str
    stealth_rating: str

class PayloadQualityController:
    """Advanced payload quality control system"""
    
    def __init__(self):
        self.quality_metrics = self._initialize_metrics()
        self.detection_patterns = self._load_detection_patterns()
        self.obfuscation_patterns = self._load_obfuscation_patterns()
        self.stability_checks = self._load_stability_checks()
        
    def _initialize_metrics(self) -> Dict[str, QualityMetric]:
        """Initialize quality assessment metrics"""
        return {
            "evasion": QualityMetric(
                name="Evasion Capability",
                weight=0.3,
                min_score=0.0,
                max_score=100.0,
                description="Ability to evade detection systems"
            ),
            "obfuscation": QualityMetric(
                name="Obfuscation Level",
                weight=0.25,
                min_score=0.0,
                max_score=100.0,
                description="Code obfuscation and encoding quality"
            ),
            "stability": QualityMetric(
                name="Code Stability",
                weight=0.2,
                min_score=0.0,
                max_score=100.0,
                description="Code reliability and error handling"
            ),
            "stealth": QualityMetric(
                name="Stealth Operations",
                weight=0.15,
                min_score=0.0,
                max_score=100.0,
                description="Covert operation capabilities"
            ),
            "functionality": QualityMetric(
                name="Functionality",
                weight=0.1,
                min_score=0.0,
                max_score=100.0,
                description="Feature completeness and effectiveness"
            )
        }
    
    def _load_detection_patterns(self) -> Dict[str, Any]:
        """Load known detection patterns"""
        return {
            "high_risk": [
                {"pattern": r"powershell.*-enc.*command", "penalty": 30, "description": "PowerShell encoded command"},
                {"pattern": r"iex.*downloadstring", "penalty": 25, "description": "PowerShell download and execute"},
                {"pattern": r"invoke-expression", "penalty": 20, "description": "Direct code execution"},
                {"pattern": r"system\.net\.webclient", "penalty": 15, "description": "Web client usage"},
                {"pattern": r"start-process.*hidden", "penalty": 20, "description": "Hidden process execution"},
                {"pattern": r"new-object.*com", "penalty": 15, "description": "COM object creation"}
            ],
            "medium_risk": [
                {"pattern": r"cmd\.exe.*\/c", "penalty": 10, "description": "Command prompt execution"},
                {"pattern": r"wmic.*process.*create", "penalty": 15, "description": "WMIC process creation"},
                {"pattern": r"rundll32.*javascript", "penalty": 18, "description": "Rundll32 JavaScript execution"},
                {"pattern": r"regsvr32.*\/i", "penalty": 12, "description": "Regsvr32 usage"},
                {"pattern": r"mshta.*javascript", "penalty": 20, "description": "MSHTA JavaScript execution"}
            ],
            "low_risk": [
                {"pattern": r"echo.*\>", "penalty": 5, "description": "File writing operations"},
                {"pattern": r"ping.*localhost", "penalty": 3, "description": "Network connectivity test"},
                {"pattern": r"tasklist", "penalty": 2, "description": "Process enumeration"},
                {"pattern": r"whoami", "penalty": 2, "description": "User identification"}
            ]
        }
    
    def _load_obfuscation_patterns(self) -> Dict[str, Any]:
        """Load obfuscation pattern bonuses"""
        return {
            "encoding": [
                {"pattern": r"[A-Za-z0-9+/]{40,}={0,2}", "bonus": 15, "description": "Base64 encoding detected"},
                {"pattern": r"0x[0-9A-Fa-f]{8,}", "bonus": 10, "description": "Hexadecimal encoding"},
                {"pattern": r"\\u[0-9A-Fa-f]{4}", "bonus": 8, "description": "Unicode encoding"}
            ],
            "string_manipulation": [
                {"pattern": r"[\'\"][^\'\"]*\+[^\'\"]*[\'\"]", "bonus": 5, "description": "String concatenation"},
                {"pattern": r"split\([\'\"]\w+[\'\"]\)", "bonus": 8, "description": "String splitting"},
                {"pattern": r"replace\([\'\"]\w+[\'\"]\)", "bonus": 6, "description": "String replacement"}
            ],
            "advanced_techniques": [
                {"pattern": r"gzip|compress|deflate", "bonus": 12, "description": "Compression usage"},
                {"pattern": r"aes|des|rc4", "bonus": 20, "description": "Encryption implementation"},
                {"pattern": r"xor|bitwise", "bonus": 10, "description": "Bitwise operations"}
            ]
        }
    
    def _load_stability_checks(self) -> List[Dict[str, Any]]:
        """Load stability check patterns"""
        return [
            {"check": "error_handling", "pattern": r"try\s*{|catch\s*\(|except\s*:", "bonus": 10, "description": "Error handling present"},
            {"check": "null_checks", "pattern": r"if\s*\(.*null\)|if.*is.*none", "bonus": 5, "description": "Null checking"},
            {"check": "timeout_handling", "pattern": r"timeout|sleep|delay", "bonus": 8, "description": "Timeout management"},
            {"check": "cleanup", "pattern": r"finally\s*:|cleanup|dispose", "bonus": 12, "description": "Resource cleanup"},
            {"check": "logging", "pattern": r"log|debug|trace", "bonus": 6, "description": "Logging implementation"}
        ]
    
    def analyze_payload(self, payload: str, payload_type: str = "powershell") -> QualityResult:
        """Comprehensive payload quality analysis"""
        
        # Initialize scoring
        scores = {}
        issues = []
        recommendations = []
        
        # Analyze each metric
        scores["evasion"] = self._analyze_evasion(payload, issues, recommendations)
        scores["obfuscation"] = self._analyze_obfuscation(payload, issues, recommendations)
        scores["stability"] = self._analyze_stability(payload, issues, recommendations)
        scores["stealth"] = self._analyze_stealth(payload, issues, recommendations)
        scores["functionality"] = self._analyze_functionality(payload, payload_type, issues, recommendations)
        
        # Calculate weighted overall score
        overall_score = sum(
            scores[metric] * self.quality_metrics[metric].weight 
            for metric in scores
        )
        
        # Generate ratings
        evasion_rating = self._get_rating(scores["evasion"])
        stability_rating = self._get_rating(scores["stability"])
        stealth_rating = self._get_rating(scores["stealth"])
        
        # Assign grade
        grade = self._calculate_grade(overall_score)
        
        return QualityResult(
            overall_score=round(overall_score, 2),
            grade=grade,
            metrics=scores,
            issues=issues,
            recommendations=recommendations,
            evasion_rating=evasion_rating,
            stability_rating=stability_rating,
            stealth_rating=stealth_rating
        )
    
    def _analyze_evasion(self, payload: str, issues: List[str], recommendations: List[str]) -> float:
        """Analyze evasion capabilities"""
        score = 100.0
        payload_lower = payload.lower()
        
        # Check for detection patterns
        for risk_level, patterns in self.detection_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], payload_lower, re.IGNORECASE):
                    score -= pattern_info["penalty"]
                    issues.append(f"Detection risk: {pattern_info['description']}")
        
        # Check for AMSI bypass
        amsi_patterns = ["amsi", "antimalware", "amsiutils"]
        if any(pattern in payload_lower for pattern in amsi_patterns):
            score += 15
        else:
            recommendations.append("Consider implementing AMSI bypass techniques")
        
        # Check for execution policy bypass
        if "executionpolicy" in payload_lower and "bypass" in payload_lower:
            score += 10
        else:
            recommendations.append("Consider adding execution policy bypass")
        
        return max(0.0, min(100.0, score))
    
    def _analyze_obfuscation(self, payload: str, issues: List[str], recommendations: List[str]) -> float:
        """Analyze obfuscation level"""
        score = 0.0
        
        # Check for obfuscation patterns
        for category, patterns in self.obfuscation_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], payload, re.IGNORECASE):
                    score += pattern_info["bonus"]
        
        # Penalty for plaintext commands
        plaintext_patterns = ["echo", "dir", "type", "copy", "move"]
        plaintext_count = sum(1 for pattern in plaintext_patterns if pattern in payload.lower())
        score -= plaintext_count * 5
        
        if score < 30:
            recommendations.append("Apply additional obfuscation techniques")
            recommendations.append("Consider string encoding methods")
        
        return max(0.0, min(100.0, score))
    
    def _analyze_stability(self, payload: str, issues: List[str], recommendations: List[str]) -> float:
        """Analyze code stability"""
        score = 50.0  # Base score
        
        # Check for stability patterns
        for check_info in self.stability_checks:
            if re.search(check_info["pattern"], payload, re.IGNORECASE):
                score += check_info["bonus"]
        
        # Check for common stability issues
        stability_issues = [
            {"pattern": r"while\s*\(\s*true\s*\)", "penalty": 20, "issue": "Infinite loop detected"},
            {"pattern": r"recursion|recursive", "penalty": 15, "issue": "Potential recursion issue"},
            {"pattern": r"malloc|alloc.*without.*free", "penalty": 10, "issue": "Memory management concern"}
        ]
        
        for issue_info in stability_issues:
            if re.search(issue_info["pattern"], payload, re.IGNORECASE):
                score -= issue_info["penalty"]
                issues.append(issue_info["issue"])
        
        if score < 60:
            recommendations.append("Add error handling mechanisms")
            recommendations.append("Implement timeout controls")
        
        return max(0.0, min(100.0, score))
    
    def _analyze_stealth(self, payload: str, issues: List[str], recommendations: List[str]) -> float:
        """Analyze stealth capabilities"""
        score = 50.0  # Base score
        payload_lower = payload.lower()
        
        # Stealth bonuses
        stealth_bonuses = [
            {"pattern": "hidden", "bonus": 15, "description": "Hidden execution"},
            {"pattern": "windowstyle.*hidden", "bonus": 20, "description": "Hidden window style"},
            {"pattern": "createnowindow", "bonus": 18, "description": "No window creation"},
            {"pattern": "silent", "bonus": 10, "description": "Silent operation"},
            {"pattern": "background", "bonus": 12, "description": "Background execution"}
        ]
        
        for bonus_info in stealth_bonuses:
            if re.search(bonus_info["pattern"], payload_lower):
                score += bonus_info["bonus"]
        
        # Stealth penalties
        stealth_penalties = [
            {"pattern": "echo", "penalty": 5, "description": "Visible output"},
            {"pattern": "write-host", "penalty": 8, "description": "Console output"},
            {"pattern": "messagebox", "penalty": 15, "description": "GUI elements"},
            {"pattern": "popup", "penalty": 12, "description": "Popup windows"}
        ]
        
        for penalty_info in stealth_penalties:
            if re.search(penalty_info["pattern"], payload_lower):
                score -= penalty_info["penalty"]
                issues.append(f"Stealth concern: {penalty_info['description']}")
        
        if score < 70:
            recommendations.append("Implement stealth execution methods")
            recommendations.append("Suppress output and notifications")
        
        return max(0.0, min(100.0, score))
    
    def _analyze_functionality(self, payload: str, payload_type: str, issues: List[str], recommendations: List[str]) -> float:
        """Analyze functionality completeness"""
        score = 70.0  # Base score
        
        # Functionality checks based on payload type
        if payload_type == "reverse_shell":
            required_functions = ["connect", "socket", "send", "receive"]
            implemented = sum(1 for func in required_functions if func in payload.lower())
            score += (implemented / len(required_functions)) * 30
            
        elif payload_type == "persistence":
            required_functions = ["schedule", "registry", "startup", "service"]
            implemented = sum(1 for func in required_functions if func in payload.lower())
            score += (implemented / len(required_functions)) * 30
            
        elif payload_type == "lateral_movement":
            required_functions = ["credential", "remote", "wmi", "psexec"]
            implemented = sum(1 for func in required_functions if func in payload.lower())
            score += (implemented / len(required_functions)) * 30
        
        # Check for common functionality patterns
        if "function" in payload.lower() or "def " in payload.lower():
            score += 10  # Modular code bonus
        
        if len(payload) < 50:
            score -= 20
            issues.append("Payload appears too simple")
        
        return max(0.0, min(100.0, score))
    
    def _get_rating(self, score: float) -> str:
        """Convert score to rating"""
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 70:
            return "Average"
        elif score >= 60:
            return "Below Average"
        else:
            return "Poor"
    
    def _calculate_grade(self, score: float) -> str:
        """Calculate letter grade"""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "A-"
        elif score >= 80:
            return "B+"
        elif score >= 75:
            return "B"
        elif score >= 70:
            return "B-"
        elif score >= 65:
            return "C+"
        elif score >= 60:
            return "C"
        elif score >= 55:
            return "C-"
        else:
            return "F"
    
    def generate_improvement_plan(self, result: QualityResult) -> Dict[str, Any]:
        """Generate detailed improvement plan"""
        plan = {
            "current_grade": result.grade,
            "target_grade": "A",
            "priority_improvements": [],
            "quick_wins": [],
            "advanced_techniques": [],
            "estimated_effort": "medium"
        }
        
        # Identify priority improvements
        if result.metrics["evasion"] < 70:
            plan["priority_improvements"].append({
                "area": "Evasion",
                "current_score": result.metrics["evasion"],
                "target_score": 85,
                "actions": [
                    "Implement AMSI bypass techniques",
                    "Add execution policy bypass",
                    "Use LOLBAS techniques instead of direct PowerShell"
                ]
            })
        
        if result.metrics["obfuscation"] < 60:
            plan["priority_improvements"].append({
                "area": "Obfuscation",
                "current_score": result.metrics["obfuscation"],
                "target_score": 80,
                "actions": [
                    "Apply base64 encoding",
                    "Use string manipulation techniques",
                    "Implement variable name obfuscation"
                ]
            })
        
        # Quick wins
        if result.metrics["stealth"] < 80:
            plan["quick_wins"].extend([
                "Add -WindowStyle Hidden parameter",
                "Suppress console output",
                "Use background execution methods"
            ])
        
        # Advanced techniques
        if result.overall_score > 70:
            plan["advanced_techniques"].extend([
                "Implement polymorphic code generation",
                "Add environment-specific evasion",
                "Use process hollowing techniques",
                "Implement beacon randomization"
            ])
        
        return plan
    
    def validate_syntax(self, payload: str, language: str = "powershell") -> Dict[str, Any]:
        """Validate payload syntax"""
        result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "suggestions": []
        }
        
        try:
            if language.lower() == "python":
                # Validate Python syntax
                ast.parse(payload)
            elif language.lower() == "powershell":
                # Basic PowerShell syntax validation
                self._validate_powershell_syntax(payload, result)
            
        except SyntaxError as e:
            result["valid"] = False
            result["errors"].append(f"Syntax error: {str(e)}")
        except Exception as e:
            result["warnings"].append(f"Validation warning: {str(e)}")
        
        return result
    
    def _validate_powershell_syntax(self, payload: str, result: Dict[str, Any]):
        """Basic PowerShell syntax validation"""
        # Check for balanced brackets
        brackets = {"(": ")", "[": "]", "{": "}"}
        stack = []
        
        for char in payload:
            if char in brackets.keys():
                stack.append(char)
            elif char in brackets.values():
                if not stack:
                    result["errors"].append("Unmatched closing bracket")
                    result["valid"] = False
                    return
                last_open = stack.pop()
                if brackets[last_open] != char:
                    result["errors"].append("Mismatched brackets")
                    result["valid"] = False
                    return
        
        if stack:
            result["errors"].append("Unclosed brackets")
            result["valid"] = False

# Global quality controller instance
quality_controller = PayloadQualityController()
