#!/usr/bin/env python3
"""
Setup script for C2PY Framework
Handles installation across platforms while maintaining direct execution capability
"""

from setuptools import setup, find_packages
import os
import sys
from pathlib import Path

# Read version
version_file = Path(__file__).parent / "VERSION"
if version_file.exists():
    with open(version_file, 'r') as f:
        version = f.read().strip()
else:
    version = "2.0.1"

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
with open(requirements_file, 'r') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Read README
readme_file = Path(__file__).parent / "README.md"
with open(readme_file, 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="c2py-framework",
    version=version,
    description="Professional Command & Control Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="TechNinja632",
    url="https://github.com/TechNinja632/c2py",
    license="MIT",
    
    # Package configuration
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    
    # Include non-Python files
    include_package_data=True,
    package_data={
        "": ["*.png", "*.ico", "*.json", "*.txt", "*.md"],
        "resources": ["*"],
        "lolbas_templates": ["*"],
    },
    
    # Dependencies
    install_requires=requirements,
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Entry points for console scripts
    entry_points={
        "console_scripts": [
            "c2py=c2py:main",
        ],
    },
    
    # Classification
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    
    # Additional metadata
    keywords="c2 command control framework security penetration testing",
    project_urls={
        "Bug Reports": "https://github.com/TechNinja632/c2py/issues",
        "Source": "https://github.com/TechNinja632/c2py",
        "Documentation": "https://github.com/TechNinja632/c2py/wiki",
    },
)
