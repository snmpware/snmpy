#!/usr/bin/env python3
"""
Setup script per AdvancedSnmp
"""

from setuptools import setup, find_packages
import os

# Leggi il README per la descrizione lunga
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Leggi i requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="snmpy",
    version="1.0.0",
    author="Advanced SNMP Library Team",
    description="A complete SNMP library for Python with support for v1, v2c, and v3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/advancedsnmp",  # Sostituisci con il tuo repository
    project_urls={
        "Bug Reports": "https://github.com/snmpware/snmpy/issues",
        "Source": "https://github.com/snmpware/snmpy",
        "Documentation": "https://github.com/snmpware/snmpy#readme",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: System :: Hardware :: Hardware Drivers",
    ],
    keywords="snmp, snmpv1, snmpv2c, snmpv3, network, monitoring, ups, network-management, asn1, ber",
    python_requires=">=3.7",
    py_modules=["snmpy"],  # Il nostro modulo principale
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.10.0",
            "black>=21.0.0",
            "flake8>=3.8.0",
            "mypy>=0.800",
        ],
        "docs": [
            "sphinx>=4.0.0",
            "sphinx-rtd-theme>=0.5.0",
        ],
        "examples": [
            "matplotlib>=3.3.0",
            "numpy>=1.20.0",
            "pandas>=1.2.0",
            "requests>=2.25.0",
            "psutil>=5.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "advancedsnmp=snmpy:main",
            "snmp-monitor=snmpy:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["README.md", "LICENSE", "requirements.txt"],
    },
    zip_safe=False,
    test_suite="examples.test_basic",
)
