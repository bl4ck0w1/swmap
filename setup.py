#!/usr/bin/env python3
from setuptools import setup, find_packages
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

def get_version():
    try:
        with open('config/constants.py', 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"\'')
    except Exception:
        return "1.0.0"

setup(
    name="swmap",
    version=get_version(),
    description="Service Worker Security Analyzer - Advanced recon tool for Service Worker security assessment",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="SWMap Security",
    author_email="security@swmap.dev",
    url="https://github.com/bl4ck0w1/swmap.git",
    packages=find_packages(include=['src', 'src.*', 'config', 'config.*']),
    package_dir={'src': 'src', 'config': 'config'},
    package_data={'config': ['*.py'], 'src': ['**/*.py']},
    include_package_data=True,
    py_modules=["swmap"],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'pytest-asyncio>=0.21.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
        'full': [
            'psutil>=5.9.0; sys_platform != "win32"',
            'colorama>=0.4.6; sys_platform == "win32"',
        ],
        'headless': [
            'playwright>=1.36.0',
        ],
        'enhanced': [
            'psutil>=5.9.0; sys_platform != "win32"',
            'colorama>=0.4.6; sys_platform == "win32"',
            'playwright>=1.36.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'swmap=swmap:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
        "Topic :: Utilities",
    ],
    keywords=[
        "security",
        "service-worker",
        "pwa",
        "reconnaissance",
        "bug-bounty",
        "penetration-testing",
        "web-security",
    ],
    project_urls={
        "Documentation": "https://github.com/bl4ck0w1/swmap/wiki",
        "Source": "https://github.com/bl4ck0w1/swmap",
        "Tracker": "https://github.com/bl4ck0w1/swmap/issues",
    },
)
