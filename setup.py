"""
Setup configuration for KAVACH-AIDR.
Enables: pip install -e .  (editable install for development)
"""

from setuptools import setup, find_packages

setup(
    name             = "kavach-aidr",
    version          = "1.0.0",
    description      = "Sovereign Autonomous Intelligent Defensive Reasoner — Indian Armed Forces",
    packages         = find_packages(),
    python_requires  = ">=3.11",
    install_requires = [
        "rich>=13.7.0",
        "click>=8.1.7",
        "bandit>=1.7.8",
        "semgrep>=1.50.0",
        "z3-solver>=4.12.4.0",
        "fastapi>=0.111.0",
        "uvicorn>=0.30.0",
        "pydantic>=2.7.0",
        "python-dotenv>=1.0.1",
        "PyYAML>=6.0.1",
        "psutil>=5.9.0",
    ],
    extras_require = {
        "llm": ["llama-cpp-python>=0.2.56"],
        "dev": ["pytest>=8.2.0", "pytest-cov>=5.0.0"],
    },
    entry_points = {
        "console_scripts": [
            "kavach = kavach.main:cli",
        ],
    },
    classifiers = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
    ],
)
