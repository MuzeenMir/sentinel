"""SENTINEL Firewall Adapters - installable package for policy-orchestrator and other consumers."""
from setuptools import setup

setup(
    name="sentinel-firewall-adapters",
    version="1.0.0",
    description="Multi-platform firewall adapters for SENTINEL",
    packages=["firewall_adapters"],
    package_dir={"firewall_adapters": "."},
    python_requires=">=3.10",
    install_requires=[],
)
