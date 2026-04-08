#!/usr/bin/env python3
"""
SENTINEL Dependency Checker
Validates all package versions across the entire project for conflicts and compatibility.
"""

import os
import json
import re
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional

# Known compatibility issues (package, python_version, issue)
COMPATIBILITY_ISSUES = {
    ("apache-flink", "3.12"): "Does not support Python 3.12 (max 3.11)",
    ("stable-baselines3", "3.12", "<=2.1.0"): "No Python 3.12 support in versions <=2.1.0",
    ("gymnasium", "3.12", "<=0.29.1"): "No Python 3.12 support in versions <=0.29.1",
    ("torch", "3.12", "<2.2.0"): "No Python 3.12 support in versions <2.2.0",
}

# Known good package versions (package, min_version, max_version, python_versions)
RECOMMENDED_VERSIONS = {
    "torch": ("2.2.0", None, ["3.8", "3.9", "3.10", "3.11", "3.12"]),
    "stable-baselines3": ("2.2.0", None, ["3.8", "3.9", "3.10", "3.11", "3.12"]),
    "gymnasium": ("1.0.0", None, ["3.8", "3.9", "3.10", "3.11", "3.12"]),
    "apache-flink": ("1.19.0", "1.20.9", ["3.8", "3.9", "3.10", "3.11"]),
}

@dataclass
class PackageSpec:
    """Represents a package version specification"""
    name: str
    version: Optional[str] = None
    operator: str = "=="  # ==, >=, <=, >, <, ~=
    source: str = ""  # filename where this was found

    def __str__(self):
        if self.version:
            return f"{self.name}{self.operator}{self.version}"
        return self.name

class DependencyChecker:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.python_packages: Dict[str, List[PackageSpec]] = defaultdict(list)
        self.npm_packages: Dict[str, str] = {}
        self.issues: List[str] = []
        self.warnings: List[str] = []

    def parse_requirement(self, line: str, source: str) -> Optional[PackageSpec]:
        """Parse a single requirement line"""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # Match: package_name[extras]operator version
        match = re.match(r'^([a-zA-Z0-9\-_.]+)(?:\[.*?\])?\s*([><=~!]+)\s*(.+)$', line)
        if match:
            name, operator, version = match.groups()
            return PackageSpec(name=name.lower(), version=version.strip(),
                             operator=operator, source=source)

        # Match: just package name
        match = re.match(r'^([a-zA-Z0-9\-_.]+)$', line)
        if match:
            return PackageSpec(name=match.group(1).lower(), source=source)

        return None

    def scan_requirements_files(self):
        """Scan all requirements.txt files"""
        print("📦 Scanning Python requirements...")

        # Backend services
        backend_dir = self.project_root / "backend"
        for service_dir in backend_dir.iterdir():
            if service_dir.is_dir() and not service_dir.name.startswith("_"):
                req_file = service_dir / "requirements.txt"
                if req_file.exists():
                    self._parse_requirements_file(
                        req_file,
                        f"backend/{service_dir.name}/requirements.txt"
                    )

        # Stream processing
        flink_req = self.project_root / "stream-processing" / "flink-jobs" / "requirements.txt"
        if flink_req.exists():
            self._parse_requirements_file(flink_req, "stream-processing/flink-jobs/requirements.txt")

        # Training
        training_req = self.project_root / "training" / "requirements.txt"
        if training_req.exists():
            self._parse_requirements_file(training_req, "training/requirements.txt")

        # Agent
        agent_req = self.project_root / "agent" / "requirements.txt"
        if agent_req.exists():
            self._parse_requirements_file(agent_req, "agent/requirements.txt")

        # SDK
        sdk_req = self.project_root / "sdk" / "requirements.txt"
        if sdk_req.exists():
            self._parse_requirements_file(sdk_req, "sdk/requirements.txt")

    def _parse_requirements_file(self, path: Path, source: str):
        """Parse a single requirements file"""
        try:
            with open(path, 'r') as f:
                for line in f:
                    spec = self.parse_requirement(line, source)
                    if spec:
                        self.python_packages[spec.name].append(spec)
                        print(f"  ✓ {spec.name} from {source}")
        except Exception as e:
            self.issues.append(f"Error reading {source}: {e}")

    def scan_package_json(self):
        """Scan package.json for npm dependencies"""
        print("\n📦 Scanning Node.js dependencies...")

        pkg_json = self.project_root / "frontend" / "admin-console" / "package.json"
        if pkg_json.exists():
            try:
                with open(pkg_json, 'r') as f:
                    data = json.load(f)

                for dep in {**data.get('dependencies', {}),
                           **data.get('devDependencies', {})}:
                    version = data['dependencies'].get(dep) or data['devDependencies'].get(dep)
                    self.npm_packages[dep] = version
                    print(f"  ✓ {dep}@{version}")
            except Exception as e:
                self.issues.append(f"Error reading package.json: {e}")

    def check_duplicate_versions(self):
        """Check for packages with different versions across services"""
        print("\n🔍 Checking for version conflicts across services...")

        for package_name, specs in self.python_packages.items():
            if len(specs) > 1:
                versions = set()
                sources = {}

                for spec in specs:
                    ver_key = f"{spec.operator}{spec.version or '*'}"
                    versions.add(ver_key)
                    if ver_key not in sources:
                        sources[ver_key] = []
                    sources[ver_key].append(spec.source)

                if len(versions) > 1:
                    msg = f"⚠️  {package_name}: Version mismatch across services:\n"
                    for ver_key, srcs in sources.items():
                        msg += f"     {ver_key}: {', '.join(srcs)}\n"
                    self.warnings.append(msg.strip())
                    print(msg)

    def check_python_compatibility(self):
        """Check Python version compatibility for critical packages"""
        print("\n🐍 Checking Python version compatibility...")

        critical_packages = {
            "torch", "stable-baselines3", "gymnasium",
            "apache-flink", "apache-beam"
        }

        for package_name, specs in self.python_packages.items():
            if package_name in critical_packages:
                for spec in specs:
                    version_str = f"{spec.operator}{spec.version}" if spec.version else "any"

                    # Check against known issues
                    for py_version in ["3.12", "3.11", "3.10"]:
                        issue_key = (package_name, py_version)
                        if issue_key in COMPATIBILITY_ISSUES:
                            issue = COMPATIBILITY_ISSUES[issue_key]
                            msg = f"❌ {spec.source}: {package_name}{version_str} may have issues with Python {py_version}: {issue}"
                            self.warnings.append(msg)
                            print(msg)

                    # Check against recommended
                    if package_name in RECOMMENDED_VERSIONS:
                        rec_min, rec_max, rec_py = RECOMMENDED_VERSIONS[package_name]
                        msg = f"ℹ️  {spec.source}: {package_name}{version_str}"
                        msg += f" (recommended {rec_min}" + (f"-{rec_max}" if rec_max else "") + ")"
                        print(msg)

    def check_deprecated_packages(self):
        """Check for known deprecated packages"""
        print("\n📛 Checking for deprecated packages...")

        deprecated = {
            "kafka-python": "Replaced by kafka-python-ng",
            "lime": "Superseded by other explainability tools",
        }

        for package_name in deprecated:
            if package_name in self.python_packages:
                msg = f"⚠️  Deprecated: {package_name} ({deprecated[package_name]})"
                self.warnings.append(msg)
                print(msg)

    def check_missing_critical_deps(self):
        """Check that all services have required packages"""
        print("\n✅ Checking for required packages...")

        required = {
            "flask": ["backend"],
            "redis": ["backend"],
            "requests": ["backend", "stream-processing"],
            "prometheus-client": ["backend"],
        }

        for package, expected_in in required.items():
            found_in = []
            for spec in self.python_packages.get(package, []):
                for area in expected_in:
                    if area in spec.source:
                        found_in.append(spec.source)

            if found_in:
                print(f"  ✓ {package}: {len(set(found_in))} services")
            else:
                msg = f"⚠️  {package}: Not found in expected areas {expected_in}"
                self.warnings.append(msg)
                print(msg)

    def generate_report(self):
        """Generate a comprehensive report"""
        print("\n" + "="*70)
        print("SENTINEL DEPENDENCY CHECK REPORT")
        print("="*70)

        print(f"\n📊 Summary:")
        print(f"  Python packages: {len(self.python_packages)}")
        print(f"  NPM packages: {len(self.npm_packages)}")
        print(f"  Services scanned: {len(set(pkg.source.split('/')[0] for pkg in [s for specs in self.python_packages.values() for s in specs]))}")

        if self.issues:
            print(f"\n❌ ERRORS ({len(self.issues)}):")
            for issue in self.issues:
                print(f"  • {issue}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  • {warning}")

        if not self.issues and not self.warnings:
            print("\n✅ No dependency conflicts detected!")

        return len(self.issues) == 0 and len(self.warnings) == 0

def main():
    """Main entry point"""
    project_root = Path(__file__).parent

    checker = DependencyChecker(str(project_root))
    checker.scan_requirements_files()
    checker.scan_package_json()
    checker.check_duplicate_versions()
    checker.check_python_compatibility()
    checker.check_deprecated_packages()
    checker.check_missing_critical_deps()

    success = checker.generate_report()

    print("\n" + "="*70)
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
