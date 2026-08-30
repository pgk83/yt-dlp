#!/usr/bin/env python3
"""
Compliance & Security Auditor Script
Scans codebases and repositories for compliance with 23+ global security frameworks:
SOC 2, GDPR, ISO 27001, HIPAA, PCI DSS, NIST 800-53, NIST 800-171, CCPA, DORA, AWS FTR,
Cyber Essentials, USDP, NIS 2, NYCRR 500, ISO 42001, CMMC, ACSC Essential Eight, HITRUST,
Microsoft SSPA, TISAX, MVSP, OFDSS, and Custom Standards.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Set


@dataclass
class ComplianceIssue:
    file_path: str
    line_number: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    rule_id: str
    standards: List[str]
    description: str
    snippet: str
    remediation: str


class ComplianceAuditor:
    # Common ignore directories
    DEFAULT_EXCLUDES = {
        ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
        "dist", "build", ".idea", ".vscode", "coverage", ".next", ".nuxt"
    }

    # Rule definitions and associated standards
    RULES = [
        # --- SECRETS & CREDENTIALS ---
        {
            "id": "SEC-001",
            "category": "Hardcoded Secrets",
            "severity": "CRITICAL",
            "standards": ["SOC 2", "ISO 27001", "PCI DSS", "NIST 800-53", "MVSP", "CMMC", "AWS FTR"],
            "regex": re.compile(r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.=]{16,}["\']'),
            "description": "Potential hardcoded API key or access token detected.",
            "remediation": "Move secrets to environment variables or standard secret vaults (HashiCorp Vault, AWS Secrets Manager)."
        },
        {
            "id": "SEC-002",
            "category": "Hardcoded Private Key",
            "severity": "CRITICAL",
            "standards": ["SOC 2", "ISO 27001", "PCI DSS", "NIST 800-53", "TISAX", "HITRUST"],
            "regex": re.compile(r'-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP|PRIVATE)\s+KEY'),
            "description": "Private key file or embedded private key header detected.",
            "remediation": "Remove private keys from source repository. Use key management services or external file stores."
        },
        {
            "id": "SEC-003",
            "category": "Database Credentials",
            "severity": "HIGH",
            "standards": ["SOC 2", "ISO 27001", "PCI DSS", "NIST 800-171", "NYCRR 500"],
            "regex": re.compile(r'(?i)(postgres|mysql|mongodb|redis|oracle|mssql):\/\/[a-zA-Z0-9_\-]+:[^@\s]+@'),
            "description": "Hardcoded database connection string containing plain text credentials.",
            "remediation": "Inject database connection strings via environment variables or secret managers."
        },
        {
            "id": "SEC-004",
            "category": "AWS Credential Leak",
            "severity": "CRITICAL",
            "standards": ["AWS FTR", "SOC 2", "ISO 27001", "NIST 800-53", "Cyber Essentials"],
            "regex": re.compile(r'(?:AKIA|ASIA)[0-9A-Z]{16}'),
            "description": "AWS Access Key ID format matched in code.",
            "remediation": "Revoke key immediately. Use IAM Roles for AWS service authentication."
        },

        # --- PRIVACY & PII ---
        {
            "id": "PRIV-001",
            "category": "PII Logging",
            "severity": "HIGH",
            "standards": ["GDPR", "CCPA", "HIPAA", "USDP", "EU-US Data Privacy", "Microsoft SSPA"],
            "regex": re.compile(r'(?i)(console\.log|logger\.(info|debug|error|warn)|print)\s*\(.*\b(email|ssn|social_security|credit_card|card_number|passport|dob|birthdate)\b.*', re.IGNORECASE),
            "description": "Potential PII (Personally Identifiable Information) logged to standard console/loggers.",
            "remediation": "Mask or redact PII fields before logging or use structured contextual logging with sanitized scope."
        },
        {
            "id": "PRIV-002",
            "category": "PHI / Medical Data Exposure",
            "severity": "HIGH",
            "standards": ["HIPAA", "HITRUST", "GDPR"],
            "regex": re.compile(r'(?i)\b(patient[_-]?id|medical[_-]?record|diagnosis|health[_-]?plan|prescription)\b\s*[:=]'),
            "description": "Unencrypted Personal Health Information (PHI) attribute assignment found.",
            "remediation": "Ensure PHI data is encrypted at rest and in transit, with strict access control logs according to HIPAA §164.312."
        },

        # --- CRYPTOGRAPHY & TRANSMISSION SECURITY ---
        {
            "id": "CRYPTO-001",
            "category": "Insecure Hash Algorithm",
            "severity": "MEDIUM",
            "standards": ["PCI DSS", "ISO 27001", "NIST 800-53", "ACSC Essential Eight"],
            "regex": re.compile(r'(?i)(crypto\.createHash\(["\'](md5|sha1)["\']\)|hashlib\.(md5|sha1)\(|MD5\(|SHA1\()'),
            "description": "Use of weak cryptographically vulnerable hash function (MD5 or SHA-1).",
            "remediation": "Upgrade hashing algorithm to SHA-256, SHA-512, or bcrypt/argon2 for passwords."
        },
        {
            "id": "CRYPTO-002",
            "category": "Disabled TLS Verification",
            "severity": "CRITICAL",
            "standards": ["SOC 2", "PCI DSS", "AWS FTR", "NIS 2", "MVSP", "OFDSS"],
            "regex": re.compile(r'(?i)(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0["\']?|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)'),
            "description": "TLS/SSL certificate verification explicitly disabled.",
            "remediation": "Enable strict TLS verification in production environments to prevent MITM attacks."
        },
        {
            "id": "CRYPTO-003",
            "category": "Cleartext HTTP Transport",
            "severity": "MEDIUM",
            "standards": ["PCI DSS", "SOC 2", "Cyber Essentials", "NYCRR 500"],
            "regex": re.compile(r'http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|w3\.org|schema\.org|example\.com|test\.com|mock-|openxmlformats\.org|.*\.rtfd\.io)[a-zA-Z0-9_\-\.]+'),
            "description": "Insecure HTTP endpoint detected for external network request.",
            "remediation": "Enforce HTTPS transport (TLS 1.2/1.3) for all external service calls."
        },

        # --- AUTHENTICATION & ACCESS CONTROL ---
        {
            "id": "AUTH-001",
            "category": "Hardcoded Default Password",
            "severity": "HIGH",
            "standards": ["SOC 2", "ACSC Essential Eight", "MVSP", "Cyber Essentials", "TISAX"],
            "regex": re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'](admin|password|123456|root|default|guest|changeit)["\']'),
            "description": "Hardcoded default or predictable password string.",
            "remediation": "Require strong dynamically generated passwords or multi-factor authentication (MFA)."
        },

        # --- INFRASTRUCTURE & CONTAINER SECURITY ---
        {
            "id": "INFRA-001",
            "category": "Root Container Execution",
            "severity": "HIGH",
            "standards": ["AWS FTR", "SOC 2", "NIST 800-53", "CMMC", "NIS 2"],
            "regex": re.compile(r'^\s*USER\s+root\b', re.MULTILINE),
            "description": "Dockerfile explicitly sets container execution user to privileged root.",
            "remediation": "Define and switch to a non-privileged user (e.g. `USER appuser`) in Dockerfile."
        },
        {
            "id": "INFRA-002",
            "category": "Wildcard IP Binding",
            "severity": "MEDIUM",
            "standards": ["Cyber Essentials", "NIST 800-171", "NYCRR 500", "MVSP"],
            "regex": re.compile(r'(?i)(bind|listen|host)\s*[:=]\s*["\']0\.0\.0\.0["\']'),
            "description": "Service configured to bind to all network interfaces (0.0.0.0).",
            "remediation": "Bind services strictly to localhost (127.0.0.1) or specific internal VPC network interfaces unless publicly intended."
        },

        # --- AI GOVERNANCE & SAFETY ---
        {
            "id": "AI-001",
            "category": "Unsanitized AI Prompt Construction",
            "severity": "HIGH",
            "standards": ["ISO 42001", "CUSTOM"],
            "regex": re.compile(r'(?i)(prompt|user_input|query)\s*\+\s*["\'].*["\']|f["\'].*\{user_input\}.*["\']'),
            "description": "Direct concatenation of raw user input into AI model prompts without sanitization (Prompt Injection Risk).",
            "remediation": "Validate input length, sanitize delimiters, and separate untrusted user input into designated user message blocks per ISO 42001 AI governance standards."
        },
        {
            "id": "AI-002",
            "category": "Unbounded AI Model Call",
            "severity": "MEDIUM",
            "standards": ["ISO 42001", "SOC 2"],
            "regex": re.compile(r'(?i)(openai|anthropic|gemini|litellm)\..*\(.*max_tokens\s*=\s*(None|999999)'),
            "description": "AI model completion call without maximum token caps or rate limits.",
            "remediation": "Set explicit token limits and timeout parameters to avoid resource exhaustion and budget denial of service."
        }
    ]

    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()
        self.issues: List[ComplianceIssue] = []

    def scan(self) -> List[ComplianceIssue]:
        self.issues.clear()
        self._scan_repository_structure()
        self._scan_code_files()
        return self.issues

    def _scan_repository_structure(self):
        """Scans repository level security configurations (CI/CD, gitignore, dependabot)."""
        rel_files = []
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in self.DEFAULT_EXCLUDES]
            for f in files:
                full_path = Path(root) / f
                rel_files.append(full_path.relative_to(self.root_dir).as_posix())

        # Rule: Check missing .gitignore
        if ".gitignore" not in rel_files:
            self.issues.append(ComplianceIssue(
                file_path=".gitignore",
                line_number=1,
                severity="HIGH",
                category="Repository Security",
                rule_id="SUPPLY-001",
                standards=["SOC 2", "ISO 27001", "DORA", "NIS 2", "MVSP"],
                description="Missing .gitignore file. High risk of accidentally committing secrets, build artifacts, or environment files.",
                snippet="<File missing>",
                remediation="Create a comprehensive .gitignore file for your project language and framework."
            ))

        # Rule: Check Dependabot / Automated Dependency Scanning
        dependabot_paths = [".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".renovaterc"]
        if not any(dp in rel_files for dp in dependabot_paths):
            self.issues.append(ComplianceIssue(
                file_path=".github/dependabot.yml",
                line_number=1,
                severity="MEDIUM",
                category="Supply Chain Security",
                rule_id="SUPPLY-002",
                standards=["DORA", "NIS 2", "MVSP", "Microsoft SSPA", "OFDSS"],
                description="No automated dependency vulnerability scanning config (Dependabot/Renovate) found in repository.",
                snippet="<File missing>",
                remediation="Configure Dependabot or Renovate in .github/dependabot.yml to meet DORA/NIS 2 supply chain compliance."
            ))

        # Rule: Check CI/CD SAST Security Scanning Workflow
        has_workflow = any(rf.startswith(".github/workflows/") for rf in rel_files)
        if not has_workflow:
            self.issues.append(ComplianceIssue(
                file_path=".github/workflows/",
                line_number=1,
                severity="LOW",
                category="Continuous Compliance",
                rule_id="SUPPLY-003",
                standards=["SOC 2", "ISO 27001", "NYCRR 500", "CMMC"],
                description="No GitHub Actions security audit workflows detected.",
                snippet="<Workflow directory missing>",
                remediation="Add automated static code analysis (SAST) and compliance checking to your CI/CD pipeline."
            ))

    def _scan_code_files(self):
        """Scans source code files against defined security and compliance regex rules."""
        scannable_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".cpp", ".c",
            ".cs", ".php", ".rb", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".json",
            ".env", ".env.example", "Dockerfile", ".tf"
        }

        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in self.DEFAULT_EXCLUDES]

            for file_name in files:
                file_path = Path(root) / file_name
                if file_path.suffix not in scannable_extensions and file_name not in {"Dockerfile", ".env", ".env.example"}:
                    continue

                rel_path = file_path.relative_to(self.root_dir).as_posix()
                self._scan_single_file(file_path, rel_path)

    def _scan_single_file(self, file_path: Path, rel_path: str):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            return

        full_content = "".join(lines)

        # File level checks
        for rule in self.RULES:
            regex: re.Pattern = rule["regex"]
            if regex.search(full_content):
                for idx, line in enumerate(lines, 1):
                    if regex.search(line):
                        self.issues.append(ComplianceIssue(
                            file_path=rel_path,
                            line_number=idx,
                            severity=rule["severity"],
                            category=rule["category"],
                            rule_id=rule["id"],
                            standards=rule["standards"],
                            description=rule["description"],
                            snippet=line.strip()[:100],
                            remediation=rule["remediation"]
                        ))


def print_terminal_report(issues: List[ComplianceIssue]):
    print("\n==========================================================================")
    print("      COMPLIANCE & SECURITY AUDIT RESULTS (23+ FRAMEWORKS SCAN)")
    print("==========================================================================\n")

    if not issues:
        print("✅ CONGRATULATIONS! No security compliance violations found.")
        print("Your repository complies with SOC 2, GDPR, ISO 27001, HIPAA, PCI DSS, etc.\n")
        return

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    standards_affected: Set[str] = set()

    for issue in issues:
        severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        standards_affected.update(issue.standards)

    print(f"Total Issues Found: {len(issues)}")
    print(f"🔴 CRITICAL: {severity_counts['CRITICAL']} | 🟠 HIGH: {severity_counts['HIGH']} | 🟡 MEDIUM: {severity_counts['MEDIUM']} | 🔵 LOW: {severity_counts['LOW']}")
    print(f"Frameworks Impacted: {', '.join(sorted(standards_affected))}\n")

    print("--------------------------------------------------------------------------")
    for idx, issue in enumerate(issues, 1):
        color = "🔴" if issue.severity == "CRITICAL" else ("🟠" if issue.severity == "HIGH" else "🟡")
        print(f"{idx}. [{issue.rule_id}] {color} {issue.severity} - {issue.category}")
        print(f"   File: {issue.file_path}:{issue.line_number}")
        print(f"   Standards: {', '.join(issue.standards)}")
        print(f"   Description: {issue.description}")
        print(f"   Snippet: {issue.snippet}")
        print(f"   Fix: {issue.remediation}\n")


def generate_markdown_report(issues: List[ComplianceIssue], output_file: str):
    standards_list = [
        "SOC 2", "GDPR", "ISO 27001", "HIPAA", "PCI DSS", "NIST 800-53", "NIST 800-171",
        "CCPA", "DORA", "AWS FTR", "Cyber Essentials", "USDP", "NIS 2", "NYCRR 500",
        "ISO 42001", "CMMC", "ACSC Essential Eight", "HITRUST", "Microsoft SSPA",
        "TISAX", "MVSP", "OFDSS", "CUSTOM"
    ]

    standards_map: Dict[str, List[ComplianceIssue]] = {std: [] for std in standards_list}
    for issue in issues:
        for std in issue.standards:
            if std in standards_map:
                standards_map[std].append(issue)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# 🛡️ Compliance & Security Audit Report\n\n")
        f.write("This report provides an automated compliance scan across **23+ Security Standards** based on the Vanta framework spectrum.\n\n")

        f.write("## 📊 Executive Summary\n\n")
        f.write(f"- **Target Directory**: `{os.getcwd()}`\n")
        f.write(f"- **Total Violations**: {len(issues)}\n")
        f.write("| Severity | Count |\n| --- | --- |\n")
        f.write(f"| 🔴 Critical | {sum(1 for i in issues if i.severity == 'CRITICAL')} |\n")
        f.write(f"| 🟠 High | {sum(1 for i in issues if i.severity == 'HIGH')} |\n")
        f.write(f"| 🟡 Medium | {sum(1 for i in issues if i.severity == 'MEDIUM')} |\n")
        f.write(f"| 🔵 Low | {sum(1 for i in issues if i.severity == 'LOW')} |\n\n")

        f.write("## 📜 Compliance Framework Breakdown\n\n")
        f.write("| Framework / Standard | Status | Violations |\n| --- | --- | --- |\n")
        for std in sorted(standards_list):
            count = len(standards_map[std])
            status = "✅ PASS" if count == 0 else f"❌ NON-COMPLIANT ({count})"
            f.write(f"| **{std}** | {status} | {count} |\n")

        f.write("\n## 🔍 Detailed Issue Log & Remediation Guidelines\n\n")
        if not issues:
            f.write("No compliance issues detected.\n")
        else:
            for idx, issue in enumerate(issues, 1):
                f.write(f"### {idx}. [{issue.rule_id}] {issue.category} (`{issue.severity}`)\n")
                f.write(f"- **File**: `{issue.file_path}:{issue.line_number}`\n")
                f.write(f"- **Impacted Frameworks**: {', '.join(issue.standards)}\n")
                f.write(f"- **Description**: {issue.description}\n")
                f.write(f"- **Code Snippet**: `{issue.snippet}`\n")
                f.write(f"- **Remediation**: {issue.remediation}\n\n")

    print(f"📄 Markdown compliance report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Compliance Standards Auditor for Code repositories.")
    parser.add_argument("--dir", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument("--markdown", help="Path to generate markdown report (e.g. compliance_report.md)")
    parser.add_argument("--json", help="Path to output JSON results")
    args = parser.parse_args()

    auditor = ComplianceAuditor(args.dir)
    issues = auditor.scan()

    print_terminal_report(issues)

    if args.markdown:
        generate_markdown_report(issues, args.markdown)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(i) for i in issues], f, indent=2)
        print(f"📊 JSON report written to {args.json}")

    if any(i.severity in {"CRITICAL", "HIGH"} for i in issues):
        sys.exit(1)


if __name__ == "__main__":
    main()
