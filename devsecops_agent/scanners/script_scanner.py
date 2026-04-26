from __future__ import annotations

import re
from pathlib import Path

from devsecops_agent.models import Finding
from devsecops_agent.utils import read_text_file

POWERSHELL_SUFFIXES = {".ps1", ".psm1"}
SHELL_SUFFIXES = {".sh", ".bash", ".zsh"}
SCRIPT_BACKEND_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}
SQL_SUFFIXES = {".sql"}

POWERSHELL_SECRET_PATTERN = re.compile(
    r"\$(password|passwd|secret|token)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
POWERSHELL_ENCODED_COMMAND_PATTERN = re.compile(
    r"\b(powershell|pwsh)(\.exe)?\b.*-encodedcommand\b",
    re.IGNORECASE,
)
POWERSHELL_START_PROCESS_VARIABLE_PATTERN = re.compile(
    r"\bstart-process\b.*\$\w+",
    re.IGNORECASE,
)
POWERSHELL_PLAINTEXT_SECURESTRING_PATTERN = re.compile(
    r"\bconvertto-securestring\b.*-asplaintext\b",
    re.IGNORECASE,
)

SHELL_REMOTE_EXEC_PATTERN = re.compile(
    r"\b(curl|wget)\b.*\|\s*(bash|sh)\b",
    re.IGNORECASE,
)
SHELL_SECRET_PATTERN = re.compile(
    r"(export\s+)?(password|token|secret)\s*=\s*['\"]?[^'\"\s]+['\"]?",
    re.IGNORECASE,
)

NODE_COMMAND_EXECUTION_PATTERNS = (
    re.compile(r"\bchild_process\.exec\s*\(", re.IGNORECASE),
    re.compile(r"\bexecSync\s*\(", re.IGNORECASE),
    re.compile(r"\bspawn\s*\(.*shell\s*:\s*true", re.IGNORECASE),
)
NODE_SECRET_PATTERN = re.compile(
    r"\b(password|token|secret|apikey)\b\s*[:=]\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
NODE_TLS_DISABLED_PATTERN = re.compile(
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]",
    re.IGNORECASE,
)

SQL_DELETE_WITHOUT_WHERE_PATTERN = re.compile(r"^\s*delete\s+from\b(?!.*\bwhere\b)", re.IGNORECASE)
SQL_UPDATE_WITHOUT_WHERE_PATTERN = re.compile(r"^\s*update\b(?!.*\bwhere\b)", re.IGNORECASE)
SQL_DROP_TABLE_PATTERN = re.compile(r"^\s*drop\s+table\b", re.IGNORECASE)
SQL_GRANT_ALL_PATTERN = re.compile(r"^\s*grant\s+all\b", re.IGNORECASE)
SQL_XP_CMDSHELL_PATTERN = re.compile(r"\bxp_cmdshell\b", re.IGNORECASE)
SQL_DYNAMIC_EXEC_PATTERN = re.compile(r"\bexec(ute)?\s*\(\s*@\w+", re.IGNORECASE)


def run(files: list[Path], base_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in files:
        suffix = file_path.suffix.lower()
        if suffix not in POWERSHELL_SUFFIXES | SHELL_SUFFIXES | SCRIPT_BACKEND_SUFFIXES | SQL_SUFFIXES:
            continue

        content = read_text_file(file_path)
        if not content:
            continue

        relative_path = _relative_path(file_path, base_path)
        lines = content.splitlines()
        if suffix in POWERSHELL_SUFFIXES:
            findings.extend(_scan_powershell(lines, relative_path))
        elif suffix in SHELL_SUFFIXES:
            findings.extend(_scan_shell(lines, relative_path))
        elif suffix in SCRIPT_BACKEND_SUFFIXES:
            findings.extend(_scan_script_backend(lines, relative_path))
        elif suffix in SQL_SUFFIXES:
            findings.extend(_scan_sql(lines, relative_path))

    return findings


def _scan_powershell(lines: list[str], file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _contains_token(line, "invoke-expression") or re.search(r"(?<!\w)iex(?!\w)", line, re.IGNORECASE):
            findings.append(
                _finding(
                    severity="high",
                    title="Risky PowerShell command execution detected",
                    description="The PowerShell script uses dynamic command execution, which can run untrusted input.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Avoid dynamic command execution and allowlist any external command inputs.",
                )
            )
        if POWERSHELL_START_PROCESS_VARIABLE_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="Risky PowerShell command execution detected",
                    description="Start-Process appears to be launching a command with variable-controlled input.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Validate and allowlist process arguments before invoking external commands.",
                )
            )
        if POWERSHELL_ENCODED_COMMAND_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="PowerShell encoded command usage detected",
                    description="Encoded PowerShell commands can hide script behavior and bypass basic review checks.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Avoid encoded command execution unless it is strictly required and documented.",
                )
            )
        if POWERSHELL_PLAINTEXT_SECURESTRING_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="medium",
                    title="PowerShell plaintext secure string usage detected",
                    description="The script appears to build a secure string from plaintext content.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Load secrets from a secure store instead of embedding plaintext values in scripts.",
                )
            )
        if POWERSHELL_SECRET_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="medium",
                    title="Possible hardcoded secret in PowerShell script",
                    description="The PowerShell script appears to assign a secret-like value directly in code.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Move secrets to AWS Secrets Manager, HashiCorp Vault, or an approved secret store.",
                )
            )
    return findings


def _scan_shell(lines: list[str], file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if re.search(r"(?<!\w)eval(?!\w)", line):
            findings.append(
                _finding(
                    severity="high",
                    title="Risky shell eval usage detected",
                    description="The shell script uses eval, which can execute user-controlled input.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Avoid eval and pass validated arguments to explicit commands instead.",
                )
            )
        if SHELL_REMOTE_EXEC_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="Remote script execution pattern detected",
                    description="The script pipes downloaded content directly into a shell interpreter.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Download remote scripts for review first and avoid piping untrusted content to shell.",
                )
            )
        if "chmod 777" in line.lower():
            findings.append(
                _finding(
                    severity="medium",
                    title="Overly permissive chmod usage detected",
                    description="The script grants world-writable and executable permissions.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Use the minimum permissions required and avoid chmod 777.",
                )
            )
        if re.search(r"(^|\s)sudo(\s|$)", line):
            findings.append(
                _finding(
                    severity="medium",
                    title="Elevated shell command usage detected",
                    description="The script invokes sudo, which can widen blast radius if the script is misused.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Limit privileged operations and isolate them behind reviewed administrative steps.",
                )
            )
        if SHELL_SECRET_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="medium",
                    title="Possible hardcoded secret in shell script",
                    description="The shell script appears to set a secret-like value directly in code.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Move secrets to AWS Secrets Manager, HashiCorp Vault, or an approved secret store.",
                )
            )
    return findings


def _scan_script_backend(lines: list[str], file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if any(pattern.search(line) for pattern in NODE_COMMAND_EXECUTION_PATTERNS):
            findings.append(
                _finding(
                    severity="high",
                    title="Risky Node.js command execution detected",
                    description="The script invokes OS commands dynamically, which can lead to command injection.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Avoid dynamic command execution and validate or allowlist all command inputs.",
                )
            )
        if re.search(r"\beval\s*\(", line) or re.search(r"\bnew\s+Function\s*\(", line):
            findings.append(
                _finding(
                    severity="high",
                    title="Risky JavaScript eval usage detected",
                    description="The script uses dynamic code evaluation, which can execute untrusted input.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Avoid eval-style APIs and use explicit, validated logic paths instead.",
                )
            )
        if NODE_TLS_DISABLED_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="TLS certificate verification disabled",
                    description="The script disables Node.js TLS certificate verification.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Keep TLS verification enabled and trust only approved certificates.",
                )
            )
        if NODE_SECRET_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="medium",
                    title="Possible hardcoded secret in JavaScript/TypeScript",
                    description="The script appears to assign a secret-like value directly in code.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Move secrets to AWS Secrets Manager, HashiCorp Vault, or an approved secret store.",
                )
            )
    return findings


def _scan_sql(lines: list[str], file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if SQL_DROP_TABLE_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="Potentially destructive SQL statement detected",
                    description="The SQL file includes a DROP TABLE statement.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Review destructive SQL carefully and protect it behind explicit approval workflows.",
                )
            )
        if SQL_DELETE_WITHOUT_WHERE_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="SQL update/delete without WHERE detected",
                    description="The SQL file contains a DELETE statement without a WHERE clause.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Use precise predicates and validate destructive SQL before execution.",
                )
            )
        if SQL_UPDATE_WITHOUT_WHERE_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="SQL update/delete without WHERE detected",
                    description="The SQL file contains an UPDATE statement without a WHERE clause.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Use precise predicates and validate destructive SQL before execution.",
                )
            )
        if SQL_GRANT_ALL_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="medium",
                    title="Potentially destructive SQL statement detected",
                    description="The SQL file grants broad database privileges.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Grant only the minimum database privileges required for the target role.",
                )
            )
        if SQL_XP_CMDSHELL_PATTERN.search(line) or SQL_DYNAMIC_EXEC_PATTERN.search(line):
            findings.append(
                _finding(
                    severity="high",
                    title="Dangerous SQL command execution feature detected",
                    description="The SQL file includes dynamic or OS-level command execution behavior.",
                    file_path=file_path,
                    line_number=line_number,
                    recommendation="Avoid dynamic command execution and use parameterized APIs for query construction.",
                )
            )
    return findings


def _finding(
    *,
    severity: str,
    title: str,
    description: str,
    file_path: str,
    line_number: int,
    recommendation: str,
) -> Finding:
    return Finding(
        finding_id="",
        scanner_name="script_scanner",
        category="script",
        severity=severity,
        title=title,
        description=description,
        file_path=file_path,
        line_number=line_number,
        recommendation=recommendation,
    )


def _contains_token(line: str, token: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(token)}(?!\w)", line, re.IGNORECASE) is not None


def _relative_path(file_path: Path, base_path: Path) -> str:
    if base_path.is_dir():
        return str(file_path.relative_to(base_path))
    return file_path.name
