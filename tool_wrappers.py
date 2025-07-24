"""
tool_wrappers.py
Cross-platform helpers that invoke external security tools and normalise
their output for the SecOps-CLI-Wrapper project.

Returned result schema
{
   success": bool,
    "summary": str,          # one-line human summary
    "data":    dict,         # parsed details (tool-specific)
    "error":   str | None    # stderr or raised-exception text
}
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

# -------------------------------------------------------
#  Detect host OS once at import time
# -------------------------------------------------------
_OS: str = platform.system().lower()          # 'windows' | 'linux' | 'darwin'


# -------------------------------------------------------
#  Helper for uniform failure objects
# -------------------------------------------------------
def _fail(summary: str, err: str) -> Dict[str, Any]:
    return {"success": False, "summary": summary, "data": {}, "error": err}


class ToolManager:
    """
    Wraps external binaries and exposes them through execute_tool().
    """

    # ---------------------------------------------------
    #  Build static meta-data once
    # ---------------------------------------------------
    def __init__(self) -> None:
        self.tool_info: Dict[str, Dict[str, Any]] = self._build_tool_catalogue()

    def _build_tool_catalogue(self) -> Dict[str, Dict[str, Any]]:
        """Return OS-aware metadata for each supported tool."""
        install = {
            "windows": {
                "nmap":   "Download MSI from https://nmap.org/download.html",
                "nikto":  "Install Strawberry Perl → clone Nikto from GitHub",
                "clamav": "Download ClamAV MSI from https://www.clamav.net/downloads",
            },
            "linux": {
                "nmap":   "sudo apt/yum/dnf install nmap",
                "nikto":  "sudo apt install nikto  # or git clone",
                "clamav": "sudo apt install clamav clamav-daemon",
            },
            "darwin": {
                "nmap":   "brew install nmap",
                "nikto":  "brew install nikto  # requires Xcode CLI tools",
                "clamav": "brew install clamav",
            },
        }

        exe = {
            "windows": {
                "nmap":   ["nmap.exe"],
                "nikto":  ["nikto.pl"],           # run via Perl
                "clamav": ["clamscan.exe"],
            },
            "linux": {
                "nmap":   ["nmap"],
                "nikto":  ["nikto"],
                "clamav": ["clamscan"],
            },
            "darwin": {
                "nmap":   ["nmap"],
                "nikto":  ["nikto"],
                "clamav": ["clamscan"],
            },
        }

        return {
            name: {
                "description": desc,
                "executables": exe[_OS][name],
                "install_guide": install[_OS][name],
            }
            for name, desc in {
                "nmap": "Network discovery and port scanning",
                "nikto": "Web-server vulnerability scanner",
                "clamav": "Antivirus engine for malware detection",
            }.items()
        }

    # ---------------------------------------------------
    #  Public helpers used by main.py
    # ---------------------------------------------------
    def is_tool_available(self, tool: str) -> bool:
        """Return True if any executable for *tool* is on PATH."""
        for exe in self.tool_info.get(tool, {}).get("executables", []):
            if shutil.which(exe):
                return True
        return False

    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Return list of all tools with availability status and path."""
        out: List[Dict[str, Any]] = []
        for name, meta in self.tool_info.items():
            path = next((shutil.which(e) for e in meta["executables"] if shutil.which(e)), None)
            out.append(
                {
                    "name": name,
                    "description": meta["description"],
                    "installed": bool(path),
                    "path": path,
                    "install_guide": meta["install_guide"],
                }
            )
        return out

    def check_dependencies(self) -> List[Dict[str, Any]]:
        """Return dependency table including Python runtime."""
        deps: List[Dict[str, Any]] = []

        ver_ok = sys.version_info >= (3, 7)
        deps.append(
            {
                "name": "Python 3.7+",
                "available": ver_ok,
                "status": f"{'✓' if ver_ok else '✗'} Python {platform.python_version()}",
                "requirement": "Upgrade Python" if not ver_ok else "",
            }
        )

        for row in self.get_available_tools():
            deps.append(
                {
                    "name": row["name"],
                    "available": row["installed"],
                    "status": f"{'✓' if row['installed'] else '✗'} {row['path'] or 'Not found'}",
                    "requirement": row["install_guide"] if not row["installed"] else "",
                }
            )
        return deps

    # ---------------------------------------------------
    #  Main router called by DecisionEngine / main.py
    # ---------------------------------------------------
    def execute_tool(
        self,
        tool_name: str,
        target: str,
        options: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Dispatch to the correct internal runner."""
        options = options or {}

        if not self.is_tool_available(tool_name):
            guide = self.tool_info.get(tool_name, {}).get("install_guide", "Unknown tool")
            return _fail(
                f"{tool_name} not installed",
                f"TOOL_NOT_AVAILABLE • Install hint: {guide}",
            )

        match tool_name.lower():
            case "nmap":
                return self._run_nmap(target, options)
            case "nikto":
                return self._run_nikto(target, options)
            case "clamav":
                return self._run_clamav(target, options)
            case _:
                return _fail("Unsupported tool", "TOOL_NOT_IMPLEMENTED")

    # ---------------------------------------------------
    #  Nmap runner
    # ---------------------------------------------------
    def _run_nmap(self, target: str, opt: Dict[str, Any]) -> Dict[str, Any]:
        exe = self.tool_info["nmap"]["executables"][0]
        cmd: List[str] = [exe, "-oX", "-"]  # XML to stdout

        if opt.get("syn_scan"):
            cmd.append("-sS")
        if opt.get("service_detection"):
            cmd.append("-sV")
        if opt.get("port_range") == "web_ports":
            cmd += ["-p", "80,443,8080,8443"]
        elif opt.get("port_range") == "top_1000":
            cmd.append("--top-ports=1000")

        cmd += ["-T", opt.get("timing", "4"), target]

        try:
            cp = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=opt.get("timeout", 300),
            )
            if cp.returncode != 0:
                return _fail("Nmap error", cp.stderr or "Non-zero exit")

            open_ports = []
            for line in cp.stdout.splitlines():
                if 'state="open"' in line and "portid" in line:
                    try:
                        open_ports.append(int(line.split('portid="')[1].split('"')[0]))
                    except (ValueError, IndexError):
                        continue

            return {
                "success": True,
                "summary": f"Nmap found {len(open_ports)} open port(s)",
                "data": {"open_ports": sorted(open_ports), "xml": cp.stdout},
                "error": None,
            }
        except subprocess.TimeoutExpired:
            return _fail("Nmap timed out", "TIMEOUT")
        except Exception as exc:
            return _fail("Nmap exception", str(exc))

    # ---------------------------------------------------
    #  Nikto runner
    # ---------------------------------------------------
    def _run_nikto(self, target: str, opt: Dict[str, Any]) -> Dict[str, Any]:
        if _OS == "windows":
            perl = shutil.which("perl") or "perl"
            nikto_script = self.tool_info["nikto"]["executables"][0]
            cmd = [perl, nikto_script, "-h", target, "-o", "-", "-F", "json"]
        else:
            nikto_bin = self.tool_info["nikto"]["executables"][0]
            cmd = [nikto_bin, "-h", target, "-o", "-", "-Format", "json"]

        if opt.get("comprehensive_scan"):
            cmd.append("-C")

        try:
            cp = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=opt.get("timeout", 600),
            )
            if cp.returncode not in (0, 1):  # 1 = vulns found, still OK
                return _fail("Nikto error", cp.stderr or "Non-zero exit")

            output = cp.stdout.strip()
            try:
                parsed = json.loads(output) if output.startswith("{") else {}
                vuln_count = len(parsed.get("vulnerabilities", []))
            except Exception:
                parsed = {}
                vuln_count = 0

            return {
                "success": True,
                "summary": f"Nikto found {vuln_count} potential issue(s)",
                "data": {"vulnerabilities_found": vuln_count, "raw": output},
                "error": None,
            }
        except subprocess.TimeoutExpired:
            return _fail("Nikto timed out", "TIMEOUT")
        except Exception as exc:
            return _fail("Nikto exception", str(exc))

    # ---------------------------------------------------
    #  ClamAV runner
    # ---------------------------------------------------
    def _run_clamav(self, target: str, opt: Dict[str, Any]) -> Dict[str, Any]:
        exe = self.tool_info["clamav"]["executables"][0]
        cmd: List[str] = [
            exe,
            "--infected",
            "--recursive",
            "--no-summary",
        ]

        if opt.get("scan_archives", True):
            cmd.append("--scan-archive")

        cmd.append(target)

        try:
            cp = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=opt.get("timeout", 600),
            )
            if cp.returncode not in (0, 1):  # 0=clean, 1=infected
                return _fail("ClamAV error", cp.stderr or "Non-zero exit")

            infected = []
            for line in cp.stdout.splitlines():
                if line.endswith("FOUND"):
                    file_path, threat = line.rsplit(":", 1)
                    infected.append({"file": file_path.strip(), "threat": threat.strip(" FOUND")})

            return {
                "success": True,
                "summary": f"ClamAV flagged {len(infected)} file(s)",
                "data": {"infected_files": infected},
                "error": None,
            }
        except subprocess.TimeoutExpired:
            return _fail("ClamAV timed out", "TIMEOUT")
        except Exception as exc:
            return _fail("ClamAV exception", str(exc))
