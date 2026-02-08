#!/usr/bin/env python3
"""
Network Protocol Fuzzer
Comprehensive mutation-based fuzzing for network protocols.

Author: arkanzasfeziii
License: MIT
Version: 1.0.0
"""

# === Imports ===
import argparse
import logging
import random
import socket
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from pydantic import BaseModel, ValidationError
from rich.console import Console
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False


# === Constants ===
VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ⚠️  CRITICAL WARNING ⚠️                          ║
╟──────────────────────────────────────────────────────────────────────────────╢
║ This tool is for AUTHORIZED security testing ONLY.                           ║
║ Fuzzing can cause DENIAL-OF-SERVICE or system instability.                   ║
║ Unauthorized testing is ILLEGAL in most jurisdictions.                       ║
║                                                                              ║
║ Author (arkanzasfeziii) assumes NO liability for misuse or damage.           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

DEFAULT_TIMEOUT = 5
DEFAULT_MUTATIONS = 100
DEFAULT_RATE_LIMIT = 10  # requests per second
MAX_AGGRESSIVE_RATE = 50


# === Enums ===
class Protocol(str, Enum):
    """Supported protocols."""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    FTP = "ftp"
    SMTP = "smtp"
    SSH = "ssh"


class SeverityLevel(str, Enum):
    """Finding severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# === Data Models ===
@dataclass
class FuzzResult:
    """Single fuzzing test result."""
    mutation_id: int
    payload: bytes
    response_time: float
    status_code: Optional[int] = None
    error: Optional[str] = None
    crashed: bool = False
    anomaly: bool = False


@dataclass
class Finding:
    """Security finding from fuzzing."""
    title: str
    severity: SeverityLevel
    description: str
    payload: bytes
    evidence: str
    recommendation: str
    confidence: float = 0.0


@dataclass
class FuzzSession:
    """Fuzzing session results."""
    target: str
    protocol: Protocol
    total_mutations: int
    findings: List[Finding] = field(default_factory=list)
    results: List[FuzzResult] = field(default_factory=list)
    crashes: int = 0
    anomalies: int = 0


# === Utility Functions ===
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)]
    )
    return logging.getLogger("fuzzer")


# === Mutation Engine ===
class MutationEngine:
    """Generates mutated payloads for fuzzing."""
    
    def __init__(self, base_payload: bytes, intensity: int = 1):
        """
        Initialize mutation engine.
        
        Args:
            base_payload: Original payload to mutate
            intensity: Mutation intensity (1-3)
        """
        self.base_payload = base_payload
        self.intensity = intensity
    
    def generate_mutations(self, count: int) -> List[bytes]:
        """Generate mutated payloads."""
        mutations = []
        
        for i in range(count):
            if i % 5 == 0:
                payload = self._bit_flip(self.base_payload)
            elif i % 5 == 1:
                payload = self._byte_repeat(self.base_payload)
            elif i % 5 == 2:
                payload = self._boundary_values(self.base_payload)
            elif i % 5 == 3:
                payload = self._format_strings(self.base_payload)
            else:
                payload = self._overflow_payload(self.base_payload)
            
            mutations.append(payload)
        
        return mutations
    
    def _bit_flip(self, data: bytes) -> bytes:
        """Flip random bits."""
        data_list = bytearray(data)
        for _ in range(self.intensity):
            if data_list:
                pos = random.randint(0, len(data_list) - 1)
                data_list[pos] ^= (1 << random.randint(0, 7))
        return bytes(data_list)
    
    def _byte_repeat(self, data: bytes) -> bytes:
        """Repeat bytes."""
        if not data:
            return data
        pos = random.randint(0, len(data) - 1)
        repeat_count = random.randint(10, 100 * self.intensity)
        return data[:pos] + bytes([data[pos]]) * repeat_count + data[pos + 1:]
    
    def _boundary_values(self, data: bytes) -> bytes:
        """Insert boundary values."""
        boundaries = [
            b'\x00', b'\xff', b'\x00' * 100, b'\xff' * 100,
            b'-1', b'0', b'255', b'65535', b'2147483647'
        ]
        boundary = random.choice(boundaries)
        pos = random.randint(0, len(data))
        return data[:pos] + boundary + data[pos:]
    
    def _format_strings(self, data: bytes) -> bytes:
        """Insert format string payloads."""
        formats = [b'%s', b'%n', b'%x', b'%d', b'%s%s%s%s', b'%p%p%p%p']
        fmt = random.choice(formats)
        pos = random.randint(0, len(data))
        return data[:pos] + fmt + data[pos:]
    
    def _overflow_payload(self, data: bytes) -> bytes:
        """Create overflow payload."""
        overflow = b'A' * random.randint(1000, 5000 * self.intensity)
        return data + overflow


# === Protocol Handlers ===
class ProtocolHandler:
    """Base protocol handler."""
    
    def __init__(self, target: str, port: int, timeout: int):
        """Initialize handler."""
        self.target = target
        self.port = port
        self.timeout = timeout
    
    def send_fuzz(self, payload: bytes) -> FuzzResult:
        """Send fuzzed payload."""
        raise NotImplementedError


class HTTPHandler(ProtocolHandler):
    """HTTP/HTTPS protocol handler."""
    
    def __init__(self, target: str, port: int, timeout: int, use_https: bool = False):
        """Initialize HTTP handler."""
        super().__init__(target, port, timeout)
        self.use_https = use_https
        self.session = requests.Session()
    
    def send_fuzz(self, payload: bytes) -> FuzzResult:
        """Send HTTP request with fuzzed payload."""
        mutation_id = id(payload)
        start_time = time.time()
        
        try:
            scheme = "https" if self.use_https else "http"
            url = f"{scheme}://{self.target}:{self.port}/"
            
            # Try as body
            response = self.session.post(
                url,
                data=payload,
                timeout=self.timeout,
                verify=False
            )
            
            elapsed = time.time() - start_time
            
            return FuzzResult(
                mutation_id=mutation_id,
                payload=payload,
                response_time=elapsed,
                status_code=response.status_code,
                crashed=response.status_code >= 500,
                anomaly=elapsed > self.timeout * 0.8
            )
        
        except requests.exceptions.Timeout:
            return FuzzResult(
                mutation_id=mutation_id,
                payload=payload,
                response_time=self.timeout,
                error="Timeout",
                anomaly=True
            )
        except requests.exceptions.ConnectionError:
            return FuzzResult(
                mutation_id=mutation_id,
                payload=payload,
                response_time=time.time() - start_time,
                error="Connection reset",
                crashed=True
            )
        except Exception as e:
            return FuzzResult(
                mutation_id=mutation_id,
                payload=payload,
                response_time=time.time() - start_time,
                error=str(e),
                anomaly=True
            )


class TCPHandler(ProtocolHandler):
    """Generic TCP protocol handler."""
    
    def send_fuzz(self, payload: bytes) -> FuzzResult:
        """Send TCP payload."""
        mutation_id = id(payload)
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((self.target, self.port))
            sock.sendall(payload)
            
            # Try to receive response
            try:
                response = sock.recv(4096)
                elapsed = time.time() - start_time
                
                return FuzzResult(
                    mutation_id=mutation_id,
                    payload=payload,
                    response_time=elapsed,
                    crashed=False,
                    anomaly=elapsed > self.timeout * 0.8
                )
            except socket.timeout:
                return FuzzResult(
                    mutation_id=mutation_id,
                    payload=payload,
                    response_time=self.timeout,
                    anomaly=True
                )
        
        except ConnectionRefusedError:
            return FuzzResult(
                mutation_id=mutation_id,
                payload=payload,
                response_time=time.time() - start_time,
                error="Connection refused",
                crashed=True
            )
        except Exception as e:
            return FuzzResult(
                mutation_id=mutation_id,
                payload=payload,
                response_time=time.time() - start_time,
                error=str(e),
                anomaly=True
            )
        finally:
            try:
                sock.close()
            except:
                pass


# === Fuzzing Logic ===
class NetworkFuzzer:
    """Main fuzzing orchestrator."""
    
    def __init__(self, target: str, port: int, protocol: Protocol,
                 mutations: int, rate_limit: int, aggressive: bool,
                 timeout: int, template: Optional[bytes] = None):
        """Initialize fuzzer."""
        self.target = target
        self.port = port
        self.protocol = protocol
        self.mutations = mutations
        self.rate_limit = rate_limit
        self.aggressive = aggressive
        self.timeout = timeout
        self.console = Console()
        self.logger = setup_logging(False)
        
        # Set up handler
        self.handler = self._create_handler()
        
        # Set up template
        self.template = template or self._get_default_template()
        
        # Mutation engine
        intensity = 3 if aggressive else 1
        self.mutator = MutationEngine(self.template, intensity)
    
    def _create_handler(self) -> ProtocolHandler:
        """Create protocol handler."""
        if self.protocol in [Protocol.HTTP, Protocol.HTTPS]:
            return HTTPHandler(
                self.target,
                self.port,
                self.timeout,
                self.protocol == Protocol.HTTPS
            )
        else:
            return TCPHandler(self.target, self.port, self.timeout)
    
    def _get_default_template(self) -> bytes:
        """Get default template for protocol."""
        templates = {
            Protocol.HTTP: b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            Protocol.HTTPS: b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            Protocol.FTP: b"USER anonymous\r\n",
            Protocol.SMTP: b"EHLO test\r\n",
            Protocol.SSH: b"SSH-2.0-OpenSSH_8.0\r\n",
            Protocol.DNS: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        }
        return templates.get(self.protocol, b"FUZZ")
    
    def fuzz(self) -> FuzzSession:
        """Execute fuzzing session."""
        session = FuzzSession(
            target=f"{self.target}:{self.port}",
            protocol=self.protocol,
            total_mutations=self.mutations
        )
        
        # Generate mutations
        self.console.print("[cyan]Generating mutations...[/cyan]")
        mutations = self.mutator.generate_mutations(self.mutations)
        
        # Execute fuzzing
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            task = progress.add_task(
                f"Fuzzing {self.target}...",
                total=len(mutations)
            )
            
            for i, mutation in enumerate(mutations):
                # Rate limiting
                if i > 0 and self.rate_limit > 0:
                    time.sleep(1.0 / self.rate_limit)
                
                # Send fuzzed payload
                result = self.handler.send_fuzz(mutation)
                session.results.append(result)
                
                # Track anomalies
                if result.crashed:
                    session.crashes += 1
                if result.anomaly:
                    session.anomalies += 1
                
                progress.update(task, advance=1)
        
        # Analyze results
        session.findings = self._analyze_results(session.results)
        
        return session
    
    def _analyze_results(self, results: List[FuzzResult]) -> List[Finding]:
        """Analyze fuzzing results for findings."""
        findings = []
        
        # Baseline response time
        baseline_times = [r.response_time for r in results[:10] if not r.crashed and not r.anomaly]
        if baseline_times:
            avg_time = sum(baseline_times) / len(baseline_times)
        else:
            avg_time = 1.0
        
        # Check for crashes
        crashed_results = [r for r in results if r.crashed]
        if crashed_results:
            findings.append(Finding(
                title="Service Crash Detected",
                severity=SeverityLevel.CRITICAL,
                description=f"Service crashed or returned 500+ errors on {len(crashed_results)} mutations",
                payload=crashed_results[0].payload[:100],
                evidence=f"Crash detected with error: {crashed_results[0].error or 'Server error'}",
                recommendation="Investigate crash cause. Implement input validation and error handling.",
                confidence=0.9
            ))
        
        # Check for timing anomalies
        slow_results = [r for r in results if r.response_time > avg_time * 3 and not r.crashed]
        if len(slow_results) > 5:
            findings.append(Finding(
                title="Response Time Anomaly",
                severity=SeverityLevel.MEDIUM,
                description=f"{len(slow_results)} mutations caused significant delays",
                payload=slow_results[0].payload[:100],
                evidence=f"Response time: {slow_results[0].response_time:.2f}s (baseline: {avg_time:.2f}s)",
                recommendation="Review performance impact. May indicate DoS vulnerability.",
                confidence=0.7
            ))
        
        return findings


# === Reporting ===
class Reporter:
    """Generate fuzzing reports."""
    
    def __init__(self, console: Console):
        """Initialize reporter."""
        self.console = console
    
    def print_summary(self, session: FuzzSession) -> None:
        """Print fuzzing summary."""
        self.console.print("\n" + "=" * 80)
        self.console.print("[bold cyan]Fuzzing Session Summary[/bold cyan]")
        self.console.print("=" * 80 + "\n")
        
        # Statistics
        stats = Table(show_header=False, box=None)
        stats.add_column("Metric", style="cyan")
        stats.add_column("Value", style="white")
        
        stats.add_row("Target", session.target)
        stats.add_row("Protocol", session.protocol.value.upper())
        stats.add_row("Total Mutations", str(session.total_mutations))
        stats.add_row("Crashes Detected", str(session.crashes))
        stats.add_row("Anomalies Detected", str(session.anomalies))
        stats.add_row("Findings", str(len(session.findings)))
        
        self.console.print(stats)
        
        # Findings
        if session.findings:
            self.console.print("\n[bold cyan]Security Findings[/bold cyan]\n")
            
            for i, finding in enumerate(session.findings, 1):
                self._print_finding(finding, i)
        else:
            self.console.print("\n[bold green]✓ No security issues detected[/bold green]\n")
        
        self.console.print("=" * 80 + "\n")
    
    def _print_finding(self, finding: Finding, index: int) -> None:
        """Print individual finding."""
        color = self._get_severity_color(finding.severity)
        
        content = f"""[bold]Severity:[/bold] [{color}]{finding.severity.value.upper()}[/{color}]
[bold]Confidence:[/bold] {finding.confidence * 100:.0f}%

[bold]Description:[/bold]
{finding.description}

[bold]Evidence:[/bold]
{finding.evidence}

[bold]Recommendation:[/bold]
{finding.recommendation}

[bold]Sample Payload:[/bold]
{finding.payload.hex()[:100]}...
"""
        
        panel = Panel(content, title=f"[bold]Finding #{index}: {finding.title}[/bold]", border_style=color)
        self.console.print(panel)
        self.console.print()
    
    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity."""
        colors = {
            SeverityLevel.CRITICAL: "bold red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "cyan"
        }
        return colors.get(severity, "white")


# === CLI ===
def print_examples() -> None:
    """Print usage examples."""
    console = Console()
    
    examples = """
[bold cyan]Usage Examples:[/bold cyan]

[bold yellow]1. Fuzz HTTP service:[/bold yellow]
   [green]python networkprotocolfuzzer.py example.com --protocol http --port 80[/green]

[bold yellow]2. Fuzz HTTPS with custom mutations:[/bold yellow]
   [green]python networkprotocolfuzzer.py example.com --protocol https --port 443 --mutations 200[/green]

[bold yellow]3. Aggressive fuzzing (requires acknowledgment):[/bold yellow]
   [green]python networkprotocolfuzzer.py example.com --protocol ftp --aggressive --i-understand-legal-responsibilities[/green]

[bold yellow]4. Custom rate limit:[/bold yellow]
   [green]python networkprotocolfuzzer.py example.com --protocol smtp --rate 5[/green]

[bold yellow]5. FTP fuzzing:[/bold yellow]
   [green]python networkprotocolfuzzer.py ftp.example.com --protocol ftp --port 21[/green]
"""
    
    console.print(examples)


def print_banner(console: Console) -> None:
    """Print application banner."""
    if PYFIGLET_AVAILABLE:
        banner = pyfiglet.figlet_format("Net Proto Fuzzer", font="slant")
        console.print(f"[bold cyan]{banner}[/bold cyan]")
    else:
        console.print("\n[bold cyan]" + "=" * 70 + "[/bold cyan]")
        console.print("[bold cyan]    Network Protocol Fuzzer v" + VERSION + "[/bold cyan]")
        console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
    
    console.print(f"[dim]Author: {AUTHOR}[/dim]\n")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network Protocol Fuzzer - Mutation-based fuzzing tool",
        epilog=f"Author: {AUTHOR} | Version: {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target host/IP')
    parser.add_argument('--port', type=int, help='Target port')
    parser.add_argument('--protocol', choices=['http', 'https', 'ftp', 'smtp', 'ssh', 'dns'],
                       default='http', help='Protocol to fuzz')
    parser.add_argument('--template', type=Path, help='Template file for base payload')
    parser.add_argument('--mutations', type=int, default=DEFAULT_MUTATIONS,
                       help=f'Number of mutations (default: {DEFAULT_MUTATIONS})')
    parser.add_argument('--rate', type=int, default=DEFAULT_RATE_LIMIT,
                       help=f'Rate limit (req/sec, default: {DEFAULT_RATE_LIMIT})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                       help=f'Timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--aggressive', action='store_true',
                       help='Enable aggressive fuzzing (requires acknowledgment)')
    parser.add_argument('--examples', action='store_true', help='Show examples')
    parser.add_argument('--i-understand-legal-responsibilities', action='store_true',
                       help='Acknowledge legal warning')
    
    args = parser.parse_args()
    
    console = Console()
    
    if args.examples:
        print_examples()
        return 0
    
    # Banner
    print_banner(console)
    
    # Legal warning
    console.print(LEGAL_WARNING, style="bold yellow")
    
    if not args.i_understand_legal_responsibilities:
        response = console.input(
            "\n[bold yellow]Do you have authorization to fuzz this target? (yes/no):[/bold yellow] "
        )
        if response.lower() not in ['yes', 'y']:
            console.print("[red]Fuzzing cancelled.[/red]")
            return 1
    
    # Aggressive mode check
    if args.aggressive and not args.i_understand_legal_responsibilities:
        console.print("[red]Aggressive mode requires --i-understand-legal-responsibilities[/red]")
        return 1
    
    # Set default port if not specified
    if not args.port:
        default_ports = {
            'http': 80, 'https': 443, 'ftp': 21,
            'smtp': 25, 'ssh': 22, 'dns': 53
        }
        args.port = default_ports.get(args.protocol, 80)
    
    # Load template if provided
    template = None
    if args.template:
        try:
            with open(args.template, 'rb') as f:
                template = f.read()
        except Exception as e:
            console.print(f"[red]Error loading template: {e}[/red]")
            return 1
    
    try:
        # Create fuzzer
        fuzzer = NetworkFuzzer(
            target=args.target,
            port=args.port,
            protocol=Protocol(args.protocol),
            mutations=args.mutations,
            rate_limit=args.rate,
            aggressive=args.aggressive,
            timeout=args.timeout,
            template=template
        )
        
        # Run fuzzing
        session = fuzzer.fuzz()
        
        # Report results
        reporter = Reporter(console)
        reporter.print_summary(session)
        
        return 0 if not session.findings else 1
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logging.exception("Fatal error")
        return 1


if __name__ == '__main__':
    sys.exit(main())
