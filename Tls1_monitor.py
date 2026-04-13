#!/usr/bin/env python3
r"""
tls_monitor.py — Real-time TLS/SSL traffic monitor for Windows.

Features:
  - Live packet capture via WinDivert (pydivert)
  - Process + PID resolution via psutil
  - SNI, ALPN, TLS version extraction from handshakes
  - Reassembly buffers for fragmented ClientHello/ServerHello
  - Rich full-screen dashboard with:
      * Real-time throughput sparklines
      * Color-coded flow table with rate columns
      * Themed event stream with severity icons
      * Top-talkers summary
  - Graceful shutdown on Ctrl+C
  - Keyboard navigation:
      Up/Down / K/J / W/S — scroll active panel
      PgUp/PgDn            — jump 10 rows
      Home/End             — jump to top/bottom
      Tab                  — switch active panel (Flows / Events)
      q                    — quit

Does NOT decrypt TLS payloads — passive metadata observer only.

Requirements:
    pip install pydivert rich psutil

Run from elevated PowerShell:
    python tls_monitor.py
"""

from __future__ import annotations

import argparse
import msvcrt
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple, Union

if os.name != "nt":
    print("This script is Windows-only (requires WinDivert/pydivert).")
    sys.exit(1)

try:
    import psutil
    import pydivert
    from rich.box import ROUNDED, HEAVY
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    from rich.style import Style
except ImportError as exc:
    missing = getattr(exc, "name", "required package")
    print(
        f"Missing dependency: {missing}\n"
        "Install with:  pip install pydivert rich psutil"
    )
    sys.exit(1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TLS_PORTS_DEFAULT = [443, 465, 587, 853, 8443, 9443, 993, 995]
BUFFER_LIMIT      = 65536
MAX_HISTORY       = 60          # seconds of throughput history for sparkline
SPARK_CHARS       = "▁▂▃▄▅▆▇█"
RATE_WINDOW_SEC   = 3.0         # sliding window for per-flow rate calculation
EXPIRE_INTERVAL   = 30.0        # how often to sweep stale flows (seconds)
FLOW_TTL          = 300         # flow idle timeout (seconds)

TLS_VERSION_MAP = {
    b"\x03\x00": "SSLv3",
    b"\x03\x01": "TLS1.0",
    b"\x03\x02": "TLS1.1",
    b"\x03\x03": "TLS1.2",
    b"\x03\x04": "TLS1.3",
}

# Normalised to lowercase so _apply_metadata comparisons are consistent
TLS_CONTENT_NAMES = {
    20: "change_cipher",
    21: "alert",
    22: "handshake",
    23: "app_data",
    24: "heartbeat",
}

EVENT_ICONS = {
    "client_hello":   ">>",
    "server_hello":   "<<",
    "app_data":       "..",
    "alert":          "!!",
    "handshake":      "HS",
    "change_cipher":  "CC",
    "other":          "~~",
}

EVENT_STYLES = {
    "client_hello":  "bold bright_cyan",
    "server_hello":  "bold bright_green",
    "app_data":      "magenta",
    "alert":         "bold bright_red",
    "handshake":     "yellow",
    "change_cipher": "bright_yellow",
    "other":         "white",
}

PANEL_NAMES = ["Flows", "Events"]

HEADER_TALL       = 7
HEADER_COMPACT    = 6
FOOTER_HEIGHT     = 3
FLOW_TABLE_CHROME = 4
EVENT_TABLE_CHROME = 4
TALKER_TABLE_CHROME = 4


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scroll state + keyboard
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ScrollState:
    """Track scroll offsets and active panel for keyboard navigation."""
    flow_offset:    int = 0
    event_offset:   int = 0
    active_panel:   int = 0   # 0 = Flows, 1 = Events
    total_flows:    int = 0
    total_events:   int = 0
    visible_flows:  int = 12
    visible_events: int = 10

    @property
    def active_name(self) -> str:
        return PANEL_NAMES[self.active_panel]

    def scroll_up(self, n: int = 1) -> None:
        if self.active_panel == 0:
            self.flow_offset = max(0, self.flow_offset - n)
        else:
            self.event_offset = max(0, self.event_offset - n)

    def scroll_down(self, n: int = 1) -> None:
        if self.active_panel == 0:
            max_off = max(0, self.total_flows - self.visible_flows)
            self.flow_offset = min(max_off, self.flow_offset + n)
        else:
            max_off = max(0, self.total_events - self.visible_events)
            self.event_offset = min(max_off, self.event_offset + n)

    def scroll_home(self) -> None:
        if self.active_panel == 0:
            self.flow_offset = 0
        else:
            self.event_offset = 0

    def scroll_end(self) -> None:
        if self.active_panel == 0:
            self.flow_offset = max(0, self.total_flows - self.visible_flows)
        else:
            self.event_offset = max(0, self.total_events - self.visible_events)

    def switch_panel(self) -> None:
        self.active_panel = (self.active_panel + 1) % len(PANEL_NAMES)

    def clamp(self) -> None:
        """Re-clamp offsets after totals change."""
        self.flow_offset  = min(self.flow_offset,  max(0, self.total_flows  - self.visible_flows))
        self.event_offset = min(self.event_offset, max(0, self.total_events - self.visible_events))


def poll_keys(scroll: ScrollState) -> None:
    """Non-blocking keyboard poll (arrow keys + Vim/WASD aliases)."""
    while msvcrt.kbhit():
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):        # extended key prefix
            code = msvcrt.getch()
            if   code == b"H": scroll.scroll_up()
            elif code == b"P": scroll.scroll_down()
            elif code == b"I": scroll.scroll_up(10)
            elif code == b"Q": scroll.scroll_down(10)
            elif code == b"G": scroll.scroll_home()
            elif code == b"O": scroll.scroll_end()
            continue

        lower = ch.lower()
        if   lower in (b"k", b"w"): scroll.scroll_up()
        elif lower in (b"j", b"s"): scroll.scroll_down()
        elif ch == b"\t":           scroll.switch_panel()
        elif lower == b"q":         raise KeyboardInterrupt


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def human_bytes(v: Union[int, float]) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(v) < 1024 or unit == "TB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.0f} B"


def human_rate(bps: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if abs(bps) < 1024 or unit == "GB/s":
            return f"{bps:.0f} {unit}" if unit == "B/s" else f"{bps:.1f} {unit}"
        bps /= 1024
    return f"{bps:.0f} B/s"


def age_text(sec: float) -> str:
    sec = max(int(sec), 0)
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def trim(text: Optional[str], limit: int) -> str:
    if not text:
        return "-"
    return text if len(text) <= limit else text[: max(1, limit - 1)] + "\u2026"


def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def is_outbound(packet: "pydivert.Packet") -> bool:
    direct = getattr(packet, "is_outbound", None)
    if isinstance(direct, bool):
        return direct
    d = getattr(packet, "direction", None)
    return str(d).upper().endswith("OUTBOUND") if d else False


def read_u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "big")


def read_u24(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 3], "big")


def tls_version_name(version: bytes) -> str:
    return TLS_VERSION_MAP.get(version, f"0x{version.hex()}")


def tls_content_name(rtype: int) -> str:
    return TLS_CONTENT_NAMES.get(rtype, "other")


def build_filter(ports: list[int]) -> str:
    clauses = [f"(tcp.DstPort == {p} or tcp.SrcPort == {p})" for p in ports]
    return "tcp and tcp.PayloadLength > 0 and (" + " or ".join(clauses) + ")"


def sparkline(values: Deque[float], width: int = 40) -> str:
    if not values or max(values) == 0:
        return SPARK_CHARS[0] * width
    peak = max(values)
    step = max(len(values), 1) / width
    out = []
    for i in range(width):
        idx   = min(int(i * step), len(values) - 1)
        ratio = values[idx] / peak if peak else 0
        out.append(SPARK_CHARS[min(int(ratio * (len(SPARK_CHARS) - 1)), len(SPARK_CHARS) - 1)])
    return "".join(out)


def visible_range(offset: int, visible: int, total: int) -> str:
    if total <= 0 or visible <= 0:
        return "0/0"
    start = min(offset, max(total - 1, 0))
    end   = min(start + visible, total)
    return f"{start + 1}-{end}/{total}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TLS Parser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def find_tls_start(data: bytes) -> Optional[int]:
    for i in range(min(len(data), 512)):
        if i + 5 > len(data):
            return None
        if data[i] not in {20, 21, 22, 23, 24}:
            continue
        if data[i + 1] != 0x03:
            continue
        length = read_u16(data, i + 3)
        if length > 0 and i + 5 + length <= len(data):
            return i
    return None


def parse_sni(ext: bytes) -> Optional[str]:
    if len(ext) < 5:
        return None
    total = read_u16(ext, 0)
    off   = 2
    end   = min(len(ext), 2 + total)
    while off + 3 <= end:
        ntype = ext[off]
        nlen  = read_u16(ext, off + 1)
        off  += 3
        if off + nlen > end:
            break
        if ntype == 0 and nlen:
            return safe_decode(ext[off:off + nlen])
        off += nlen
    return None


def parse_alpn(ext: bytes) -> List[str]:
    out: List[str] = []
    if len(ext) < 2:
        return out
    total = read_u16(ext, 0)
    off   = 2
    end   = min(len(ext), 2 + total)
    while off < end:
        if off + 1 > end:
            break
        nlen  = ext[off]
        off  += 1
        if off + nlen > end:
            break
        if nlen:
            out.append(safe_decode(ext[off:off + nlen]))
        off += nlen
    return out


def parse_supported_versions(ext: bytes) -> List[str]:
    versions: List[str] = []
    if not ext:
        return versions
    # ClientHello: 1-byte list length + 2-byte entries
    if len(ext) >= 3 and ext[0] <= len(ext) - 1:
        size = ext[0]
        off  = 1
        end  = min(len(ext), 1 + size)
        while off + 2 <= end:
            versions.append(tls_version_name(ext[off:off + 2]))
            off += 2
        if versions:
            return versions
    # ServerHello: single 2-byte selected version
    if len(ext) >= 2:
        return [tls_version_name(ext[:2])]
    return versions


def parse_client_hello(body: bytes) -> Optional[Dict[str, object]]:
    if len(body) < 34:
        return None
    off    = 0
    legacy = body[off:off + 2]
    off   += 2 + 32
    if off >= len(body):
        return None
    sid_len  = body[off]
    off     += 1 + sid_len
    if off + 2 > len(body):
        return None
    cs_len = read_u16(body, off)
    off   += 2 + cs_len
    if off >= len(body):
        return None
    comp_len = body[off]
    off     += 1 + comp_len
    if off == len(body):
        return {"msg": "client_hello", "sni": None, "alpn": [], "versions": [tls_version_name(legacy)]}
    if off + 2 > len(body):
        return None

    ext_len = read_u16(body, off)
    off    += 2
    end     = min(len(body), off + ext_len)
    sni, alpn, versions = None, [], []

    while off + 4 <= end:
        etype = read_u16(body, off)
        elen  = read_u16(body, off + 2)
        off  += 4
        if off + elen > end:
            break
        edata = body[off:off + elen]
        off  += elen
        if etype == 0:
            sni = parse_sni(edata) or sni
        elif etype == 16:
            p = parse_alpn(edata)
            if p:
                alpn = p
        elif etype == 43:
            p = parse_supported_versions(edata)
            if p:
                versions = p

    if not versions:
        versions = [tls_version_name(legacy)]

    return {"msg": "client_hello", "sni": sni, "alpn": alpn, "versions": versions}


def parse_server_hello(body: bytes) -> Optional[Dict[str, object]]:
    if len(body) < 38:
        return None
    off    = 0
    legacy = body[off:off + 2]
    off   += 2 + 32
    if off >= len(body):
        return None
    sid_len = body[off]
    off    += 1 + sid_len
    if off + 3 > len(body):
        return None
    off     += 3  # cipher + compression
    selected = tls_version_name(legacy)
    if off + 2 <= len(body):
        ext_len = read_u16(body, off)
        off    += 2
        end     = min(len(body), off + ext_len)
        while off + 4 <= end:
            etype = read_u16(body, off)
            elen  = read_u16(body, off + 2)
            off  += 4
            if off + elen > end:
                break
            edata = body[off:off + elen]
            off  += elen
            if etype == 43:
                p = parse_supported_versions(edata)
                if p:
                    selected = p[0]
    return {"msg": "server_hello", "selected_version": selected}


def parse_tls_metadata(buf: bytes) -> Optional[Dict[str, object]]:
    start = find_tls_start(buf)
    if start is None or start + 5 > len(buf):
        return None
    rtype = buf[start]
    rver  = buf[start + 1:start + 3]
    rlen  = read_u16(buf, start + 3)
    end   = start + 5 + rlen
    if end > len(buf):
        return None
    rbody = buf[start + 5:end]
    cname = tls_content_name(rtype)

    if rtype != 22:
        return {"msg": cname, "record_version": tls_version_name(rver)}

    off = 0
    while off + 4 <= len(rbody):
        ht   = rbody[off]
        hlen = read_u24(rbody, off + 1)
        off += 4
        if off + hlen > len(rbody):
            break
        hbody = rbody[off:off + hlen]
        off  += hlen
        if ht == 1:
            p = parse_client_hello(hbody)
            if p:
                return p
        elif ht == 2:
            p = parse_server_hello(hbody)
            if p:
                return p

    return {"msg": "handshake", "record_version": tls_version_name(rver)}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Data Classes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class StreamEvent:
    ts:        float
    direction: str          # OUT / IN
    process:   str
    pid:       Optional[int]
    remote:    str
    message:   str
    category:  str          # key into EVENT_STYLES / EVENT_ICONS


@dataclass
class FlowRecord:
    local:            str
    remote:           str
    pid:              Optional[int] = None
    process:          str           = "unknown"
    sni:              Optional[str] = None
    alpn:             List[str]     = field(default_factory=list)
    offered_versions: List[str]     = field(default_factory=list)
    selected_version: Optional[str] = None
    packets_out:      int           = 0
    packets_in:       int           = 0
    bytes_out:        int           = 0
    bytes_in:         int           = 0
    first_seen:       float         = field(default_factory=time.time)
    last_seen:        float         = field(default_factory=time.time)
    out_buffer:       bytearray     = field(default_factory=bytearray)
    in_buffer:        bytearray     = field(default_factory=bytearray)
    client_hello_seen: bool         = False
    server_hello_seen: bool         = False
    # Timestamped byte samples for sliding-window rate calculation
    _rate_out_samples: Deque[Tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=64)
    )
    _rate_in_samples: Deque[Tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=64)
    )

    def touch(self, now: float) -> None:
        self.last_seen = now

    @property
    def version_label(self) -> str:
        if self.selected_version:
            return self.selected_version
        return self.offered_versions[0] if self.offered_versions else "-"

    @property
    def alpn_label(self) -> str:
        return ", ".join(self.alpn) if self.alpn else "-"

    @property
    def rate_out(self) -> float:
        return self._calc_rate(self._rate_out_samples)

    @property
    def rate_in(self) -> float:
        return self._calc_rate(self._rate_in_samples)

    @staticmethod
    def _calc_rate(samples: Deque[Tuple[float, int]]) -> float:
        """
        Sliding-window rate: only consider samples within RATE_WINDOW_SEC.
        Uses the oldest sample in the window as baseline, newest as endpoint.
        """
        if len(samples) < 2:
            return 0.0
        now    = time.monotonic()
        cutoff = now - RATE_WINDOW_SEC
        # Filter to the window; keep at least first+last if all are old
        window = [(t, b) for t, b in samples if t >= cutoff]
        if len(window) < 2:
            # Fall back to oldest vs newest available
            window = [samples[0], samples[-1]]
        t0, b0 = window[0]
        t1, b1 = window[-1]
        dt = t1 - t0
        if dt <= 0:
            return 0.0
        return max(0.0, (b1 - b0) / dt)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Process Resolver
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProcessResolver:
    def __init__(self, refresh_seconds: float) -> None:
        self.refresh_seconds = refresh_seconds
        self._last:     float = 0.0
        self._by_flow:  Dict[Tuple[str, int, str, int], Tuple[Optional[int], str]] = {}
        self._by_local: Dict[Tuple[str, int],           Tuple[Optional[int], str]] = {}
        self._name_cache: Dict[int, str] = {}

    def _name(self, pid: Optional[int]) -> str:
        if pid is None:
            return "unknown"
        if pid in self._name_cache:
            return self._name_cache[pid]
        try:
            n = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            n = "unknown"
        self._name_cache[pid] = n
        return n

    def refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last) < self.refresh_seconds:
            return
        by_flow:  Dict[Tuple[str, int, str, int], Tuple[Optional[int], str]] = {}
        by_local: Dict[Tuple[str, int],           Tuple[Optional[int], str]] = {}
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if not conn.laddr:
                    continue
                lip, lport = conn.laddr.ip, conn.laddr.port
                name = self._name(conn.pid)
                by_local[(lip, lport)] = (conn.pid, name)
                if conn.raddr:
                    rip, rport = conn.raddr.ip, conn.raddr.port
                    by_flow[(lip, lport, rip, rport)] = (conn.pid, name)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        self._by_flow  = by_flow
        self._by_local = by_local
        self._last     = now

    def lookup(self, lip: str, lport: int, rip: str, rport: int) -> Tuple[Optional[int], str]:
        self.refresh()
        return (
            self._by_flow.get((lip, lport, rip, rport))
            or self._by_local.get((lip, lport))
            or (None, "unknown")
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Dashboard State
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DashboardState:
    def __init__(self, max_events: int) -> None:
        self.lock          = threading.Lock()
        self.flows:        Dict[Tuple[str, str], FlowRecord] = {}
        self.events:       Deque[StreamEvent] = deque(maxlen=max_events)
        self.total_packets = 0
        self.total_bytes   = 0
        self.start_time    = time.time()
        # Per-second throughput buckets for sparklines
        self._tp_history_out:     Deque[float] = deque(maxlen=MAX_HISTORY)
        self._tp_history_in:      Deque[float] = deque(maxlen=MAX_HISTORY)
        self._tp_bucket_bytes_out = 0
        self._tp_bucket_bytes_in  = 0
        self._tp_bucket_start     = time.time()
        self._current_rate_out    = 0.0
        self._current_rate_in     = 0.0
        # Expire sweep timestamp (monotonic, avoids clock skew issues)
        self._last_expire: float  = time.monotonic()

    # ------------------------------------------------------------------
    # Internal helpers (called from capture thread under self.lock)
    # ------------------------------------------------------------------

    def _tick_throughput(self, now: float) -> None:
        dt = now - self._tp_bucket_start
        if dt >= 1.0:
            self._current_rate_out = self._tp_bucket_bytes_out / dt
            self._current_rate_in  = self._tp_bucket_bytes_in  / dt
            self._tp_history_out.append(self._current_rate_out)
            self._tp_history_in.append(self._current_rate_in)
            self._tp_bucket_bytes_out = 0
            self._tp_bucket_bytes_in  = 0
            self._tp_bucket_start     = now

    @staticmethod
    def _append_buffer(buf: bytearray, data: bytes) -> None:
        buf.extend(data)
        if len(buf) > BUFFER_LIMIT:
            del buf[:len(buf) - BUFFER_LIMIT]

    def _expire_old_flows(self) -> None:
        """Sweep stale flows. Gated by EXPIRE_INTERVAL — call on every packet."""
        mono_now = time.monotonic()
        if mono_now - self._last_expire < EXPIRE_INTERVAL:
            return
        self._last_expire = mono_now
        cutoff = time.time() - FLOW_TTL
        stale  = [k for k, f in self.flows.items() if f.last_seen < cutoff]
        for k in stale:
            del self.flows[k]

    # ------------------------------------------------------------------
    # Metadata extraction (OUTSIDE the lock — operates on a local copy)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_metadata(
        flow: FlowRecord,
        payload: bytes,
        *,
        outbound: bool,
    ) -> Optional[Dict[str, object]]:
        """
        Parse TLS metadata from payload, with per-flow reassembly buffers
        for fragmented ClientHello / ServerHello.

        NOTE: Called before acquiring self.lock.  The flow object itself is
        only read here (buffers mutated); the caller holds no lock.  This is
        safe because each flow key is only processed by the single capture
        thread.
        """
        direct_meta = parse_tls_metadata(payload)

        if outbound:
            if flow.client_hello_seen:
                return direct_meta
            DashboardState._append_buffer(flow.out_buffer, payload)
            buffered = parse_tls_metadata(bytes(flow.out_buffer))
            if buffered and buffered.get("msg") == "client_hello":
                flow.out_buffer.clear()
                flow.client_hello_seen = True
                return buffered
            return direct_meta

        if flow.server_hello_seen:
            return direct_meta
        DashboardState._append_buffer(flow.in_buffer, payload)
        buffered = parse_tls_metadata(bytes(flow.in_buffer))
        if buffered and buffered.get("msg") == "server_hello":
            flow.in_buffer.clear()
            flow.server_hello_seen = True
            return buffered
        return direct_meta

    @staticmethod
    def _apply_metadata(
        flow:      FlowRecord,
        meta:      Optional[Dict[str, object]],
        payload:   bytes,
        direction: str,
    ) -> Tuple[str, str]:
        """Derive (human message, category key) from parsed TLS metadata."""
        if not meta:
            return f"TCP {human_bytes(len(payload))}", "other"

        msg_type = str(meta.get("msg", "other"))

        if msg_type == "client_hello":
            flow.client_hello_seen = True
            sni = meta.get("sni")
            if isinstance(sni, str) and sni:
                flow.sni = sni
            alpn = meta.get("alpn")
            if isinstance(alpn, list) and alpn:
                flow.alpn = [str(v) for v in alpn]
            versions = meta.get("versions")
            if isinstance(versions, list) and versions:
                flow.offered_versions = [str(v) for v in versions]
            parts = ["ClientHello"]
            if flow.offered_versions:
                parts.append(flow.offered_versions[0])
            if flow.sni:
                parts.append(f"SNI={flow.sni}")
            if flow.alpn:
                parts.append(f"ALPN={','.join(flow.alpn)}")
            return " | ".join(parts), "client_hello"

        if msg_type == "server_hello":
            flow.server_hello_seen = True
            sel = meta.get("selected_version")
            if isinstance(sel, str) and sel:
                flow.selected_version = sel
            parts = ["ServerHello"]
            if flow.selected_version:
                parts.append(flow.selected_version)
            return " | ".join(parts), "server_hello"

        if msg_type == "app_data":
            ver   = flow.selected_version or (flow.offered_versions[0] if flow.offered_versions else None)
            label = f"AppData {human_bytes(len(payload))}"
            if ver:
                label += f" | {ver}"
            return label, "app_data"

        if msg_type == "alert":
            return f"TLS Alert {human_bytes(len(payload))}", "alert"

        if msg_type == "handshake":
            ver = meta.get("record_version")
            if isinstance(ver, str) and ver:
                return f"Handshake | {ver}", "handshake"
            return "Handshake", "handshake"

        if msg_type == "change_cipher":
            return "ChangeCipherSpec", "change_cipher"

        ver = meta.get("record_version")
        if isinstance(ver, str) and ver:
            return f"{msg_type} | {ver}", "other"
        return f"{msg_type} | {human_bytes(len(payload))}", "other"

    # ------------------------------------------------------------------
    # Public capture entry-point
    # ------------------------------------------------------------------

    def add_packet(self, packet: "pydivert.Packet", resolver: ProcessResolver) -> None:
        payload = bytes(packet.payload or b"")
        if not payload:
            return

        outbound = is_outbound(packet)
        if outbound:
            lip, lport = str(packet.src_addr), int(packet.src_port)
            rip, rport = str(packet.dst_addr), int(packet.dst_port)
            direction  = "OUT"
        else:
            lip, lport = str(packet.dst_addr), int(packet.dst_port)
            rip, rport = str(packet.src_addr), int(packet.src_port)
            direction  = "IN"

        # Resolve PID/process name BEFORE acquiring the lock
        pid, pname = resolver.lookup(lip, lport, rip, rport)
        key        = (f"{lip}:{lport}", f"{rip}:{rport}")
        now        = time.time()

        # ── Extract TLS metadata from buffers BEFORE the lock ──────────
        # The flow object may not exist yet; create a temporary one for
        # metadata extraction when it's a new flow, then discard or merge.
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = FlowRecord(local=key[0], remote=key[1], pid=pid, process=pname)
                self.flows[key] = flow
            else:
                if pid is not None:
                    flow.pid = pid
                if pname != "unknown":
                    flow.process = pname

        # Metadata parsing operates on flow buffers and is CPU-bound;
        # do it outside the lock so renders aren't blocked.
        meta = self._extract_metadata(flow, payload, outbound=outbound)

        mono_now = time.monotonic()

        with self.lock:
            flow.touch(now)

            if outbound:
                flow.packets_out += 1
                flow.bytes_out   += len(payload)
                flow._rate_out_samples.append((mono_now, flow.bytes_out))
                self._tp_bucket_bytes_out += len(payload)
            else:
                flow.packets_in += 1
                flow.bytes_in   += len(payload)
                flow._rate_in_samples.append((mono_now, flow.bytes_in))
                self._tp_bucket_bytes_in += len(payload)

            self.total_packets += 1
            self.total_bytes   += len(payload)

            message, category = self._apply_metadata(flow, meta, payload, direction)
            self.events.appendleft(
                StreamEvent(
                    ts=now, direction=direction, process=flow.process,
                    pid=flow.pid, remote=flow.remote,
                    message=message, category=category,
                )
            )
            self._expire_old_flows()
            self._tick_throughput(now)

    # ------------------------------------------------------------------
    # Snapshot for render thread
    # ------------------------------------------------------------------

    def snapshot(
        self,
    ) -> Tuple[
        List[FlowRecord],
        List[StreamEvent],
        Tuple[int, int, float],
        Tuple[float, float],
        List[float],
        List[float],
    ]:
        with self.lock:
            flows    = list(self.flows.values())
            events   = list(self.events)
            tp       = (self.total_packets, self.total_bytes, time.time() - self.start_time)
            rates    = (self._current_rate_out, self._current_rate_in)
            hist_out = list(self._tp_history_out)
            hist_in  = list(self._tp_history_in)
        return flows, events, tp, rates, hist_out, hist_in


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Viewport
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass(frozen=True)
class DashboardViewport:
    width:         int
    height:        int
    header_height: int
    footer_height: int
    lower_height:  int
    flow_rows:     int
    event_rows:    int
    talker_rows:   int
    spark_width:   int


def compute_dashboard_viewport(
    console:   Console,
    flow_cap:  int,
    event_cap: int,
) -> DashboardViewport:
    width  = max(console.size.width,  80)
    height = max(console.size.height, 24)
    header_height = HEADER_TALL if height >= 30 else HEADER_COMPACT
    footer_height = FOOTER_HEIGHT
    body_height   = max(12, height - header_height - footer_height)
    lower_height  = min(12, max(7, body_height // 3 + 2))
    flow_height   = max(5, body_height - lower_height)
    lower_height  = max(6, body_height - flow_height)

    flow_rows   = max(3, min(flow_cap,  flow_height  - FLOW_TABLE_CHROME))
    event_rows  = max(3, min(event_cap, lower_height - EVENT_TABLE_CHROME))
    talker_rows = max(2, min(5,         lower_height - TALKER_TABLE_CHROME))
    spark_width = max(14, min(30, width // 6))

    return DashboardViewport(
        width=width,
        height=height,
        header_height=header_height,
        footer_height=footer_height,
        lower_height=lower_height,
        flow_rows=flow_rows,
        event_rows=event_rows,
        talker_rows=talker_rows,
        spark_width=spark_width,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Rendering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def make_summary_panel(
    ports:         List[int],
    total_packets: int,
    total_bytes:   int,
    uptime:        float,
    rate_out:      float,
    rate_in:       float,
    hist_out:      List[float],
    hist_in:       List[float],
    num_flows:     int,
    scroll:        ScrollState,
    viewport:      DashboardViewport,
) -> Panel:
    active_color = "bright_blue" if scroll.active_panel == 0 else "bright_magenta"
    spark_out    = sparkline(deque(hist_out), width=viewport.spark_width)
    spark_in     = sparkline(deque(hist_in),  width=viewport.spark_width)

    title = Text()
    title.append("TLS Traffic Monitor", style="bold bright_white")
    title.append("  live handshake and session metadata", style="bright_cyan")

    overview = Text()
    overview.append("Ports ",  style="bold white")
    overview.append(", ".join(str(p) for p in sorted(ports)), style="cyan")
    overview.append("   Active ", style="dim")
    overview.append(scroll.active_name, style=f"bold {active_color}")
    overview.append("   Screen ", style="dim")
    overview.append(f"{viewport.width}x{viewport.height}", style="bright_white")

    stats = Text()
    stats.append("Uptime ",   style="dim")
    stats.append(age_text(uptime), style="bright_green")
    stats.append("   Flows ", style="dim")
    stats.append(str(num_flows), style="bright_cyan")
    stats.append("   Packets ", style="dim")
    stats.append(f"{total_packets:,}", style="yellow")
    stats.append("   Total ", style="dim")
    stats.append(human_bytes(total_bytes), style="magenta")

    traffic = Text()
    traffic.append("Out ", style="dim")
    traffic.append(human_rate(rate_out), style="bold bright_blue")
    traffic.append(" ")
    traffic.append(spark_out, style="bright_blue")
    traffic.append("   In ", style="dim")
    traffic.append(human_rate(rate_in), style="bold bright_magenta")
    traffic.append(" ")
    traffic.append(spark_in, style="bright_magenta")

    return Panel(
        Group(title, overview, stats, traffic),
        border_style="bright_cyan",
        box=HEAVY,
        padding=(0, 1),
        title="[bold]Capture Summary[/bold]",
        title_align="left",
    )


def build_flow_table(flows: List[FlowRecord], max_rows: int, scroll: ScrollState) -> Table:
    now    = time.time()
    active = scroll.active_panel == 0
    title_style = "bold bright_white on bright_blue" if active else "bold bright_white"
    border      = "bright_blue" if active else "blue"
    table = Table(
        title        = f"[{title_style}]Active TLS Sessions[/]",
        expand       = True,
        box          = ROUNDED,
        show_lines   = False,
        border_style = border,
    )
    table.add_column("App",      style="bold white",     max_width=16, overflow="ellipsis")
    table.add_column("PID",      justify="right", style="cyan",          width=6)
    table.add_column("Remote",   style="green",          max_width=20, overflow="ellipsis")
    table.add_column("SNI",      style="bright_magenta", max_width=24, overflow="ellipsis")
    table.add_column("TLS",      style="bright_yellow",  width=7)
    table.add_column("ALPN",     style="magenta",        max_width=12, overflow="ellipsis")
    table.add_column("TX",       justify="right", style="bright_blue",    width=8)
    table.add_column("RX",       justify="right", style="bright_magenta", width=8)
    table.add_column("TX/s",     justify="right", style="blue",           width=8)
    table.add_column("RX/s",     justify="right", style="magenta",        width=8)
    table.add_column("Idle",     justify="right", style="dim",            width=6)

    ranked = sorted(flows, key=lambda f: (f.bytes_out + f.bytes_in, f.last_seen), reverse=True)

    scroll.total_flows  = len(ranked)
    scroll.visible_flows = max_rows
    scroll.clamp()
    start  = scroll.flow_offset
    end    = start + max_rows
    sliced = ranked[start:end]
    table.title = (
        f"[{title_style}]Active TLS Sessions[/] "
        f"[dim]{visible_range(start, max_rows, len(ranked))}[/]"
    )

    for fl in sliced:
        idle      = now - fl.last_seen
        dim       = idle > 30
        app_style = "dim white" if dim else "bold white"
        pid_str   = str(fl.pid or "-")
        rate_o    = human_rate(fl.rate_out) if fl.rate_out > 0 else "-"
        rate_i    = human_rate(fl.rate_in)  if fl.rate_in  > 0 else "-"

        table.add_row(
            Text(trim(fl.process, 16), style=app_style),
            Text(pid_str, style="dim cyan" if dim else "cyan"),
            trim(fl.remote, 20),
            trim(fl.sni, 24),
            trim(fl.version_label, 7),
            trim(fl.alpn_label, 12),
            human_bytes(fl.bytes_out),
            human_bytes(fl.bytes_in),
            rate_o if rate_o != "-" else Text("-", style="dim"),
            rate_i if rate_i != "-" else Text("-", style="dim"),
            age_text(idle),
        )

    if not sliced:
        table.add_row("waiting", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-")

    return table


def build_top_talkers(flows: List[FlowRecord], n: int) -> Table:
    table = Table(
        title        = "[bold bright_white]Top Talkers[/bold bright_white]",
        box          = ROUNDED,
        expand       = True,
        show_lines   = False,
        border_style = "cyan",
    )
    table.add_column("#",       style="dim",             width=3)
    table.add_column("Process", style="bold white",      max_width=16, overflow="ellipsis")
    table.add_column("SNI",     style="bright_magenta",  max_width=22, overflow="ellipsis")
    table.add_column("Bytes",   justify="right", style="bright_blue", width=10)
    table.add_column("Share",   width=16)

    by_proc: Dict[str, Dict] = {}
    for fl in flows:
        key = fl.process
        if key not in by_proc:
            by_proc[key] = {"bytes": 0, "sni": fl.sni or "-"}
        by_proc[key]["bytes"] += fl.bytes_out + fl.bytes_in
        if fl.sni and by_proc[key]["sni"] == "-":
            by_proc[key]["sni"] = fl.sni

    top   = sorted(by_proc.items(), key=lambda item: item[1]["bytes"], reverse=True)[:n]
    total = sum(v["bytes"] for v in by_proc.values()) or 1

    if not top:
        table.add_row("-", "waiting", "-", "-", "-")
        return table

    for idx, (proc, data) in enumerate(top, 1):
        share      = data["bytes"] / total
        bar_filled = min(12, int(round(share * 12)))
        if share > 0 and bar_filled == 0:
            bar_filled = 1
        share_bar = (
            f"[bright_cyan]{'=' * bar_filled}[/]"
            f"[dim]{'.' * (12 - bar_filled)}[/] {share:.0%}"
        )
        table.add_row(
            str(idx),
            trim(proc, 16),
            trim(data["sni"], 22),
            human_bytes(data["bytes"]),
            share_bar,
        )

    table.title = f"[bold bright_white]Top Talkers[/] [dim]top {len(top)}[/]"
    return table


def build_event_stream(events: List[StreamEvent], max_rows: int, scroll: ScrollState) -> Table:
    active      = scroll.active_panel == 1
    title_style = "bold bright_white on bright_magenta" if active else "bold bright_white"
    border      = "bright_magenta" if active else "magenta"
    table = Table(
        title        = f"[{title_style}]Event Stream[/]",
        box          = ROUNDED,
        expand       = True,
        show_lines   = False,
        border_style = border,
    )
    table.add_column("T",      style="dim",  width=8)
    table.add_column("Dir",    width=3)
    table.add_column("App",    style="bold", max_width=16, overflow="ellipsis")
    table.add_column("Remote", max_width=20, overflow="ellipsis")
    table.add_column("Detail")

    scroll.total_events  = len(events)
    scroll.visible_events = max_rows
    scroll.clamp()
    start  = scroll.event_offset
    end    = start + max_rows
    sliced = events[start:end]
    table.title = (
        f"[{title_style}]Event Stream[/] "
        f"[dim]{visible_range(start, max_rows, len(events))}[/]"
    )

    for ev in sliced:
        stamp     = time.strftime("%H:%M:%S", time.localtime(ev.ts))
        icon      = EVENT_ICONS.get(ev.category, "~~")
        style     = EVENT_STYLES.get(ev.category, "white")
        dir_style = "bright_cyan" if ev.direction == "OUT" else "bright_yellow"
        pid_suffix = f"({ev.pid})" if ev.pid else ""

        table.add_row(
            stamp,
            Text(ev.direction, style=dir_style),
            Text(trim(ev.process + pid_suffix, 16), style="bold"),
            trim(ev.remote, 20),
            Text(f"[{icon}] {trim(ev.message, 72)}", style=style),
        )

    if not sliced:
        table.add_row("-", "-", "waiting", "-", "No TLS traffic captured yet.")

    return table


def build_controls_footer(scroll: ScrollState) -> Panel:
    flow_info  = visible_range(scroll.flow_offset,  scroll.visible_flows,  scroll.total_flows)
    event_info = visible_range(scroll.event_offset, scroll.visible_events, scroll.total_events)
    active_color = "bright_blue" if scroll.active_panel == 0 else "bright_magenta"

    line = Text()
    line.append("Active ", style="dim")
    line.append(scroll.active_name, style=f"bold {active_color}")
    line.append("   Flows ",  style="dim")
    line.append(flow_info,  style="bright_blue")
    line.append("   Events ", style="dim")
    line.append(event_info, style="bright_magenta")
    line.append("   Keys ",  style="dim")
    line.append("Arrows/J/K/W/S", style="bold white")
    line.append(" scroll  ", style="dim")
    line.append("PgUp/PgDn",  style="bold white")
    line.append(" page  ",   style="dim")
    line.append("Home/End",  style="bold white")
    line.append(" ends  ",   style="dim")
    line.append("Tab",       style="bold white")
    line.append(" switch  ", style="dim")
    line.append("Q",         style="bold red")
    line.append(" quit",     style="dim")

    return Panel(line, box=ROUNDED, border_style="dim", padding=(0, 1))


def render_dashboard(
    console:    Console,
    ports:      List[int],
    state:      DashboardState,
    max_rows:   int,
    max_events: int,
    scroll:     ScrollState,
) -> Layout:
    flows, events, (tp, tb, up), (ro, ri), ho, hi = state.snapshot()
    viewport = compute_dashboard_viewport(console, max_rows, max_events)

    header      = make_summary_panel(ports, tp, tb, up, ro, ri, ho, hi, len(flows), scroll, viewport)
    flow_table  = build_flow_table(flows, viewport.flow_rows, scroll)
    top_talkers = build_top_talkers(flows, viewport.talker_rows)
    event_stream = build_event_stream(events, viewport.event_rows, scroll)
    footer      = build_controls_footer(scroll)

    layout = Layout(name="root")
    layout.split_column(
        Layout(header,  name="header", size=viewport.header_height),
        Layout(name="body", ratio=1),
        Layout(footer,  name="footer", size=viewport.footer_height),
    )
    layout["body"].split_column(
        Layout(flow_table, name="flows",  ratio=1),
        Layout(name="bottom", size=viewport.lower_height),
    )
    layout["bottom"].split_row(
        Layout(top_talkers,  name="talkers", ratio=1),
        Layout(event_stream, name="events",  ratio=2),
    )
    return layout


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Capture Loop
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def capture_loop(
    state:       DashboardState,
    resolver:    ProcessResolver,
    filter_text: str,
    stop_event:  threading.Event,
    error_box:   Dict[str, str],
) -> None:
    try:
        with pydivert.WinDivert(filter_text, flags=pydivert.Flag.SNIFF) as handle:
            while not stop_event.is_set():
                packet = handle.recv()
                state.add_packet(packet, resolver)
    except KeyboardInterrupt:
        stop_event.set()
    except Exception as exc:
        error_box["message"] = str(exc)
        stop_event.set()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Real-time TLS/SSL traffic monitor for Windows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--ports", nargs="+", type=int, default=TLS_PORTS_DEFAULT,
        help="TCP ports to monitor (default: 443 465 587 853 8443 9443 993 995).",
    )
    p.add_argument(
        "--rows", type=int, default=18,
        help="Upper cap for visible flow rows; actual rows adapt to terminal height (default: 18).",
    )
    p.add_argument(
        "--events", type=int, default=200,
        help="Events to retain in history; visible rows adapt to terminal height (default: 200).",
    )
    p.add_argument(
        "--resolver-refresh", type=float, default=2.0,
        help="Process/socket refresh interval in seconds (default: 2.0).",
    )
    return p.parse_args()


def main() -> int:
    args       = parse_args()
    ports      = sorted(set(args.ports))
    filter_text = build_filter(ports)

    console    = Console()
    state      = DashboardState(max_events=args.events)
    resolver   = ProcessResolver(refresh_seconds=args.resolver_refresh)
    stop_event = threading.Event()
    error_box: Dict[str, str] = {}
    scroll     = ScrollState()

    worker = threading.Thread(
        target=capture_loop,
        args=(state, resolver, filter_text, stop_event, error_box),
        daemon=True,
    )
    worker.start()

    try:
        with Live(
            render_dashboard(console, ports, state, args.rows, args.events, scroll),
            console=console,
            screen=True,
            refresh_per_second=4,
            vertical_overflow="crop",
        ) as live:
            while not stop_event.is_set():
                try:
                    poll_keys(scroll)
                except KeyboardInterrupt:
                    stop_event.set()
                    break
                live.update(render_dashboard(console, ports, state, args.rows, args.events, scroll))
                time.sleep(0.25)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        worker.join(timeout=1.0)

    if error_box:
        console.print(Panel(
            Group(
                Text("Capture stopped with an error.", style="bold bright_red"),
                Text(error_box["message"], style="red"),
                Text("Run PowerShell as Administrator and try again.", style="dim"),
            ),
            border_style="red",
        ))
        return 1

    console.print(Panel(
        Text("TLS monitor stopped.", style="bold bright_green"),
        border_style="green",
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())