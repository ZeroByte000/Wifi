#!/usr/bin/env python3
"""
wifi_audit.py — Passive WiFi Security Audit Tool (Defensive)
- Passive scan for APs/clients (monitor mode required)
- Detect encryption, WPA versions, PMF/802.11w (where visible), WPS presence
- Basic rogue/eviI-twin indicators (SSID reuse, OUI/vendor mismatch hints)
- Exports JSON/CSV, live TUI-style output, robust error handling

This tool does NOT perform attacks (no deauth, no handshake/PMKID capture, no cracking).
"""

import argparse
import csv
import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Set, Tuple, List

# Scapy imports (monitor-mode sniffing)
try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap, conf
except Exception as e:
    print(f"[!] Scapy import failed: {e}")
    print("[!] Install requirements: pip3 install scapy")
    sys.exit(1)


def sh(cmd: List[str], check: bool = False, capture: bool = True, text: bool = True, timeout: Optional[int] = None):
    """Run a command safely and return CompletedProcess."""
    try:
        return subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=text,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(cmd, 124, stdout="", stderr=str(e))
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, stdout="", stderr="command not found")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def normalize_mac(mac: Optional[str]) -> str:
    if not mac:
        return ""
    mac = mac.strip().lower()
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        return mac
    return mac


def safe_decode(b: bytes) -> str:
    for enc in ("utf-8", "latin-1", "utf-16", "cp1252"):
        try:
            return b.decode(enc, errors="ignore")
        except Exception:
            continue
    return "".join(chr(x) if 32 <= x <= 126 else "." for x in b[:32])


def oui_prefix(mac: str) -> str:
    mac = normalize_mac(mac)
    parts = mac.split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else ""


def load_oui_db(path: str) -> Dict[str, str]:
    """
    Load simple OUI mapping file (optional).
    Accepts formats:
      - "FC:FB:FB Apple, Inc."
      - "FCFBFB Apple, Inc."
      - CSV "prefix,vendor"
    """
    db: Dict[str, str] = {}
    if not path or not os.path.exists(path):
        return db
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "," in line and re.match(r"^[0-9A-Fa-f:]{6,}", line):
                    p, v = line.split(",", 1)
                    p = p.strip().replace("-", "").replace(":", "").upper()
                    if len(p) >= 6:
                        p = p[:6]
                        db[p] = v.strip()
                    continue
                m = re.match(r"^([0-9A-Fa-f]{2}[:\-]?[0-9A-Fa-f]{2}[:\-]?[0-9A-Fa-f]{2})\s+(.+)$", line)
                if m:
                    p = m.group(1).replace("-", "").replace(":", "").upper()
                    p = p[:6]
                    db[p] = m.group(2).strip()
                    continue
                m2 = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                if m2:
                    p = m2.group(1).upper()[:6]
                    db[p] = m2.group(2).strip()
    except Exception:
        return db
    return db


def vendor_for(mac: str, oui_db: Dict[str, str]) -> str:
    p = normalize_mac(mac)
    if not p:
        return ""
    key = p.replace(":", "").upper()[:6]
    return oui_db.get(key, "")


@dataclass
class APInfo:
    bssid: str
    ssid: str
    channel: Optional[int] = None
    band: str = ""
    enc: str = "OPEN"
    wpa: str = ""
    rsn_akm: str = ""
    pmf: str = ""  # 802.11w / PMF: "required"/"capable"/"unknown"
    wps: str = ""  # "present"/"absent"/"unknown"
    rssi: Optional[int] = None
    vendor: str = ""
    first_seen: str = ""
    last_seen: str = ""
    beacons: int = 0
    probes: int = 0
    # Indicators
    ssid_collision_count: int = 0
    notes: str = ""


@dataclass
class ClientInfo:
    mac: str
    ap_bssid: str = ""
    rssi: Optional[int] = None
    vendor: str = ""
    first_seen: str = ""
    last_seen: str = ""
    frames: int = 0


class WiFiAudit:
    def __init__(self, iface: str, oui_db_path: str = "", hop: bool = True):
        self.iface = iface
        self.oui_db = load_oui_db(oui_db_path)
        self.hop = hop
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self.aps: Dict[str, APInfo] = {}
        self.clients: Dict[str, ClientInfo] = {}
        self._ssid_map: Dict[str, Set[str]] = {}  # ssid -> set(bssid)
        self._channel = None
        self._hop_thread: Optional[threading.Thread] = None

    def stop(self):
        self._stop.set()

    def _guess_rssi(self, pkt) -> Optional[int]:
        try:
            if pkt.haslayer(RadioTap):
                # Not always present; dBm_AntSignal can be None
                sig = pkt.dBm_AntSignal
                if isinstance(sig, int):
                    return sig
        except Exception:
            pass
        return None

    def _parse_channel_from_ies(self, pkt) -> Optional[int]:
        # Try DS Parameter Set (ID 3), HT Operation (ID 61), VHT Operation (ID 192)
        try:
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 3 and elt.info and len(elt.info) >= 1:
                    return int(elt.info[0])
                if elt.ID == 61 and elt.info and len(elt.info) >= 1:
                    # Primary channel is first byte in HT Operation
                    return int(elt.info[0])
                if elt.ID == 192 and elt.info and len(elt.info) >= 1:
                    # VHT Operation: first byte is channel width; not always primary
                    # Keep as fallback only if we don't have others
                    pass
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return None

    def _parse_security(self, pkt) -> Tuple[str, str, str, str]:
        """
        Returns (enc, wpa, rsn_akm, pmf)
        - enc: OPEN/WEP/WPA/WPA2/WPA3/MIXED
        - wpa: textual details
        - rsn_akm: detected AKM suites (best-effort)
        - pmf: required/capable/unknown
        """
        enc = "OPEN"
        wpa = ""
        rsn_akm = ""
        pmf = "unknown"

        # Capability flags can indicate WEP, but is unreliable for modern networks
        try:
            cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
            if "privacy" in (cap or "").lower():
                enc = "WEP/WPA?"
        except Exception:
            pass

        # Parse information elements
        has_rsn = False
        has_wpa = False
        akms: Set[str] = set()
        pmf_flags = None

        try:
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                # RSN element (ID 48)
                if elt.ID == 48 and elt.info:
                    has_rsn = True
                    # Best-effort RSN parsing without external libs
                    # RSN structure varies; we will only heuristically detect AKM and PMF bits when possible.
                    data = bytes(elt.info)
                    # PMF capabilities flags are in RSN Capabilities field (2 bytes) near the end.
                    # Full parse is complex; we'll do cautious minimal parse:
                    # We'll locate RSN Capabilities if possible by walking counts.
                    try:
                        # offset 0-1: Version
                        off = 2
                        # Group Cipher Suite: 4 bytes
                        off += 4
                        # Pairwise Cipher Suite Count (2)
                        if off + 2 > len(data):
                            raise ValueError
                        pcnt = int.from_bytes(data[off:off+2], "little")
                        off += 2
                        off += 4 * pcnt
                        # AKM Suite Count (2)
                        if off + 2 > len(data):
                            raise ValueError
                        acnt = int.from_bytes(data[off:off+2], "little")
                        off += 2
                        # AKM suites
                        for _ in range(acnt):
                            if off + 4 > len(data):
                                break
                            suite = data[off:off+4]
                            off += 4
                            # OUI + type
                            oui = suite[:3].hex()
                            stype = suite[3]
                            # Common RSN AKM types:
                            # 1=802.1X, 2=PSK, 8=SAE, 12=OWE, 18=SuiteB 192, etc.
                            if stype == 2:
                                akms.add("PSK")
                            elif stype == 8:
                                akms.add("SAE")
                            elif stype == 1:
                                akms.add("802.1X")
                            elif stype == 12:
                                akms.add("OWE")
                            else:
                                akms.add(f"AKM-{stype}")
                        # RSN Capabilities (2 bytes)
                        if off + 2 <= len(data):
                            pmf_flags = int.from_bytes(data[off:off+2], "little")
                    except Exception:
                        pass

                # WPA vendor IE (Microsoft OUI 00:50:f2, type 1)
                if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                    if elt.info[:3] == b"\x00\x50\xf2" and elt.info[3] == 1:
                        has_wpa = True

                # WPS vendor IE (Microsoft OUI 00:50:f2, type 4)
                if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                    if elt.info[:3] == b"\x00\x50\xf2" and elt.info[3] == 4:
                        # presence means WPS advertised
                        pass

                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass

        # PMF inference from RSN Capabilities bits (if present)
        # IEEE 802.11 RSN Capabilities: bit 6 MFPR, bit 7 MFPC
        if pmf_flags is not None:
            mfpr = bool(pmf_flags & (1 << 6))
            mfpc = bool(pmf_flags & (1 << 7))
            if mfpr:
                pmf = "required"
            elif mfpc:
                pmf = "capable"
            else:
                pmf = "not-supported"

        # Determine enc label
        if has_rsn and has_wpa:
            enc = "MIXED"
            wpa = "WPA+RSN"
        elif has_rsn:
            # WPA2/WPA3/OWE are under RSN
            if "SAE" in akms:
                enc = "WPA3"
                wpa = "RSN(SAE)"
            elif "OWE" in akms:
                enc = "OWE"
                wpa = "RSN(OWE)"
            elif "PSK" in akms:
                enc = "WPA2"
                wpa = "RSN(PSK)"
            elif "802.1X" in akms:
                enc = "WPA2-ENT"
                wpa = "RSN(802.1X)"
            else:
                enc = "WPA2/RSN"
                wpa = "RSN"
        elif has_wpa:
            enc = "WPA"
            wpa = "WPA"
        else:
            # If privacy bit set earlier, keep "WEP/WPA?"
            if enc == "OPEN":
                wpa = ""
            else:
                wpa = enc

        rsn_akm = ",".join(sorted(akms)) if akms else ""
        return enc, wpa, rsn_akm, pmf

    def _parse_wps(self, pkt) -> str:
        # Look for WPS vendor IE (00:50:f2:04)
        try:
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                    if elt.info[:3] == b"\x00\x50\xf2" and elt.info[3] == 4:
                        return "present"
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return "absent"

    def _band_from_channel(self, ch: Optional[int]) -> str:
        if ch is None:
            return ""
        if 1 <= ch <= 14:
            return "2.4GHz"
        if 32 <= ch <= 177:
            return "5GHz"
        if 1 <= ch <= 233:
            # could include 6GHz, but channel mapping varies; keep generic
            return ""
        return ""

    def _update_ssid_collisions(self, ssid: str):
        # For each SSID, count distinct BSSIDs
        ssid = ssid or ""
        bssids = self._ssid_map.get(ssid, set())
        cnt = len(bssids)
        for b in bssids:
            ap = self.aps.get(b)
            if ap:
                ap.ssid_collision_count = max(ap.ssid_collision_count, cnt)

    def _handle_ap(self, pkt):
        dot11 = pkt.getlayer(Dot11)
        if not dot11:
            return
        bssid = normalize_mac(getattr(dot11, "addr3", None))
        if not bssid:
            return

        ssid = ""
        try:
            # SSID in Dot11Elt ID 0
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0:
                    ssid = safe_decode(bytes(elt.info))
                    break
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            ssid = ""

        channel = self._parse_channel_from_ies(pkt)
        enc, wpa, rsn_akm, pmf = self._parse_security(pkt)
        wps = self._parse_wps(pkt)
        rssi = self._guess_rssi(pkt)
        vendor = vendor_for(bssid, self.oui_db)

        ts = now_iso()
        with self._lock:
            ap = self.aps.get(bssid)
            if not ap:
                ap = APInfo(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    band=self._band_from_channel(channel),
                    enc=enc,
                    wpa=wpa,
                    rsn_akm=rsn_akm,
                    pmf=pmf,
                    wps=wps,
                    rssi=rssi,
                    vendor=vendor,
                    first_seen=ts,
                    last_seen=ts,
                    beacons=1,
                )
                self.aps[bssid] = ap
            else:
                ap.last_seen = ts
                ap.beacons += 1
                if ssid and (not ap.ssid):
                    ap.ssid = ssid
                if channel is not None:
                    ap.channel = channel
                    ap.band = self._band_from_channel(channel)
                if enc and ap.enc == "OPEN":
                    ap.enc = enc
                if wpa and not ap.wpa:
                    ap.wpa = wpa
                if rsn_akm and not ap.rsn_akm:
                    ap.rsn_akm = rsn_akm
                if pmf and ap.pmf == "unknown":
                    ap.pmf = pmf
                if wps:
                    ap.wps = wps
                if rssi is not None:
                    ap.rssi = rssi
                if vendor and not ap.vendor:
                    ap.vendor = vendor

            # SSID collision tracking
            if ssid not in self._ssid_map:
                self._ssid_map[ssid] = set()
            self._ssid_map[ssid].add(bssid)
            self._update_ssid_collisions(ssid)

            # Notes: possible rogue indicator if SSID appears on many BSSIDs with different vendors
            if ap.ssid_collision_count >= 2:
                # If multiple vendors for same SSID
                vendors = {vendor_for(b, self.oui_db) for b in self._ssid_map.get(ssid, set())}
                vendors = {v for v in vendors if v}
                if len(vendors) >= 2:
                    ap.notes = (ap.notes + " " if ap.notes else "") + "SSID reused across different vendors (check for rogue/mesh)."

    def _handle_client(self, pkt):
        dot11 = pkt.getlayer(Dot11)
        if not dot11:
            return

        # Identify probable client MAC from addr1/addr2 based on ToDS/FromDS
        try:
            fc = dot11.FCfield
            to_ds = bool(fc & 0x1)
            from_ds = bool(fc & 0x2)
        except Exception:
            to_ds = from_ds = False

        addr1 = normalize_mac(getattr(dot11, "addr1", None))
        addr2 = normalize_mac(getattr(dot11, "addr2", None))
        addr3 = normalize_mac(getattr(dot11, "addr3", None))

        client_mac = ""
        ap_bssid = ""

        # Common cases:
        # - client -> AP (ToDS=1, FromDS=0): addr2=client, addr1=AP(BSSID)
        # - AP -> client (ToDS=0, FromDS=1): addr1=client, addr2=AP(BSSID)
        if to_ds and not from_ds:
            client_mac = addr2
            ap_bssid = addr1
        elif from_ds and not to_ds:
            client_mac = addr1
            ap_bssid = addr2
        else:
            # unknown; skip broadcast/multicast
            return

        if not client_mac or client_mac.startswith("ff:ff:ff") or client_mac.startswith("01:00:5e"):
            return
        if not ap_bssid or ap_bssid.startswith("ff:ff:ff"):
            ap_bssid = ""

        rssi = self._guess_rssi(pkt)
        vendor = vendor_for(client_mac, self.oui_db)
        ts = now_iso()

        with self._lock:
            c = self.clients.get(client_mac)
            if not c:
                c = ClientInfo(
                    mac=client_mac,
                    ap_bssid=ap_bssid,
                    rssi=rssi,
                    vendor=vendor,
                    first_seen=ts,
                    last_seen=ts,
                    frames=1,
                )
                self.clients[client_mac] = c
            else:
                c.last_seen = ts
                c.frames += 1
                if ap_bssid and not c.ap_bssid:
                    c.ap_bssid = ap_bssid
                if rssi is not None:
                    c.rssi = rssi
                if vendor and not c.vendor:
                    c.vendor = vendor

    def _packet_handler(self, pkt):
        if self._stop.is_set():
            return

        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                self._handle_ap(pkt)
            elif pkt.haslayer(Dot11):
                self._handle_client(pkt)
        except Exception:
            # Never crash due to malformed frames
            return

    def _set_channel(self, ch: int):
        # Best effort; iw may be required
        if ch is None:
            return
        res = sh(["iw", "dev", self.iface, "set", "channel", str(ch)], capture=True)
        if res.returncode != 0:
            sh(["iwconfig", self.iface, "channel", str(ch)], capture=True)

    def _channel_hop_loop(self, dwell: float, channels: List[int]):
        idx = 0
        while not self._stop.is_set():
            ch = channels[idx % len(channels)]
            try:
                self._set_channel(ch)
                self._channel = ch
            except Exception:
                pass
            time.sleep(max(0.2, dwell))
            idx += 1

    def start_channel_hop(self, dwell: float = 1.0, channels: Optional[List[int]] = None):
        if not self.hop:
            return
        if channels is None:
            # Default: 2.4GHz channels 1-13 plus common 5GHz
            channels = list(range(1, 14)) + [36, 40, 44, 48, 149, 153, 157, 161, 165]
        self._hop_thread = threading.Thread(
            target=self._channel_hop_loop,
            args=(dwell, channels),
            daemon=True
        )
        self._hop_thread.start()

    def run(self, duration: int, pcap_out: Optional[str] = None):
        # Scapy conf tweaks for stability
        try:
            conf.sniff_promisc = True
        except Exception:
            pass

        self.start_channel_hop()

        sniff_kwargs = {
            "iface": self.iface,
            "prn": self._packet_handler,
            "store": False,
            "timeout": duration,
        }

        # Optional: save to pcap for later analysis (passive only)
        if pcap_out:
            sniff_kwargs["offline"] = None  # ensure not set
            sniff_kwargs["stop_filter"] = lambda x: self._stop.is_set()

            # Use scapy's wrpcap via sniff's 'lfilter'? Not available.
            # We'll do simple: use tcpdump if available to capture concurrently.
            tcpdump_ok = (sh(["tcpdump", "--version"]).returncode == 0)
            tcp_proc = None
            if tcpdump_ok:
                tcp_proc = subprocess.Popen(
                    ["tcpdump", "-I", "-i", self.iface, "-w", pcap_out],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            try:
                sniff(**sniff_kwargs)
            finally:
                if tcp_proc and tcp_proc.poll() is None:
                    try:
                        tcp_proc.terminate()
                        tcp_proc.wait(timeout=2)
                    except Exception:
                        try:
                            tcp_proc.kill()
                        except Exception:
                            pass
        else:
            sniff(**sniff_kwargs)

    def snapshot(self) -> Tuple[List[APInfo], List[ClientInfo]]:
        with self._lock:
            aps = list(self.aps.values())
            clients = list(self.clients.values())
        return aps, clients

    def export_json(self, path: str):
        aps, clients = self.snapshot()
        data = {
            "generated_at": now_iso(),
            "iface": self.iface,
            "aps": [asdict(a) for a in aps],
            "clients": [asdict(c) for c in clients],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_csv(self, ap_path: str, client_path: str):
        aps, clients = self.snapshot()

        with open(ap_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(list(asdict(APInfo(bssid="", ssid="")).keys()))
            for a in aps:
                w.writerow([getattr(a, k) for k in asdict(a).keys()])

        with open(client_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(list(asdict(ClientInfo(mac="")).keys()))
            for c in clients:
                w.writerow([getattr(c, k) for k in asdict(c).keys()])


def banner():
    return r"""
__        ___ _ _     _         _ _ _
\ \      / (_) | |   | |  /\   (_) | |
 \ \ /\ / / _| | |   | | /  \   _| | |_ 
  \ V  V / | | | |   | |/ /\ \ | | | __|
   \_/\_/  |_|_|_|   |_/ ____ \| | | |_
                    /_/    \_\_|_|_|\__|

Passive WiFi Security Audit (Defensive) — no attacks, no cracking.
"""


def ensure_monitor_mode_hint(iface: str):
    # We do not automate monitor mode enabling (can disrupt network); just provide checks/hints.
    iw = sh(["iw", "dev"], capture=True)
    if iw.returncode == 0 and iw.stdout:
        # Best-effort parse type for iface
        block = iw.stdout.split("\n")
        in_iface = False
        itype = ""
        for line in block:
            line = line.strip()
            if line.startswith("Interface "):
                in_iface = (line.split(" ", 1)[1].strip() == iface)
                itype = ""
            elif in_iface and line.startswith("type "):
                itype = line.split(" ", 1)[1].strip()
                break
        if itype and itype != "monitor":
            print(f"[!] Interface '{iface}' type is '{itype}', not 'monitor'.")
            print("[!] Put your adapter into monitor mode before scanning (e.g., using iw/airmon-ng).")


def render_table(aps: List[APInfo], clients: List[ClientInfo], max_rows: int = 15) -> str:
    # Sort by RSSI (descending; higher is closer to 0), fallback beacons
    def rssi_key(x):
        return (x.rssi if x.rssi is not None else -999)

    aps_sorted = sorted(aps, key=lambda a: (rssi_key(a), a.beacons), reverse=True)
    clients_sorted = sorted(clients, key=lambda c: (rssi_key(c), c.frames), reverse=True)

    lines = []
    lines.append(f"Time: {now_iso()}   APs: {len(aps)}   Clients: {len(clients)}")
    lines.append("-" * 110)
    lines.append(f"{'BSSID':17}  {'CH':>2}  {'RSSI':>4}  {'ENC':10}  {'PMF':10}  {'WPS':8}  {'SSID':30}  {'Vendor'}")
    lines.append("-" * 110)

    for a in aps_sorted[:max_rows]:
        ch = a.channel if a.channel is not None else ""
        rssi = a.rssi if a.rssi is not None else ""
        ssid = (a.ssid or "")[:30]
        vendor = (a.vendor or "")[:22]
        enc = (a.enc or "")[:10]
        pmf = (a.pmf or "")[:10]
        wps = (a.wps or "")[:8]
        lines.append(f"{a.bssid:17}  {str(ch):>2}  {str(rssi):>4}  {enc:10}  {pmf:10}  {wps:8}  {ssid:30}  {vendor}")

    if aps_sorted:
        lines.append("-" * 110)
        # Show a few possible rogue/SSID collisions
        suspicious = [a for a in aps_sorted if a.ssid_collision_count >= 2 and a.notes]
        for a in suspicious[:5]:
            lines.append(f"[!] Note for {a.bssid} ({(a.ssid or '')[:24]}): {a.notes}")

    lines.append("")
    lines.append(f"{'Client MAC':17}  {'RSSI':>4}  {'Frames':>6}  {'Associated AP':17}  {'Vendor'}")
    lines.append("-" * 110)
    for c in clients_sorted[:max_rows]:
        rssi = c.rssi if c.rssi is not None else ""
        vendor = (c.vendor or "")[:30]
        ap = c.ap_bssid or ""
        lines.append(f"{c.mac:17}  {str(rssi):>4}  {c.frames:>6}  {ap:17}  {vendor}")
    return "\n".join(lines)


def clear_screen():
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def parse_args():
    p = argparse.ArgumentParser(
        description="Passive WiFi Security Audit Tool (Defensive) — scans APs/clients and exports reports.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--iface", required=True, help="Wireless interface already in monitor mode (e.g., wlan0mon)")
    p.add_argument("--duration", type=int, default=30, help="Scan duration in seconds")
    p.add_argument("--no-hop", action="store_true", help="Disable channel hopping")
    p.add_argument("--dwell", type=float, default=1.0, help="Channel dwell time seconds (when hopping)")
    p.add_argument("--channels", default="", help="Comma-separated channel list to hop (e.g., 1,6,11,36,40,44,48)")
    p.add_argument("--oui-db", default="", help="Optional OUI/vendor mapping file path")
    p.add_argument("--pcap", default="", help="Optional passive pcap output via tcpdump")
    p.add_argument("--json-out", default="wifi_audit.json", help="JSON report path")
    p.add_argument("--ap-csv", default="aps.csv", help="AP CSV path")
    p.add_argument("--client-csv", default="clients.csv", help="Client CSV path")
    p.add_argument("--live", action="store_true", help="Live console view (refreshes while scanning)")
    p.add_argument("--refresh", type=float, default=1.0, help="Live view refresh interval seconds")
    return p.parse_args()


def main():
    print(banner().rstrip())

    if not is_root():
        print("[!] This tool requires root for monitor-mode sniffing. Run with sudo/root.")
        sys.exit(1)

    args = parse_args()

    ensure_monitor_mode_hint(args.iface)

    channels = None
    if args.channels.strip():
        try:
            channels = [int(x.strip()) for x in args.channels.split(",") if x.strip()]
            channels = [c for c in channels if 1 <= c <= 196]
            if not channels:
                channels = None
        except Exception:
            channels = None

    audit = WiFiAudit(iface=args.iface, oui_db_path=args.oui_db, hop=(not args.no_hop))

    # Handle Ctrl+C cleanly
    def _sigint(sig, frame):
        audit.stop()
    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    # Live view thread
    live_thread = None
    if args.live:
        def live_loop():
            while not audit._stop.is_set():
                aps, clients = audit.snapshot()
                clear_screen()
                print(render_table(aps, clients))
                time.sleep(max(0.2, args.refresh))
        live_thread = threading.Thread(target=live_loop, daemon=True)
        live_thread.start()

    # Start hopping with custom channels if given
    if not args.no_hop:
        audit.start_channel_hop(dwell=args.dwell, channels=channels)

    # Run scan
    try:
        audit.run(duration=args.duration, pcap_out=(args.pcap if args.pcap else None))
    except PermissionError:
        print("[!] Permission error while sniffing. Ensure monitor mode and run as root.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Scan error: {e}")
    finally:
        audit.stop()

    # Final render
    aps, clients = audit.snapshot()
    if not args.live:
        print(render_table(aps, clients))

    # Export
    try:
        audit.export_json(args.json_out)
        audit.export_csv(args.ap_csv, args.client_csv)
        print(f"\n[+] Reports saved:")
        print(f"    - JSON: {args.json_out}")
        print(f"    - AP CSV: {args.ap_csv}")
        print(f"    - Client CSV: {args.client_csv}")
        if args.pcap:
            print(f"    - PCAP: {args.pcap}")
    except Exception as e:
        print(f"[!] Export error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
