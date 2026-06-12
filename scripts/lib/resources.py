"""
Raspberry Pi 5 resource monitoring.

Uses /proc/stat two-sample delta for CPU (avoids top's platform-specific
output format), /proc/meminfo for RAM, and thermal_zone0 for temperature.
"""
import time
from pathlib import Path


def get_pi_resources() -> tuple[int, int, int]:
    """Return (cpu_pct, ram_pct, temp_celsius). All integers, never raises."""
    cpu_pct = _cpu_pct()
    ram_pct = _ram_pct()
    temp    = _temp_celsius()
    return cpu_pct, ram_pct, temp


def _cpu_pct() -> int:
    try:
        stat_path = Path("/proc/stat")
        s1 = stat_path.read_text().splitlines()[0].split()
        time.sleep(0.3)
        s2 = stat_path.read_text().splitlines()[0].split()
        t1 = sum(int(x) for x in s1[1:])
        i1 = int(s1[4])
        t2 = sum(int(x) for x in s2[1:])
        i2 = int(s2[4])
        td = t2 - t1
        if td <= 0:
            return 0
        return max(0, min(100, int((1 - (i2 - i1) / td) * 100)))
    except Exception:
        return 0


def _ram_pct() -> int:
    try:
        info: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                try:
                    info[k.strip()] = int(v.strip().split()[0])
                except (ValueError, IndexError):
                    pass
        total = info.get("MemTotal", 1)
        avail = info.get("MemAvailable", total)
        return max(0, min(100, int((1 - avail / total) * 100)))
    except Exception:
        return 0


def _temp_celsius() -> int:
    paths = [
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/devices/virtual/thermal/thermal_zone0/temp",
    ]
    for p in paths:
        try:
            raw = int(Path(p).read_text().strip())
            return raw // 1000
        except Exception:
            continue
    return 0


def resource_summary() -> str:
    cpu, ram, temp = get_pi_resources()
    return f"CPU:{cpu}%  RAM:{ram}%  TEMP:{temp}°C"


def is_overloaded(cpu_limit: int = 80, ram_limit: int = 85, temp_limit: int = 75) -> bool:
    cpu, ram, temp = get_pi_resources()
    return cpu > cpu_limit or ram > ram_limit or temp > temp_limit
