# Linux coverage

## Launcher

```bash
chmod +x run-diagnoser.sh
./run-diagnoser.sh --days 7
sudo ./run-diagnoser.sh --days 7          # better dmesg/SMART access
./run-diagnoser.sh --llm                 # optional LM Studio on same machine/LAN
./run-diagnoser.sh --log-folder /var/log
```

## What is collected

| Source | Purpose |
|--------|---------|
| `journalctl -p err` (since N days) | Service/kernel errors |
| `dmesg` | Kernel ring buffer (I/O, GPU, lockups, OOM) |
| `/var/log/syslog`, `messages`, `kern.log`, `Xorg.0.log` | Classic logs |
| `/var/crash`, `coredumpctl list` | Userspace crash dumps |
| `smartctl -H` (if installed) | Disk health |
| `systemctl --failed` | Failed units |
| `lspci` VGA/3D lines | GPU identity |
| Disk free on `/`, `/var`, `/home`, `/tmp` | ENOSPC risk |

## Typical Linux failure maps

| Pattern | Area |
|---------|------|
| `oom-kill` / Out of memory | Memory |
| `I/O error`, `nvme … reset`, `ext4_error`, remount read-only | Storage |
| `hung_task`, `soft lockup`, `NMI watchdog` | Hang |
| `amdgpu` / `i915` reset, `NVRM`, `Xid` | GPU |
| `thermal` / Package temperature | Thermal |
| `segfault` / `Unable to handle kernel` | Crash |

## Permissions

- Without root: journal user session may be limited; `dmesg` may be restricted
  (`kernel.dmesg_restrict`); SMART often needs root.
- With root/sudo: fullest picture.

## Offline / other distros

Copy logs to a folder and run:

```bash
./run-diagnoser.sh --offline-only --log-folder /path/to/copied/logs --days 30
```
