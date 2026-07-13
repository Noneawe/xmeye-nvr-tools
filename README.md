# XMEye NVR/DVR — standalone tools

Standalone Python scripts for talking directly to NVR/DVR devices on the
XMEye firmware family (also known as NetSurveillance, Sofia, or DVRIP — TCP
port 34567), outside of Home Assistant. Recon tools, live monitoring, and
archive/snapshot retrieval.

This is the companion repo to
**[ha-xmeye-nvr](https://github.com/Noneawe/ha-xmeye-nvr)**, the Home
Assistant integration for the same device family. That integration
deliberately ships with no archive-download or scheduled-snapshot features,
to stay focused on live monitoring — the scripts here fill that gap for
anyone who wants CLI tools instead (or in addition).

Deep protocol notes shared with the integration (channel-numbering quirks,
login/hash details, known firmware limitations) live in
[ha-xmeye-nvr's `PROTOCOL_NOTES.md`](https://github.com/Noneawe/ha-xmeye-nvr/blob/main/PROTOCOL_NOTES.md)
rather than being duplicated here.

## Requirements

- Python 3.10+
- Most scripts use only the standard library.
- Scripts that decode video frames (see table below) need
  [PyAV](https://pyav.org/) and Pillow:

  ```
  pip install -r requirements.txt
  ```

All scripts take `--host`/`--user`/`--password` on the command line — none
of them have credentials or IPs hardcoded. Run any script with `--help` for
its full option list; each also has a detailed module docstring explaining
what it does and why.

## Where to start

- **New/unknown device?** Run `identify_nvr.py` first (port scan + login +
  device info), then `rtsp_probe.py` to find a working RTSP URL.
- **Want periodic snapshots from archived footage** (e.g. one photo every
  minute for a time range)? Use `periodic_snapshots.py`.
- **Want photos from right after each motion/alarm event?** Use
  `alarm_snapshots.py` — it finds alarm recordings for a day/channel and
  pulls a burst of snapshots starting at the moment each one ends.
- **Want to watch alarms happen live** (motion/face/person detection, as
  they're pushed by the device)? Use `alarm_listen.py`.

## All scripts

| Script | Category | What it does | Extra deps |
|---|---|---|---|
| `identify_nvr.py` | Discovery | Port scan + HTTP banner grab + DVRIP login + `SystemInfo` dump. Start here for any new device. | — |
| `rtsp_probe.py` | Discovery | Tries a list of known RTSP URL conventions (XMEye/Dahua/Hikvision/ONVIF-style) against the device and reports which one(s) return a valid stream. | — |
| `channel_status.py` | Discovery | Dumps `NetWork.ChnStatus` (per-channel Connected/Offline/NoConfig) and `ChannelTitle` (configured channel names). Useful to see which channels actually have cameras attached. | — |
| `snapshot_probe.py` | Discovery (dead end, documented) | Tries the dedicated `OPSNAP` snapshot command. On the devices this was built against, it's blocked by the firmware (`Ret=108`) regardless of account permissions — kept as a documented negative result, and as a template for testing whether your own device's firmware supports it. | — |
| `concurrent_sessions_test.py` | Discovery | Runs status polling, alarm listening, and RTSP probing in parallel for a while, to confirm your device tolerates multiple simultaneous DVRIP/RTSP connections without one blocking another (relevant if you're also running the Home Assistant integration against the same device). | — |
| `alarm_listen.py` | Live monitoring | Subscribes to push alarm events (`AlarmSet`/`AlarmInfo`) and prints them as they happen — motion, face, person detection, with channel and start/stop status. Runs in the foreground until interrupted. | — |
| `opmonitor_probe.py` | Live monitoring | Pulls raw video via the native `OPMonitor` protocol (the same mechanism the official Windows client uses) instead of RTSP. Mostly useful as a reference/fallback if RTSP misbehaves on a given device. | — |
| `rtsp_record.py` | Live monitoring | Records N seconds from an RTSP URL to a file (remux, no re-encoding) and reports which streams/codecs were actually found — handy for confirming a stream works end-to-end after `rtsp_probe.py` finds a candidate URL. | `av`, `pillow` |
| `snapshot_from_opmonitor.py` | Snapshot | One live snapshot via `OPMonitor` (works even on devices where `OPSNAP` is blocked). | `av`, `pillow` |
| `periodic_snapshots.py` | Snapshot | One JPEG every N minutes/seconds, from **archived** recordings (not live), for a given channel/date/time-window. The main tool for building a timelapse or periodic record after the fact. | `av`, `pillow` |
| `alarm_snapshots.py` | Snapshot | Finds every alarm recording for a channel/day and pulls a burst of JPEGs starting at the moment each one ends, at a configurable interval (e.g. one every 5 seconds for 30 seconds after). Reuses `periodic_snapshots.py`'s decoding logic — keep both files together. | `av`, `pillow` |
| `alarm_photos.py` | Snapshot | Given a specific recording file (from `playback_download.py`'s search), pulls N photos at fixed intervals from within it. Lower-level building block; `alarm_snapshots.py` is the easier way to get "photos after an alarm" for a whole day. | `av`, `pillow` |
| `daily_timelapse.py` | Snapshot (superseded) | The original fixed-1-minute-step version of `periodic_snapshots.py`, for a full day. Kept for reference; `periodic_snapshots.py` does the same thing with a configurable step and time window. | `av`, `pillow` |
| `playback_download.py` | Archive | Searches recordings (`OPFileQuery`) and downloads a specific file's raw stream to disk. The lower-level tool the snapshot scripts above are built on. | — |

## A note on patience

Archive playback on these devices can be **very slow and bursty** — transfers
with gaps of tens of seconds between chunks are normal, not a hang. The
scripts here are written with that in mind (generous timeouts, resumable
runs that skip already-downloaded output, retry-on-disconnect where it
matters). Don't assume something is broken just because it's slow; let it
run.

## License

[MIT](LICENSE)
