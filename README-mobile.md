# Connecting a smartphone to the Security Check Lab

## Why 127.0.0.1 won't work on your phone

When you open `http://127.0.0.1:8080` on your phone, the browser resolves
`127.0.0.1` as **the phone itself** — not your development computer. You need
to reach your computer by its LAN IP address (e.g. `192.168.1.42`).

---

## Step 1 — Find your computer's LAN IP

**Windows (PowerShell):**
```
ipconfig
```
Look for the IPv4 Address under your active network adapter, e.g. `192.168.1.42`.

---

## Step 2 — Start the server in LAN mode

```
python serve.py --lan
```

This binds the server to `0.0.0.0` so it listens on all interfaces.

> **Security note**: Only do this on a trusted home or private Wi-Fi network.
> Do not run `--lan` on corporate, public, or shared networks.

Your phone can now open `http://192.168.1.42:8080` — but camera capture
**will not work** over plain HTTP (see Step 3).

---

## Step 3 — Enable HTTPS so the camera works

Mobile browsers only grant `getUserMedia` (camera access) in a **secure
context** (HTTPS). A plain `http://` LAN address is not a secure context.

### Option A — mkcert (recommended, no browser warning)

[mkcert](https://github.com/FiloSottile/mkcert) creates a locally trusted
certificate that your devices trust automatically.

**Install mkcert** (Windows, one-time):
```
winget install FiloSottile.mkcert
mkcert -install
```

**Generate a certificate** for your LAN IP:
```
mkcert 127.0.0.1 localhost 192.168.1.42
```
This creates `127.0.0.1+2.pem` and `127.0.0.1+2-key.pem`.

**Trust the root CA on your phone:**
1. Run `mkcert -CAROOT` to find the CA directory.
2. Copy `rootCA.pem` to your phone (AirDrop, cable, or email it to yourself).
3. On iPhone: Settings → Profile Downloaded → Install. Then go to Settings →
   General → About → Certificate Trust Settings and toggle the root CA on.
4. On Android: Settings → Security → Install a certificate → CA certificate,
   then select the file.

**Start the server with HTTPS:**
```
python serve.py --lan --https "127.0.0.1+2.pem,127.0.0.1+2-key.pem"
```

Your phone can now open `https://192.168.1.42:8080` and camera access will work.

### Option B — HTTP-only (no camera)

If you only need to test the form and audit pages (not camera capture), plain
HTTP is sufficient:
```
python serve.py --lan
```
The camera section will show a permission error; everything else works.

---

## Origin protection

When the server runs in LAN mode it accepts requests from any LAN device that
can reach it. The session ID (32 hex characters) acts as the primary secret:
anyone who guesses it could view or submit against that session, but the ID
is unguessable in practice. Do not run `--lan` on networks you don't control.

---

## Quick reference

| Goal | Command |
|---|---|
| Desktop only (default) | `python serve.py` |
| Phone access, no camera | `python serve.py --lan` |
| Phone access + camera | `python serve.py --lan --https "cert.pem,key.pem"` |
| Custom port | `python serve.py --port 9090` |
| LAN + HTTPS + custom port | `python serve.py --lan --https "cert.pem,key.pem" --port 9090` |
