# Leftik VPN

Desktop VPN client for Windows (Electron 44 + sing-box 1.14.3). VLESS + Reality: the app installs Xray on the user's own VPS over SSH (IP, login, password), then connects in TUN mode. Users talk in Russian; UI text, comments and replies are in Russian.

## Commands
- `npm install`: deps, plus `scripts/fetch-core.js` downloads sing-box.exe into `core/` (gitignored).
- `npm start`: run from source. TUN needs admin; the app offers a relaunch as admin.
- `npm run check`: self-test (vless links, split routing, kill switch rules, `sing-box check` on generated configs). Run after every change.
- `npm run dist`: NSIS installer in `dist/` (requireAdministrator, `npmRebuild: false` because ssh2's optional native dep needs MSVC).

## Layout
- `src/main/main.js`: window, IPC, connect, kill switch wiring.
- `src/main/singbox.js`: config builder (TUN -> VLESS, split tunneling rules) and the `Core` process manager.
- `src/main/installer.js`: SSH install script for Xray on the server. It runs only after the probe allows it.
- `src/main/probe.js`: read-only server probe run before installing, plus the decision logic. It reuses a working VLESS Reality (from Leftik, a foreign Xray, or an Amnezia Docker container with keys in `/opt/amnezia/xray/*.key`). It refuses to overwrite a foreign Xray config or a busy port unless "Переустановить заново" is on.
- `src/main/killswitch.js`: Windows Firewall kill switch via `netsh`.
- `src/main/store.js`: settings in `%APPDATA%\Leftik VPN\leftik.json`. SSH passwords are never stored.
- `src/renderer/`: UI (no framework, CSP `self` only).

## Hard-won lessons, keep them
- **No PowerShell in the connect or kill-switch path.** With outbound traffic blocked, PowerShell can hang on signature checks and the connect never starts. Use `netsh`, `tasklist`, `taskkill`, `reg`.
- **`netsh` output is localized** (for example «Состояние ВЫКЛЮЧИТЬ»). Read firewall state from the registry (`FirewallPolicy\*Profile`), never by parsing netsh text.
- **Kill switch allows the IPs of all saved VPN servers**, so the tunnel can always come up even if program-path rules mismatch.
- **Restore always sets outbound to allow.** `C:\ProgramData\LeftikVPN\restore-firewall.cmd` puts the firewall back; the uninstaller runs it too.
- **Disconnect must cancel a connect that has not spawned the core yet.** `Core.gen` handles this; the stray core is found via `core.pid`.
- **Decorative elements over buttons need `pointer-events: none`.** The power button was unclickable because of its rings. Tests that call `.click()` from JS miss this, so hit-test with `document.elementFromPoint`.
- **Never send server-side tool output to `/dev/null` without keeping the reason.** The official Xray installer prints its `error: …` to stdout, so the user only saw «код 1». The install script logs to `/tmp/leftik-xray-install.log` and fails through `fail "…"` (`[leftik] ОШИБКА: …`). `installError()` turns that into the message shown in the app. On a fresh VPS, wait for the apt/dpkg lock (`wait_pkg_lock`).
- **"Подключено" only after a real request went through the server.** `Core.verify()` sends HTTP through the service inbound `check-in` (127.0.0.1:9096). A route rule always sends it to `proxy`, ignoring split tunneling. If the request fails, the core is stopped and `explainCoreError()` explains why. The Clash API delay test is not used for this: its failures are not logged by the core.
- **Antivirus network filters break the tunnel.** Dr.Web SpIDer Gate redirects TCP :443 to 127.0.0.1. With the TUN interface binding, the dial fails with "requested address is not valid in its context". Without the binding, Reality fails with "reality verification failed". The fix is on the user's side: add `sing-box.exe` to the antivirus exclusions. WireGuard (UDP) is not affected, which is why AmneziaWG works on the same machine.
- **The server Xray is pinned to `XRAY_VERSION` (v26.6.27) in `installer.js`. Do not switch to "latest".** Since v26.9.8, the REALITY server rejects a ClientHello without an X25519MLKEM768 key share. sing-box strips that share, so the client logs "reality verification failed" (SagerNet/sing-box#4520, still open). Versions 26.7–26.9 also enforce a minClientVer by default. The probe reads the Xray version: Leftik's own Xray that is too new gets reinstalled (keys are kept). A foreign or Amnezia Xray that is too new is left alone, and the probe suggests "Переустановить заново" or another port. The install script also sets `net.mptcp.enabled=0`, because Xray before v26.10.31 enables MPTCP and unpatched kernels are exposed. Revisit the pin only when sing-box ships a fix.
- **The REALITY masking site must have a small certificate record.** REALITY in Xray 26.6.27 aborts the handshake when the target's Certificate TLS record is larger than 8192 bytes. The server then logs "REALITY: processed invalid connection … handshake did not complete successfully" and the client sees `EOF` (Xray-core#6356). `www.microsoft.com` returns about 8268 bytes because of the OCSP staple, so the default is `gateway.icloud.com` (`DEFAULT_SNI` in `probe.js`, about 3.2 KB). `checkMaskSite()` measures the record from the client through a local relay before installing. The probe reinstalls Leftik's own setups that use a site from `BAD_MASK_SITES`.
- **Electron test launchers run from a scratch script** use `%APPDATA%\Electron` as userData, not the real app data.

## Verified on real hardware
- A connection through TUN to a server installed by Leftik (Xray v26.6.27, masked as gateway.icloud.com), on 2026-11-03.

## Not yet verified on real hardware
- Kill switch enable/disable through the app with the new `netsh` implementation.
- Routing by `process_name` for split tunneling.
