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
- **Electron test launchers run from a scratch script** use `%APPDATA%\Electron` as userData, not the real app data.

## Not yet verified on real hardware
- A real connection through TUN to the user's server.
- Kill switch enable/disable through the app with the new `netsh` implementation.
- Routing by `process_name` for split tunneling.
