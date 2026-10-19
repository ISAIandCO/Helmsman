<p align="center"><a href="README.md">Русский</a> · <b>English</b></p>

<h1 align="center">Helmsman</h1>

<p align="center">
  <strong>VPN for Steam Deck — configure on the desktop, control from your game</strong>
</p>

<p align="center">
  <a href="https://github.com/ISAIandCO/Helmsman/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/ISAIandCO/Helmsman?display_name=tag"></a>
  <a href="https://github.com/ISAIandCO/Helmsman/actions/workflows/build.yml"><img alt="Build and checks" src="https://github.com/ISAIandCO/Helmsman/actions/workflows/build.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="GPL-3.0-only" src="https://img.shields.io/badge/license-GPL--3.0--only-blue"></a>
</p>

<p align="center">
  <a href="https://github.com/ISAIandCO/Helmsman/raw/refs/heads/main/Helmsman-Installer.desktop?v=2"><img alt="Download installer shortcut" src="https://img.shields.io/badge/Install_or_update_Helmsman-Download_shortcut-6750A4?style=for-the-badge&amp;logo=linux&amp;logoColor=white"></a>
  <br>
  <a href="https://github.com/ISAIandCO/Helmsman/releases/latest">Releases and manual installation</a>
  · <a href="#installing-on-steam-deck">Installation</a>
  · <a href="https://github.com/ISAIandCO/Helmsman/issues">Report an issue</a>
</p>

---

## What it is

**Helmsman** connects Steam Deck to your VPN, proxy or virtual network. Game and app traffic passes through a system tunnel, so you do not need to configure a proxy in each application.

**Desktop Mode** provides profiles, subscriptions, HWID, DNS and routing rules. In **Game Mode**, the main controls are in the **Decky Loader** sidebar. Both interfaces control a single background service: closing the window or switching modes keeps the connection running.

To get started, you need a provider subscription, a ready-made configuration or your own server. You can also create a Cloudflare WARP profile inside the app. Helmsman does not provide a paid VPN subscription.

## Features

- **Connections:** VLESS with REALITY and XHTTP, Hysteria2, WireGuard, AmneziaWG, OpenVPN and other common protocols.
- **Subscriptions:** manual or scheduled updates, HWID and device parameters as in NekoBox_SF. Failed updates preserve existing profiles.
- **Routes:** all internet through VPN or selective routing; regional presets for eight countries and custom “VPN / direct / block” rules.
- **Language and country:** Russian/English in Desktop and Decky, with an independent routing country selection.
- **DNS:** separate servers for VPN and direct queries, DoH/DoT presets and custom addresses.
- **WARP:** import WireGuard/AmneziaWG configurations, including warpgen, or create a profile inside the app.
- **ZeroTier:** connect to a virtual local network, with authorization status displayed.
- **For games:** home network access and Remote Play, MTU settings, recovery after sleep and network changes, and protection when VPN fails.

| Connection | Main capabilities |
| --- | --- |
| VLESS | REALITY, Vision, TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP through Xray |
| Hysteria | Hysteria2; Hysteria1 imports as a separate protocol |
| WireGuard / AmneziaWG | `.conf`, including WARP; AmneziaWG 1.0 / 1.5 / 2.0 |
| OpenVPN | Self-contained `.ovpn` with embedded keys and certificates; TLS, UDP/TCP |
| Other proxies | Shadowsocks, Trojan, VMess, TUIC v5, AnyTLS, SOCKS5, HTTP(S) CONNECT |
| ZeroTier | Virtual LAN; the network owner authorizes the device |

Only **one selected connection** runs at a time. ZeroTier is a separate virtual LAN mode, not a full internet tunnel; simultaneous use with VPN is not supported. HTTP CONNECT does not provide arbitrary UDP. See the [compatibility matrix](docs/COMPATIBILITY.md) for specific versions, formats and limitations.

---

## Installing on Steam Deck

You need **SteamOS on Steam Deck (x86_64)**, internet access and a user password for `sudo`. The archive includes the app and network engines. Decky Loader is needed only for Game Mode controls.

### Automatic — recommended

A single shortcut installs Helmsman or updates it to the **latest stable release**. You do not need to download a new shortcut for every update.

#### 1. Prepare your Steam Deck

1. Open **Steam → Power → Switch to Desktop**.
2. If you want Game Mode controls, install [Decky Loader from its official website](https://decky.xyz/).
3. Open **Konsole** from the application menu. If you have not set a user password yet, run:

```bash
passwd
```

Enter the new password twice. Terminal password input does not display characters; this is normal. Press **Steam + X** to open the on-screen keyboard while Steam is running.

#### 2. Download the installer shortcut

[![Download installer shortcut](https://img.shields.io/badge/Install_and_update-Download_.desktop-6750A4?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/ISAIandCO/Helmsman/raw/refs/heads/main/Helmsman-Installer.desktop?v=2)

Save **`Helmsman-Installer.desktop`** to your desktop. If the browser displays text instead of downloading, right-click the button and choose **Save Link As…**. If `.download` or `.txt` was appended to the name, remove that suffix: the file must end in `.desktop`.

#### 3. Run it

1. Double-click the **Install or update Helmsman** shortcut (it may appear as **«Установить или обновить Helmsman»** on a Russian desktop).
2. Allow execution if KDE asks. If it opens as text, select **Properties → Permissions → Is executable**, then launch it again.
3. Wait for the download in the terminal and enter your user password when `sudo` requests it.
4. After installation succeeds, close Konsole and open **Helmsman** from **KDE → Internet**. The terminal also stays open on failure so you can read the error.

The shortcut downloads the full archive and checksum from the same release, verifies **SHA256**, extracts it and runs the regular installer. The app, service and engines are installed in **`/opt/helmsman`**; profiles, HWID and other settings are preserved. If Decky Loader is already installed, its plugin is added or updated automatically. If you install Decky later, simply run the shortcut again.

**RW mode is enabled automatically for installation.** If the system was RO beforehand, the script restores RO when it finishes, including after installer errors. If it was already RW, it stays RW. You do not need to run `steamos-readonly` manually.

Installation does not start if downloading or SHA256 verification fails. The temporary archive is removed; it uses a cache in your home directory to avoid filling the small `/var` partition. Leave enough space on the data partition for downloading, extraction and installation — typically about 1 GiB beyond the installed version.

### Manual — installing from an archive

Use this method to install a specific version or to avoid the automatic shortcut. Switch to Desktop Mode, set a password with `passwd` and install Decky Loader if needed, as described above.

#### 1. Download and extract

Open the **[latest release](https://github.com/ISAIandCO/Helmsman/releases/latest)** and download these **Assets**:

- **`helmsman-1.0.0-linux-x86_64.tar.gz`** — the complete installation package;
- `SHA256SUMS` — checksums to verify your download.

The `source`, `engine-sources`, `runtime-sources` archives and GitHub's standard **Source code** downloads are for developers. The separate `helmsman-decky-…zip` is already included in the full package; you do not need to install it separately.

In Dolphin, open the folder containing the downloads, right-click empty space and select **Open Terminal Here**. Run:

```bash
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf helmsman-1.0.0-linux-x86_64.tar.gz
cd helmsman-1.0.0
```

The downloaded archive should be marked **OK**. Download it again if verification fails.

#### 2. Install and launch

**With the Decky Loader plugin:**

```bash
sudo bash ./install.sh --decky
```

**Desktop app only:**

```bash
sudo bash ./install.sh
```

Enter your user password and wait for successful installation. Open **Helmsman** by searching the KDE application menu or under **Internet**. Launch the window as a regular app, without `sudo`.

You can add the plugin later: install Decky Loader and repeat the Helmsman installation with `--decky`. You do not need to modify `homebrew/plugins` manually. Keep the extracted package for updating or uninstalling.

On stock SteamOS, manual installation into `/opt` and `/etc` works without disabling RO. The automatic shortcut manages RW/RO itself; this does not change the manual commands.

<details>
<summary><b>Where are files installed, and what happens after a SteamOS update?</b></summary>

- App and engines: `/opt/helmsman/versions`; `/opt/helmsman/current` points to the installed version.
- Profiles, subscriptions, HWID and WARP account: `/opt/helmsman/state`.
- Services: `/etc/systemd/system/helmsman.service` and `helmsman-guard.service`.
- Shortcut: `~/.local/share/applications/helmsman.desktop`.
- Plugin: `~/homebrew/plugins/helmsman`.

On stock SteamOS, `/opt` lives on writable storage and `/etc` uses a writable layer. The main installer does not modify `/usr`; the automatic shortcut temporarily switches RW and restores the previous mode. See the [/opt mount definition in steamos-customizations](https://github.com/evlaV/steamos-customizations/blob/master/offload/systemd/opt.mount.in) and the [Decky installer, which also registers a service in /etc](https://github.com/SteamDeckHomebrew/decky-installer/blob/main/cli/install_release.sh).

After a SteamOS update, check that the app and Decky still launch. If service registration is gone, rerun the installer shortcut or manual installation: settings in `/opt/helmsman/state` are preserved. A SteamOS recovery that erases the disk requires a separate backup.

The installer checks free space and essential system dependencies before replacing the working version. A nonstandard Linux installation may require `systemd`, `iproute2`, `nftables`, `setpriv`, Python 3, `/dev/net/tun` and graphics stack libraries. On SteamOS, you do not need to install Python/Qt or network engines separately to run the app. For a different user, run `sudo bash ./install.sh --user username`.

</details>

## First connection

### If you have a subscription link

1. Open **Subscriptions → Add**.
2. Enter a name and paste your provider's link into **HTTPS URL**.
3. If your provider binds access to a device, configure **HWID** as described below. Otherwise, leave **Do not send** selected.
4. Set **Update interval, h**: for example, `24` means daily, `0` means manual updates only.
5. Press **Save and update**. Imported connections appear under **Profiles**.

Manual updates are available in **Subscriptions → Update selected / Update all**, on the home page and in Decky. They use the same HWID and headers as scheduled updates. Download or parsing failures preserve previous profiles and the running tunnel.

### If you have a ready-made profile

Open **Profiles → Add**. Paste a link or configuration, or press **Open file…**. Supported input includes link lists/Base64, sing-box/Xray JSON, Clash Meta YAML/JSON with `proxies`, WireGuard/AmneziaWG/WARP `.conf`, self-contained OpenVPN `.ovpn` and supported Amnezia client `vpn://` exports.

### Enable VPN

1. Open **Connection** and choose a profile in **Selected connection**.
2. For the first connection, leave **All traffic via VPN** selected.
3. Press **Connect**, then **Check connection**.

The check contacts Steam Store with TLS verification. **VPN enabled** means the engine and system tunnel are running; the check result shows whether internet access through the profile works. It does not measure ping or test every UDP game.

You can now close the window and return to Game Mode. Press **Disconnect** in either interface to restore regular internet access.

## Subscriptions with HWID

HWID is a device identifier for the subscription service. Helmsman automatically creates a random persistent identifier; it does not collect hardware serial numbers. The identifier survives restarts and updates.

If your subscription already works in NekoBox_SF:

1. Open it through **Subscriptions → Edit**.
2. Under **Send HWID**, select **HWID / NekoBox_SF / Remnawave**.
3. Paste your NekoBox_SF parameters into **Parameters as in NekoBox_SF**. Format:

```text
hwid=YOUR_DEVICE_ID,os=Android,osVersion=16,model=YOUR_DEVICE_MODEL
```

These are fictional example values: replace them with your own. When filled in, only the listed fields are sent. When empty, the shared HWID and Steam Deck description are used.

4. Press **Save and update**.

View or replace the shared HWID under **Subscriptions → Device identifier · shared HWID**. **Custom HWID** sets a separate identifier for a subscription; a `hwid=…` parameter in the filled NekoBox_SF string takes priority. Use your existing HWID for an already registered device: a new identifier may consume another device slot with the provider.

Services have different requirements. If the provider requires a custom HTTP header or query parameter, choose that mode and set its name in advanced options. **User-Agent / response format** and additional HTTP headers are also available there. Change them according to your provider's instructions; there is no assumed universal HWID format.

## Language and country

The initial language is Russian. To switch to English, open **Настройки → Язык интерфейса → English** (Settings → Interface language; in Decky, **Дополнительно → Настройки**, meaning Advanced → Settings).

**Desktop → Settings** and **Decky → Advanced → Settings** provide **Interface language** (Русский / English) and **Routing country**. These settings are independent: you can use English with Russian routes. Both interfaces share the selection; it survives restarts and does not require reconnecting VPN. The other open interface picks up changes on its next status refresh.

Country determines the offered presets, not the VPN server's country. Select a server separately through a profile. Changing country **does not change the active route or user rules**: choose a new preset and press **Apply route**. Until then, the previous preset remains active even if it belongs to another country; the interface displays it separately. Selecting a preset without applying it also leaves the connection unchanged.

Updating an existing installation preserves Russian language, Russia, the previous preset, DNS, profiles, subscriptions, HWID and custom rules. There is no automatic country detection by IP. **Other country** offers a full tunnel and custom rules for countries outside the list.

## Choosing a route

Choose a route under **Connection → Traffic route** or in Decky. Read the selected preset's description using **ⓘ** on Desktop or below the list in Decky. Press **Apply route** to apply it; an active VPN connection restarts with the new rules.

| Preset | Through VPN | Direct |
| --- | --- | --- |
| **All traffic via VPN** | All internet by default | Allowed LAN and your exceptions |
| **Russia: selective** | Domains and IPs from community lists of restricted resources | Other internet traffic |
| **Russia direct** | Everything except Russian domains/IPs from the lists | Russian domains/IPs from the lists; the previous preset with unchanged rules |
| **[Country]: domains direct** | Everything except local domains | National domain zones; for Russia, China and Iran, domains from maintained lists as well. No GeoIP bypass |
| **[Country]: domains + IPs direct** | Everything except local domains and IPs | The same domains plus the selected country's GeoIP. Available for all included countries except Russia, where the existing “Russia direct” preset serves this purpose |
| **My rules** | According to your rules | According to your rules; the default for remaining traffic is configured in Settings |

Supported countries: **Russia, China, Iran, Belarus, Turkey, Vietnam, Myanmar and Turkmenistan**. The narrower domain preset allows access to local sites without a broad shared-CDN exception. The IP variant helps local services accessed without a domain name, but GeoIP may also send a foreign service on a local CDN directly. For Belarus, Turkey, Vietnam, Myanmar and Turkmenistan, the domain exception covers only the national domain zone: local `.com` and other domains may still use VPN. For extensive blocking, start with a full tunnel and add only necessary exceptions.

User rules are preserved in every preset. Service DNS/IPv6 rules and allowed LAN come first, then your rules from top to bottom, then preset rules and the default route. **All traffic via VPN** therefore respects your exceptions. Regional rules use the same sing-box compiler for regular protocols, WG/AWG and Xray transport; internet presets do not apply in ZeroTier mode.

Rule sources:

- Russia: [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat), `ru-blocked` / `ru-ip-blocked`, `category-ru` / `geoip-ru`. Existing Russian presets are preserved.
- China: [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite), `geosite-cn`, including regional CDN domain expressions.
- Iran: [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules), `geosite-ir`.
- IPs for the other seven countries: [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip), `geoip-<country code>`. National domain zones, including available IDNs, are defined in the app.

These are community routing references, not an exact map of current blocking or a guarantee of access. The country selection is based on [Freedom on the Net 2025](https://freedomhouse.org/report/freedom-net/2025/uncertain-future-global-internet), [OONI](https://explorer.ooni.org/countries) data and the availability of compatible rule sources. Independent region selection and local address bypass follow the approach in [Hiddify](https://github.com/hiddify/hiddify-app/blob/main/lib/features/route_rules/notifier/rules_notifier.dart). Blocking data is not used to select a server automatically.

Lists download when you first apply a preset that needs them, then update every 24 hours. Change the interval under **Settings → Network and recovery options**; manual updates are available under **Address lists**. Failed updates preserve the downloaded version. A new preset is not applied until every required list has downloaded successfully; the previous route stays active. GitHub must be reachable through the current network/connection; if a source is blocked, first use a full tunnel with a working VPN.

### DNS for regional routes

Direct domain exceptions use **Direct DNS**, while other traffic uses **DNS through VPN** (the default route is direct in Russia's selective mode). Before matching IP lists, the engine resolves the real address so FakeIP does not interfere with GeoIP. Only domain parts of lists, including `domain_regex`, are projected into DNS; IP conditions stay in routing. Country selection does not replace your DNS settings: check that the selected DoH/DoT and bootstrap DNS are reachable in your network. With LAN access enabled, LAN and `.local` / `.lan` / `.home.arpa` are handled before regional rules.

### Custom exceptions

For example, to send a particular site directly:

1. Open **Rules → Add**.
2. Choose **Domain and subdomains** and enter the domain without `https://` or a path.
3. Select **Direct** and save.

You can also create rules for an exact domain, IP/CIDR, address set or port. Reorder by dragging or using **Move up / Move down**, then press **Apply order**. The first matching rule wins. **Through selected VPN** always uses the profile from the home page.

Add custom lists under **Address lists**: one domain or CIDR per line, sing-box source JSON or SRS over HTTPS. Copy its ID for a **Domain / IP rule set** rule. To edit a built-in list, create a user copy.

Linux process name/path rules are available, but detection is not guaranteed for Proton/Wine, Flatpak and game child processes. Use a domain/IP exception or a full tunnel for reliable game-server routing.

## DNS and your home network

**Settings** has two independent panels:

- **DNS through VPN** — for queries routed through the connection;
- **Direct DNS** — for direct traffic.

Choose a preset or a custom server:

| Service — DoH and DoT presets | Filtering |
| --- | --- |
| [Cloudflare](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/) | Unfiltered |
| [Quad9](https://docs.quad9.net/services/) | Malicious domains |
| [Google](https://developers.google.com/speed/public-dns/docs/secure-transports) | Unfiltered |
| [AdGuard](https://adguard-dns.io/en/public-dns.html) | Ads and trackers |

If unsure, keep the defaults: Cloudflare DoH through VPN and Quad9 DoH for direct queries. Availability depends on the network. If filtering interferes with a game, try an unfiltered option.

Custom servers support **DoH** (`https://dns.example/dns-query`) and **DoT** (`tls://dns.example` or `dot://dns.example`), including custom ports. Press **Save and apply**: an active connection restarts. Certificates are verified; an unavailable server does not silently fall back to plain DNS.

**Network and recovery options** contains **Bootstrap DNS (UDP, IP)**, defaulting to `9.9.9.9`. It directly resolves VPN and DNS server names without encryption before the connection is established. With LAN enabled, local `.lan`, `.local`, `.home.arpa` queries also go there; you can use your router's IP for home names. DNS inside a WG/AWG profile takes priority over the general VPN DNS setting; remove it through **Profiles → Edit** if necessary.

**LAN access and Remote Play** is enabled by default: home addresses and device discovery remain direct. Turning it off makes them follow the other rules. IPv6 has a separate toggle; when off, IPv6 traffic is blocked. Helmsman does not change system DNS in ZeroTier mode.

## Game Mode and Decky Loader

1. Return to Game Mode and press **…**.
2. Open the Decky tab with the plug icon, then **Helmsman**.
3. Select a profile; if needed, choose a route and press **Apply route**, then **Connect**.

Disconnect, subscription updates, status and error reasons are available here too. Controls support buttons and sticks. **Advanced** contains language and country selection, auto-connect, VPN checks and WARP creation; entering long links and detailed rules is easier in Desktop Mode.

**Connect on startup is off by default.** Enable it under **Decky → Advanced → Auto-connect** or **Desktop → Settings → Connect on Steam Deck startup**. The selected profile then connects when the device next starts, even if you disconnected it manually before shutting down. Opening the window/plugin alone does not enable VPN.

<details>
<summary><b>How do I create WARP or connect ZeroTier?</b></summary>

### Cloudflare WARP

1. Open **Profiles → Cloudflare WARP** or the WARP option in Decky's advanced actions.
2. Select **AmneziaWG (obfuscated)** — the default — or regular WireGuard.
3. Enter a custom endpoint if needed.
4. Read and accept the Cloudflare terms, then press **Create profile**.
5. Select the new profile on the home page and connect.

The generator uses wgcf; the account and keys are saved locally and reused. Registration and endpoint availability depend on Cloudflare and your network. You can also import a ready-made WARP `.conf`, including warpgen AmneziaWG configurations with `I1`. MASQUE and corporate Zero Trust registration are not supported.

### ZeroTier

1. Open **Profiles → ZeroTier network** and enter the Network ID.
2. Select the profile and press **Connect**.
3. For a private network, send the displayed **Node ID** to its owner or authorize the device yourself in ZeroTier Central.

Helmsman shows authorization pending until approval. `ACCESS_DENIED` means authorization is needed, `REQUESTING_CONFIGURATION` means it is waiting for the controller, and `NOT_FOUND` means an incorrect or missing Network ID.

This mode provides a virtual LAN and device access. Regular internet traffic stays direct; internet presets, DNS and the controller's default/global routes are not applied. SSO networks are not supported.

</details>

## Connection loss, sleep and games

**Block direct access if VPN fails** is enabled by default. If the tunnel crashes, external traffic is blocked until recovery, including traffic that a selective preset normally sends directly. Allowed LAN stays available. The service attempts to restore an enabled connection after failures, sleep and network changes; this is independent of the connect-on-startup option.

**Disconnect removes protection and restores regular internet access.** Also use it to sign into a public Wi-Fi captive portal. Disabling protection in Settings may allow direct internet access if the tunnel fails.

Do not enable another VPN at the same time. Online games require a protocol and server with UDP support. If downloads, voice chat or particular games stall, try MTU `1280–1380` in advanced settings. VPN does not guarantee lower latency or anti-cheat compatibility.

## Updates, removal and backup

**Automatic updates:** in Desktop Mode, reopen **Install or update Helmsman**. The shortcut downloads the latest stable release and installs it over the current version, including the plugin if Decky Loader is found. The same action helps restore the service after a SteamOS update.

**Manual updates:** download a new full archive, extract it and repeat the same installation command. To update the app and plugin together:

```bash
sudo bash ./install.sh --decky
```

Profiles, subscriptions, HWID, rules and the WARP account are preserved. The service restarts; if the new service fails to start, the installer restores the previous version when available. Close the old app window and open Helmsman again. Old versions remain under `/opt/helmsman/versions`; after checking the new one, you may remove unused directories except the one targeted by `current`.

**Uninstalling:** use `uninstall.sh` from the full release archive. If you installed using the shortcut, download and extract the archive following the [manual instructions](#manual--installing-from-an-archive); you do not need to run `install.sh` to uninstall. In the extracted package folder, run:

```bash
sudo bash ./uninstall.sh
```

This removes the app, services and plugin and releases network resources. Settings are kept for reinstallation. To also delete profiles, HWID and keys, use **`sudo bash ./uninstall.sh --purge`**.

For a backup, save `/opt/helmsman/state` with root permissions after disconnecting VPN and stopping the service. It contains private links and keys: keep the backup secret. Restart the service after copying.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| **Installer window immediately closes / trap error** | Replace an older `.desktop` with a fresh shortcut using the button above. The fixed shortcut keeps Konsole open. |
| **No connection to service** | Rerun the installer shortcut or manual installation. Diagnostics: `systemctl status helmsman` and `journalctl -u helmsman -b`. |
| **VPN enabled but no internet** | Press “Check connection”; check subscription expiry, selected server, device clock and DNS. Try another profile. |
| **Subscription fails to update / App not supported** | Check HWID, device limits and User-Agent against your provider's instructions. That profile name may be a service response from the provider. Do not remove `fm` or `pinSHA256` parameters from working links: the app handles supported variants. |
| **Decky plugin missing** | Make sure Decky is installed, then rerun the installer shortcut or `install.sh --decky`. Restart Decky Loader or the device. The separate plugin ZIP does not install the system service. |
| **Home device unreachable** | Enable LAN; check for overlapping subnets. For ZeroTier, check Node ID authorization. |
| **Read-only file system during installation** | Rerun the automatic shortcut and check its RW switch message. This is unexpected during manual installation on stock SteamOS. Check `findmnt -T /opt` and `findmnt -T /etc`: writable storage is required. Include your SteamOS version and the failing path in an issue. |
| **No space left on device** | Free space on the data partition containing the home cache and `/opt`; the installer shows the required size. Updates need space for both the new and previous versions. |

If the network remains blocked after a failure, press **Disconnect** or run:

```bash
sudo /opt/helmsman/current/Helmsman ctl disconnect
```

If the service itself is damaged, `uninstall.sh` performs independent cleanup of Helmsman resources.

<details>
<summary><b>Early alpha versions and read-only mode</b></summary>

Updates from alpha.3 and later preserve settings. Settings from alpha.2 under `/var/lib/helmsman` are not migrated automatically; the old directory remains for manual recovery. If an interrupted alpha.2 installation filled `/var`, remove only the old app copy with `sudo rm -rf -- /var/lib/helmsman-app`, then repeat installation. This command does not touch `/var/lib/helmsman` settings.

If you previously disabled root image protection specifically for Helmsman, restore it with `sudo steamos-readonly enable`. If it was disabled for other software, consider that software's requirements. [Valve's guide to Desktop Mode and image protection](https://help.steampowered.com/ru/faqs/view/671A-4453-E8D2-323C).

</details>

## Privacy and feedback

Subscriptions, HWID and keys are stored locally in `/opt/helmsman/state`. HWID and device parameters are sent to the subscription service using your chosen method. Regular diagnostic logs do not include private URLs, subscription contents or keys.

When opening **[GitHub Issues](https://github.com/ISAIandCO/Helmsman/issues)**, include your Helmsman version, SteamOS version, protocol and reproduction steps. You can copy a report from **Diagnostics**. Review profile names and screenshots before publishing; do not attach a private subscription, HWID, full configuration or keys.

## Technical information and licence

Set the application version only in the root [`VERSION`](VERSION) file. Desktop/service and User-Agent versions, Python package metadata, the installed Decky plugin version, archive names and release tag are derived automatically. Do not edit versions manually in other files. Builds run only manually: **Actions → Build and release Helmsman → Run workflow**. Changes to code, `VERSION`, documentation and pull requests never start builds automatically. Select the `main` branch to publish a release.

[Country selection and rule source details](docs/REGIONAL_ROUTING.md).

[Protocol and import compatibility](docs/COMPATIBILITY.md) · [Checks and Steam Deck testing steps](docs/TESTING.md) · [Architecture](docs/ARCHITECTURE.md) · [Component licences](THIRD_PARTY.md).

GitHub Actions builds the app and plugin and checks import/HWID, local protocols, TUN/DNS/UDP, crash protection, the shared service, installation/updates/removal and the GUI. Physical Steam Deck hardware, real providers, sleep and individual games require device testing; automated checks do not replace these trials.

The downloadable `.desktop` installer/updater shortcut follows the example of [SDWEAK](https://github.com/Taskerer/SDWEAK). Helmsman's automation uses existing GitHub Releases and does not require a new app build.

Helmsman is distributed under **GPL-3.0-only**. It uses sing-box, the Throne fork, Xray-core, wgcf and ZeroTier Agent; corresponding sources and licences are included in releases. ZeroTier ships without the nonfree controller, and Qt/PySide6 is dynamically linked. The complete archive already contains the required engines.
