# SNISPF-HJ Android

An Android app that runs [SNISPF-HJ](https://github.com/Rainman69/SNISPF) — a cross-platform SNI spoofing & DPI bypass tool — directly on your phone, with **no Termux, no root required**.

Powered by [Chaquopy](https://chaquo.com/chaquopy/), the Python engine is bundled inside the APK and managed through a native Jetpack Compose UI.

---

## How It Works

SNISPF sits between your apps and the internet. It intercepts the TLS ClientHello handshake and either fragments the SNI field across multiple TCP packets, or injects a decoy hello with an allowed hostname, so DPI firewalls cannot identify and block the real destination.

```
┌──────────┐     ┌─────────────┐     ┌──────────┐     ┌─────────────┐
│ Your App ├────>│  SNISPF-HJ  ├────>│ Firewall ├────>│ Real Server │
│ (v2ray,  │     │ (port 40443)│     │  (DPI)   │     │             │
│  clash…) │     │             │     │          │     │             │
└──────────┘     └─────────────┘     └──────────┘     └─────────────┘
                       │                   │
               sends fragmented     sees incomplete
               or fake SNI hello    SNI → lets it through
```

The proxy listens on `127.0.0.1:40443`. Point any proxy client (v2ray, clash, etc.) at that address.

---

## Project Structure

```
app/src/main/
├── python/
│   └── bridge.py              # Python wrapper around SNISPF-HJ core
├── kotlin/com/snispf/android/
│   ├── MainActivity.kt        # Jetpack Compose UI
│   ├── SnispfViewModel.kt     # Business logic / state management
│   └── SnispfService.kt       # Foreground service (keeps proxy alive)
├── build.gradle               # Chaquopy + Android build config
├── settings.gradle
└── gradle.properties
```

---

## Prerequisites

| Tool | Version |
|------|---------|
| JDK | 17 |
| Android SDK | platform-tools + build-tools 34 + android-34 |
| Python | 3.8+ (required by Chaquopy at build time) |
| Internet | needed to download Gradle and Chaquopy packages |

---

## Build

```bash
# Windows — set your Android SDK path
set ANDROID_HOME=C:\android-sdk

# macOS / Linux
export ANDROID_HOME=~/android-sdk

# Build debug APK
./gradlew assembleDebug          # Linux / macOS
.\gradlew.bat assembleDebug      # Windows
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

---

## Install

```bash
# Via ADB (USB or wireless)
adb install app/build/outputs/apk/debug/app-debug.apk
```

Or copy the APK to your device and install manually (enable "Install from unknown sources" in settings).

---

## Usage

1. **Generate a config** at [SNISPF-HJ Configurator](https://hjfisher.github.io/SNISPF-HJ-Configurator/).
2. Open the app and paste the config JSON into the **Config** tab.
3. Tap **Start** — the app launches a foreground service that keeps the proxy running in the background.
4. In your proxy client (v2ray, clash, etc.), set the upstream proxy to:
   ```
   Address: 127.0.0.1
   Port:    40443
   ```

---

## Architecture

```
[Compose UI]  ←→  [SnispfViewModel]  ←→  [Chaquopy / bridge.py]  ←→  [SNISPF-HJ Python core]
                         ↕
               [SnispfService (Foreground)]
```

Chaquopy embeds the Python interpreter and all SNISPF-HJ dependencies directly into the APK, so there is no dependency on Termux or any external Python installation.

---

## Upstream Project

This app is an Android frontend for **[SNISPF-HJ](https://github.com/Rainman69/SNISPF)** by [@Rainman69](https://github.com/Rainman69).

SNISPF supports three bypass methods:

| Method | Description |
|--------|-------------|
| `fragment` *(default)* | Splits the TLS ClientHello so no single packet contains the full SNI |
| `fake_sni` | Sends a decoy hello with an allowed hostname before the real one |
| `combined` | Both methods together — strongest option for aggressive DPI |

See the [upstream README](https://github.com/Rainman69/SNISPF#readme) for full configuration options.

---

## License

MIT — see [LICENSE](LICENSE) for details.
