# SNISPF-HJ Android App

اپ اندروید برای SNISPF-HJ — بدون نیاز به Termux یا root.

## پیش‌نیازها

- JDK 17
- Android SDK (platform-tools, build-tools 34, platform-34)
- Python 3.8+ (برای Chaquopy build)
- اینترنت (برای دانلود Gradle و Chaquopy)

## ساختار

```
app/src/main/
├── python/
│   └── bridge.py          ← Python wrapper برای SNISPF-HJ
├── kotlin/com/snispf/android/
│   ├── MainActivity.kt    ← UI با Jetpack Compose
│   ├── SnispfViewModel.kt ← Business logic
│   └── SnispfService.kt   ← Foreground service
```

## Build

```powershell
# تنظیم ANDROID_HOME
$env:ANDROID_HOME = "C:\android-sdk"

# Build
.\gradlew.bat assembleDebug

# خروجی:
# app\build\outputs\apk\debug\app-debug.apk
```

## نصب روی دستگاه

```powershell
C:\android-sdk\platform-tools\adb.exe install app\build\outputs\apk\debug\app-debug.apk
```

## نکات مهم

1. **Chaquopy** کد Python را مستقیم داخل APK می‌برد — نیازی به Termux نیست
2. **Config** را از https://hjfisher.github.io/SNISPF-HJ-Configurator/ بساز و در تب کانفیگ paste کن
3. پروکسی روی `127.0.0.1:40443` گوش می‌دهد — این آدرس را در v2ray/clash/... تنظیم کن
4. اپ با یک **Foreground Service** در پس‌زمینه زنده می‌ماند

## معماری

```
[Compose UI] ←→ [SnispfViewModel] ←→ [Chaquopy bridge.py] ←→ [SNISPF-HJ Python]
```
