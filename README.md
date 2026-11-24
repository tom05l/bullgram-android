# Bullgram for Android

Builds the Bullgram APK from the **official Telegram for Android APK** (telegram.org standalone build),
patched by `patch_apk.py` to talk to the Bullgram server. Telegram for Android is GPL-2.0; the upstream
APK and our changes are published here.

- `upstream.json` pins the exact upstream APK (SHA-256) and apktool version.
- `patch_apk.py` documents every change; each step asserts its match count.
- GitHub Actions signs with the Bullgram key (repository secrets) and publishes a release.
