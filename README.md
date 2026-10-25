# YI IoT Clean (unofficial)

Independent cleanup/patch experiment for **YI IoT 5.1.8** (`com.yunyi.smartcamera`).

## Purpose
- Disable selected advertising SDK requests, interstitial/rewarded video ads and first-party ad UI methods.
- Keep camera streaming, login and device-control code paths untouched by the patch rules.
- This build has only passed static verification; **no physical-device runtime test** has been completed. Some redirects may remain.

## Project files
- `tools/build_mod.py`: patch/build routine (paths depend on original workspace).
- `tools/dexscan.py`: small DEX parser.
- `tools/validate_mod.py`: APK v2 signature, ZIP alignment and DEX checksum checks.
- `reports/build_report_public.json`: patch report without signing secrets.

**Original and modified proprietary APK binaries are not distributed in this repository.** Never commit keystores, keys or signing passwords.

## Rebuilding
Provide your own authorized original APKM package. The scripts require Python and `cryptography`; adjust the `/mnt/data` workspace paths before running them. A fresh build generates a new signing key: archive the private key securely for future compatible updates.

## Installing APKS
An `.apks` package contains multiple split APKs. Use an installer supporting split APKs, such as SAI. A re-signed build may require uninstalling the official app first; back up settings and ensure you know your login details.

## Limitations
- Not tested with a physical camera/phone.
- No guarantee that all ads or external links are blocked.
- Third-party trademarks belong to their owners; not affiliated with YI IoT or its vendor.
