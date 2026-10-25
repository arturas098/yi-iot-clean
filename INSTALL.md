# Install YI IoT Clean 5.1.8 on Android

## Download from Google Drive
Folder: https://drive.google.com/drive/folders/1JPxeCch4129TvX5j1ROlLaZnV1dMPZF8

The 274 MB APKS bundle exceeded the single-file upload limit of the available Google Drive integration. The tested alternative is a standard ZIP containing `YI_IoT_5.1.8_clean_arm64.apks`, divided into **7 parts** to upload:

`YI_IoT_Clean_5.1.8_complete.zip.001` through `.007`.

## On the phone
1. Download **all seven files** to the **same folder** (keep original filenames). You will need extra free space for extraction.
2. Install **ZArchiver** from Google Play (https://play.google.com/store/apps/details?id=ru.zdevs.zarchiver).
3. In ZArchiver, tap `YI_IoT_Clean_5.1.8_complete.zip.001` and choose **Extract**. It should automatically process the other six volumes.
4. The result is `YI_IoT_5.1.8_clean_arm64.apks`.
5. Install **SAI (Split APKs Installer)** (https://f-droid.org/packages/com.aefyr.sai/) and use **Install APKs** to choose that `.apks` file.

## Integrity checks
- Expected SHA-256 of the extracted `.apks` file: `0c0484654e0f420a81e56dd5c0c68310db35b9de49e7706979f8a87435a2176a`
- Expected SHA-256 of the ZIP after concatenating `.001` to `.007`: `f193d88b4710aad51aa341d4364d576c4d8eb6c5b03aa16d77751501811e138e`
- The ZIP's CRC passed validation before splitting, and a direct concatenation of the seven parts reproduced the original ZIP bit-for-bit.

## Caution
The app is re-signed; it usually cannot upgrade the original YI IoT installation directly. Back up settings and ensure you know your login details before uninstalling. The modified app has **not** been functionally tested on a phone/camera, and not every advertising redirect is guaranteed to be disabled.
