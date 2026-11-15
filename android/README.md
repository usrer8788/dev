# Chalk Log for Android

A small Android app that hosts the tracker page (`../workout-tracker/index.html`) in a WebView and adds
the one thing a web page cannot do: read heart rate from Garmin's Connect Personal API.

## Get the APK

Every push that touches `android/` or `workout-tracker/` runs the **Android APK** workflow. Open the run
under the repository's Actions tab and download the `chalk-log-debug-apk` artifact, then install
`app-debug.apk` on your phone (allow installs from your browser or file manager when asked).

To build locally instead, with the Android SDK installed:

```bash
./gradlew assembleDebug
```

## Garmin heart rate

1. In the app, tap the watch icon (top right) and follow the steps to create a Personal API key at
   Garmin Connect, then paste it in.
2. Wear the watch while you train. After the watch syncs with Garmin Connect, the app reads that day's
   heart rate and attaches the part recorded between the workout's start and finish.

Garmin's Personal API is pull-only and serves data after a sync, so heart rate is not live. The key
expires after the period you choose (30 days to one year); create a new one and reconnect when it does.

How it is wired:

- `GarminBridge.kt` exchanges the key for a 24-hour access token
  (`POST /personalapitoken-service/personal-api/personal-api-key/token`, `Authorization: ApiKey <key>`),
  then calls `GET /wellness-service/wellness/dailyHeartRate?date=YYYY-MM-DD`.
- The key and token are encrypted with an Android Keystore key and never returned to the page.
- The page can only request paths on `personal.connectapi.garmin.com`.
