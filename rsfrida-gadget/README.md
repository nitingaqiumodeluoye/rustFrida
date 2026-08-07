# rsfrida Gadget

`librsfrida-gadget.so` is an ARM64 Android shared library that starts the
rustFrida agent inside the process that loads it. It does not require the
device-side `rustfrida-server` daemon.

Place the configuration next to the library as either:

- `librsfrida-gadget.config`
- `librsfrida-gadget.config.so` for Android APK packaging

Example configuration:

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 15819,
    "on_load": "resume"
  }
}
```

Start an APK containing Gadget and load a host-side script. The client first
uses `rustfrida-server` when one is available; otherwise it starts the package
through ADB and connects to the embedded Gadget automatically:

```powershell
.\rfclient-usb.exe -U -f com.example.app -l .\script.js
```

To connect directly to an already running Gadget for diagnostics:

```powershell
.\rfclient-usb.exe -U Gadget -l .\script.js
```

Set `on_load` to `wait` when the process must remain inside the library
constructor until the first Gadget client attaches.

When injected by `xfinjectd`, the library is staged under a randomized filename
and may not have a sidecar config. The built-in default is therefore
`on_load: resume`, using `127.0.0.1:15819`.

`xfinjectd` can also stage a stable config beside the payload:

```text
xfinjectd -pkg com.example.app \
  -lib /data/local/tmp/librsfrida-gadget.so \
  -app-file /data/local/tmp/librsfrida-gadget.config.so:librsfrida-gadget.config.so
```

When used through xfinject, keep the config at `on_load: resume`; a blocking
`wait` constructor prevents xfinject's `dlopen` handshake from completing.

## APK integration

Place both files in the APK ABI directory:

```text
lib/arm64-v8a/librsfrida-gadget.so
lib/arm64-v8a/librsfrida-gadget.config.so
```

Load the library from Java/Kotlin:

```java
System.loadLibrary("rsfrida-gadget");
```

It can also be added as a native library `DT_NEEDED` dependency so its
constructor runs during process startup.

The first version implements Frida Gadget's listen interaction and
`wait`/`resume` load behavior. It uses the rustFrida frame protocol, so connect
with `rfclient-usb.exe`; the official Frida clients are not protocol-compatible.
