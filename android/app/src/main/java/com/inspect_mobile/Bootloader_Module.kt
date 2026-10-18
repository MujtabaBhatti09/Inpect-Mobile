package com.inspect_mobile

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.display.DisplayManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.os.Environment
import android.os.Process
import android.os.StatFs
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telephony.TelephonyManager
import android.view.accessibility.AccessibilityManager
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableArray
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Calendar

/**
 * Self-diagnostic that mirrors what banking apps validate on-device.
 * Each check returns pass / fail / warn / info. `blocking` marks checks that
 * typically make a bank app refuse to run.
 *
 * NOTE: on-device checks are telemetry. The real gate banks use is the Play
 * Integrity verdict decoded on their server; see the SERVER rows.
 */
class BootloaderCheckModule(private val ctx: ReactApplicationContext) :
    ReactContextBaseJavaModule(ctx) {

    override fun getName() = "BootloaderCheck"

    // ------------------------------------------------------------------ report

    private class Report {
        val items: WritableArray = Arguments.createArray()
        var pass = 0
        var fail = 0
        var warn = 0
        var info = 0
        var blockingFail = 0

        fun add(
            id: String, cat: String, title: String, status: String,
            detail: String, blocking: Boolean,
        ) {
            items.pushMap(Arguments.createMap().apply {
                putString("id", id)
                putString("category", cat)
                putString("title", title)
                putString("status", status)
                putString("detail", detail)
                putBoolean("blocking", blocking)
            })
            when (status) {
                "pass" -> pass++
                "fail" -> { fail++; if (blocking) blockingFail++ }
                "warn" -> warn++
                else -> info++
            }
        }

        fun check(
            id: String, cat: String, title: String, blocking: Boolean = false,
            fn: () -> Pair<String, String>,
        ) {
            val (s, d) = try {
                fn()
            } catch (e: Throwable) {
                "info" to "Could not evaluate: ${e.message ?: e.javaClass.simpleName}"
            }
            add(id, cat, title, s, d, blocking)
        }
    }

    private class Tlv(val cls: Int, val tag: Int, val start: Int, val end: Int)

    private class Attestation(
        val locked: Boolean?,
        val bootState: String?,
        val securityLevel: String?,
        val osPatch: Int?,      // yyyyMM
        val vendorPatch: Int?,  // yyyyMMdd
        val bootPatch: Int?,    // yyyyMMdd
        val chainLength: Int,
        val error: String?,
    )

    // ------------------------------------------------------------------ entry

    @ReactMethod
    fun check(promise: Promise) {
        Thread {
            try {
                promise.resolve(runAll())
            } catch (e: Throwable) {
                promise.reject("E_BOOTLOADER_CHECK", e.message, e)
            }
        }.start()
    }

    private fun runAll(): com.facebook.react.bridge.WritableMap {
        val r = Report()
        val pm = ctx.packageManager
        val cr = ctx.contentResolver
        val att = attest()

        val flashLocked = getProp("ro.boot.flash.locked")
        val vbmetaState = getProp("ro.boot.vbmeta.device_state")
        val vbState = getProp("ro.boot.verifiedbootstate")
        val propsUnlocked: Boolean? = when {
            flashLocked == "0" || vbmetaState == "unlocked" || vbState == "orange" -> true
            flashLocked == "1" || vbmetaState == "locked" || vbState == "green" -> false
            else -> null
        }

        // ============================ INTEGRITY ============================
        val I = "INTEGRITY"
        r.check("bootloader", I, "Bootloader locked (hardware attestation)", true) {
            when (att.locked) {
                true -> "pass" to "RootOfTrust.deviceLocked = true"
                false -> "fail" to "RootOfTrust.deviceLocked = false. Play Integrity MEETS_DEVICE_INTEGRITY needs a locked bootloader on Android 13+."
                null -> when (propsUnlocked) {
                    false -> "warn" to "Attestation unavailable (${att.error}); properties say locked."
                    true -> "fail" to "Attestation unavailable (${att.error}); properties say unlocked."
                    null -> "warn" to "Could not determine (${att.error})."
                }
            }
        }
        r.check("verified_boot", I, "Verified boot state", true) {
            when (att.bootState) {
                "Verified" -> "pass" to "Verified (green): OS signed by the manufacturer key."
                null -> "warn" to "Not available from attestation. Property: ${vbState ?: "n/a"}"
                else -> "fail" to "${att.bootState}. Expected Verified."
            }
        }
        r.check("hw_attestation", I, "Hardware-backed key attestation", true) {
            when (att.securityLevel) {
                "TrustedEnvironment", "StrongBox" ->
                    "pass" to "${att.securityLevel}, certificate chain length ${att.chainLength}."
                "Software" -> "fail" to "Software-only attestation. Not hardware backed."
                else -> "warn" to (att.error ?: "Unknown security level.")
            }
        }
        r.check("props_consistency", I, "Properties agree with attestation") {
            if (att.locked == null || propsUnlocked == null) {
                "info" to "Cannot compare (attestation or properties missing)."
            } else if (att.locked == propsUnlocked) {
                "warn" to "Attestation and ro.boot.* disagree. Possible property spoofing."
            } else {
                "pass" to "flash.locked=$flashLocked, vbmeta=$vbmetaState, verifiedbootstate=$vbState"
            }
        }
        r.check("patch_os", I, "OS security patch within 12 months (STRONG integrity)") {
            val yyyymm = att.osPatch
                ?: Build.VERSION.SECURITY_PATCH.replace("-", "").take(6).toIntOrNull()
                ?: return@check "info" to "Patch level unknown."
            val age = monthsSince(yyyymm)
            val src = if (att.osPatch != null) "attested" else "reported"
            if (age <= 12) "pass" to "$yyyymm ($src), about $age months old."
            else "warn" to "$yyyymm ($src), about $age months old. MEETS_STRONG_INTEGRITY needs a patch from the last year."
        }
        r.check("patch_vendor", I, "Vendor / boot patch within 12 months") {
            val v = att.vendorPatch
            val b = att.bootPatch
            if (v == null && b == null) return@check "info" to "Not present in attestation."
            val worst = listOfNotNull(v, b).minOrNull()!!
            val age = monthsSince(worst / 100)
            val d = "vendor=${v ?: "n/a"}, boot=${b ?: "n/a"}, about $age months old."
            if (age <= 12) "pass" to d else "warn" to "$d STRONG integrity needs all partitions patched within a year."
        }
        r.check("build_tags", I, "Official release build (user / release-keys)", true) {
            val bad = Build.TAGS?.contains("test-keys") == true || Build.TYPE != "user"
            if (bad) "fail" to "type=${Build.TYPE}, tags=${Build.TAGS}" else "pass" to "type=${Build.TYPE}, tags=${Build.TAGS}"
        }
        r.check("props_secure", I, "ro.debuggable=0 and ro.secure=1", true) {
            val dbg = getProp("ro.debuggable")
            val sec = getProp("ro.secure")
            if (dbg == "1" || sec == "0") "fail" to "ro.debuggable=$dbg, ro.secure=$sec"
            else "pass" to "ro.debuggable=${dbg ?: "n/a"}, ro.secure=${sec ?: "n/a"}"
        }
        r.check("selinux", I, "SELinux enforcing", true) {
            val v = try { File("/sys/fs/selinux/enforce").readText().trim() } catch (e: Exception) { null }
                ?: getProp("ro.boot.selinux")
            when (v) {
                "1", "enforcing" -> "pass" to "Enforcing"
                "0", "permissive" -> "fail" to "Permissive"
                else -> "info" to "Not readable from the app sandbox."
            }
        }
        r.check("play_services", I, "Google Play Store and Play Services present") {
            val store = installed(pm, "com.android.vending")
            val gms = installed(pm, "com.google.android.gms")
            if (store && gms) "pass" to "Both installed."
            else "fail" to "Play Store=$store, Play Services=$gms. Play Integrity cannot run."
        }
        r.check("install_source", I, "This app installed from Google Play") {
            val src = if (Build.VERSION.SDK_INT >= 30)
                pm.getInstallSourceInfo(ctx.packageName).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(ctx.packageName)
            if (src == "com.android.vending") "pass" to "Installed by Play Store."
            else "info" to "Installer: ${src ?: "none (sideloaded/dev build)"}. Your bank app from Play is unaffected."
        }
        r.check("app_signature", I, "This app's signing certificate (SHA-256)") {
            if (Build.VERSION.SDK_INT < 28) return@check "info" to "Requires Android 9+."
            val pi = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val sig = pi.signingInfo?.apkContentsSigners?.firstOrNull()
                ?: return@check "info" to "No signer found."
            val hex = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
                .joinToString(":") { "%02X".format(it) }
            "info" to hex
        }

        // ============================== ROOT ===============================
        val R = "ROOT"
        r.check("su_paths", R, "su binary on disk", true) {
            val hits = SU_PATHS.filter { File(it).exists() }
            if (hits.isEmpty()) "pass" to "None of ${SU_PATHS.size} known paths exist."
            else "fail" to hits.joinToString()
        }
        r.check("su_which", R, "su resolvable from PATH", true) {
            val out = exec(arrayOf("sh", "-c", "command -v su"))
            if (out.isNullOrBlank()) "pass" to "Not found." else "fail" to out
        }
        r.check("root_apps", R, "Root manager apps installed", true) {
            val hits = ROOT_PACKAGES.filter { installed(pm, it) }
            if (hits.isEmpty()) "pass" to "None found." else "fail" to hits.joinToString()
        }
        r.check("magisk_files", R, "Magisk / KernelSU / APatch artifacts") {
            val hits = MAGISK_PATHS.filter { File(it).exists() }
            if (hits.isEmpty()) "pass" to "None visible (many are hidden from app sandboxes)."
            else "fail" to hits.joinToString()
        }
        r.check("rw_system", R, "System partitions mounted read-only", true) {
            val bad = File("/proc/mounts").readLines().mapNotNull { line ->
                val f = line.split(" ")
                if (f.size >= 4 && f[1] in RO_MOUNTS && f[3].split(",").contains("rw")) f[1] else null
            }
            if (bad.isEmpty()) "pass" to "System, vendor, product are read-only."
            else "fail" to "Writable: ${bad.joinToString()}"
        }
        r.check("root_mounts", R, "Root-related mounts") {
            val hits = File("/proc/self/mounts").readLines().filter { l ->
                ROOT_MOUNT_KEYS.any { l.contains(it, ignoreCase = true) }
            }
            if (hits.isEmpty()) "pass" to "None."
            else "fail" to hits.take(3).joinToString(" | ")
        }

        // Leftovers from a previous owner's rooting. Many bank SDKs look for these.
        r.check("residue_dirs", R, "Leftover root / recovery folders on storage", true) {
            val base = Environment.getExternalStorageDirectory().path
            val hits = RESIDUE_DIRS.map { "$base/$it" }.filter { File(it).exists() }
            if (hits.isEmpty()) "pass" to "None found." else "fail" to hits.joinToString()
        }
        r.check("residue_downloads", R, "Root tool files in Downloads") {
            val dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val names = dl.listFiles()?.map { it.name }
                ?: return@check "info" to "Downloads is not listable from the app sandbox. Check it manually in Files."
            val hits = names.filter { n -> RESIDUE_FILE_KEYS.any { n.contains(it, ignoreCase = true) } }
            if (hits.isEmpty()) "pass" to "None of ${names.size} files match." else "fail" to hits.joinToString()
        }
        r.check("dangerous_apps", R, "Patching / cheat / root-hiding tools installed", true) {
            val hits = DANGEROUS_PACKAGES.filter { installed(pm, it) }
            if (hits.isEmpty()) "pass" to "None found." else "fail" to hits.joinToString()
        }
        r.check("oem_unlock_flag", R, "OEM unlocking allowed flag") {
            val v = getProp("sys.oem_unlock_allowed") ?: getProp("ro.boot.oem_unlock_allowed")
            when (v) {
                "1" -> "warn" to "OEM unlocking is still allowed. Turn it off in Developer options (then turn Developer options off again)."
                "0" -> "pass" to "Not allowed."
                else -> "info" to "Not readable from the app sandbox."
            }
        }
        r.check("kernel", R, "Kernel looks stock") {
            val v = (System.getProperty("os.version") ?: "") + " " + (try { File("/proc/version").readText() } catch (e: Exception) { "" })
            val bad = listOf("magisk", "kernelsu", "ksu", "apatch").filter { v.contains(it, ignoreCase = true) }
            if (bad.isEmpty()) "info" to (System.getProperty("os.version") ?: "unknown")
            else "fail" to "Kernel string mentions ${bad.joinToString()}."
        }

        // ======================== TAMPERING / HOOKING ======================
        val T = "TAMPER"
        r.check("debugger", T, "Debugger / tracer attached", true) {
            val tracer = File("/proc/self/status").readLines()
                .firstOrNull { it.startsWith("TracerPid:") }?.substringAfter(":")?.trim()
            if (Debug.isDebuggerConnected() || Debug.waitingForDebugger() || (tracer != null && tracer != "0"))
                "fail" to "TracerPid=$tracer"
            else "pass" to "None. TracerPid=${tracer ?: "n/a"}"
        }
        r.check("frida", T, "Frida instrumentation", true) {
            val maps = scanMaps(listOf("frida", "gum-js-loop", "gmain", "linjector"))
            val port = portOpen(27042)
            if (maps.isEmpty() && !port) "pass" to "No Frida artifacts, port 27042 closed."
            else "fail" to "maps=${maps.joinToString()}, port27042=$port"
        }
        r.check("xposed", T, "Xposed / LSPosed hooking", true) {
            val cls = try { Class.forName("de.robv.android.xposed.XposedBridge"); true } catch (e: Throwable) { false }
            val maps = scanMaps(listOf("xposed", "lspd", "lsposed", "edxp", "riru", "zygisk"))
            val apps = HOOK_PACKAGES.filter { installed(pm, it) }
            if (!cls && maps.isEmpty() && apps.isEmpty()) "pass" to "Nothing detected."
            else "fail" to "class=$cls, maps=${maps.joinToString()}, apps=${apps.joinToString()}"
        }
        r.check("emulator", T, "Running on a physical device", true) {
            val fp = Build.FINGERPRINT.lowercase()
            val emu = fp.startsWith("generic") || fp.contains("emulator") || fp.contains("vbox") ||
                Build.HARDWARE in listOf("goldfish", "ranchu") ||
                Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for") ||
                Build.PRODUCT.contains("sdk") || getProp("ro.kernel.qemu") == "1"
            if (emu) "fail" to "Emulator signatures found." else "pass" to "${Build.MANUFACTURER} ${Build.MODEL}"
        }
        r.check("cloned_user", T, "Running in main user (not dual app / clone)") {
            val user = Process.myUid() / 100000
            if (user == 0) "pass" to "User 0."
            else "warn" to "User $user (work profile, Second Space or Dual Apps). Many banks refuse this."
        }
        r.check("debuggable_app", T, "This app is a debug build") {
            val dbg = (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            "info" to if (dbg) "Yes (debug build). Banks reject debuggable builds; release builds are fine." else "No."
        }

        // ========================== DEVICE SETTINGS ========================
        val S = "SETTINGS"
        r.check("dev_options", S, "Developer options off", true) {
            if (gInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == 1) "fail" to "Enabled." else "pass" to "Off."
        }
        r.check("usb_debug", S, "USB debugging off", true) {
            if (gInt(cr, Settings.Global.ADB_ENABLED) == 1) "fail" to "Enabled." else "pass" to "Off."
        }
        r.check("wifi_debug", S, "Wireless debugging off", true) {
            if (gInt(cr, "adb_wifi_enabled") == 1) "fail" to "Enabled." else "pass" to "Off."
        }
        r.check("auto_time", S, "Automatic date, time and time zone") {
            val t = gInt(cr, Settings.Global.AUTO_TIME)
            val z = gInt(cr, Settings.Global.AUTO_TIME_ZONE)
            if (t == 1 && z == 1) "pass" to "Both automatic."
            else "warn" to "auto_time=$t, auto_time_zone=$z. A wrong clock breaks secure logins."
        }
        r.check("screen_lock", S, "Screen lock set", true) {
            val km = ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            if (km.isDeviceSecure) "pass" to "PIN, pattern or password set." else "fail" to "No secure lock screen."
        }
        r.check("biometric", S, "Strong biometric enrolled") {
            if (Build.VERSION.SDK_INT < 30) return@check "info" to "Requires Android 11+."
            val bm = ctx.getSystemService(BiometricManager::class.java)
            when (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
                BiometricManager.BIOMETRIC_SUCCESS -> "pass" to "Enrolled."
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "warn" to "Hardware present, nothing enrolled."
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "info" to "No strong biometric hardware."
                else -> "warn" to "Unavailable right now."
            }
        }
        r.check("encryption", S, "Storage encrypted") {
            val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            val st = dpm.storageEncryptionStatus
            if (st in 3..5) "pass" to "Active ($st)." else "fail" to "Status $st."
        }
        r.check("play_protect", S, "Play Protect enabled (best effort)") {
            when (gInt(cr, "package_verifier_user_consent")) {
                1 -> "pass" to "Enabled."
                -1 -> "warn" to "Disabled. Play Integrity reports POSSIBLE_RISK."
                else -> "info" to "Not determinable from the app. Check Play Store > Play Protect."
            }
        }
        r.check("sdk", S, "Android version supported") {
            val d = "SDK ${Build.VERSION.SDK_INT} (Android ${Build.VERSION.RELEASE})."
            if (Build.VERSION.SDK_INT >= 29) "pass" to "$d Android 13+ uses hardware-backed integrity signals."
            else "warn" to "$d Older than Android 10; many banks drop support."
        }
        r.check("storage", S, "Free storage") {
            val st = StatFs(Environment.getDataDirectory().path)
            val freeMb = st.availableBytes / (1024 * 1024)
            val d = "$freeMb MB free."
            when {
                freeMb < 200 -> "fail" to "$d Apps cannot write tokens or logs and may crash."
                freeMb < 1024 -> "warn" to "$d Low."
                else -> "pass" to d
            }
        }
        r.check("data_saver", S, "Data Saver not restricting background data") {
            val cm0 = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            if (cm0.restrictBackgroundStatus == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED)
                "warn" to "Data Saver is on. It can delay or block background calls."
            else "pass" to "Off or app is allowed."
        }

        // ============================ SCREEN SAFETY ========================
        val C = "SCREEN"
        r.check("accessibility", C, "Accessibility services enabled") {
            val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            val pkgs = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .map { it.resolveInfo.serviceInfo.packageName }.distinct()
            when {
                pkgs.isEmpty() -> "pass" to "None enabled."
                pkgs.all { p -> SAFE_A11Y.any { p.startsWith(it) } } -> "info" to "System services only: ${pkgs.joinToString()}"
                else -> "warn" to "Third-party: ${pkgs.joinToString()}. Banks flag these (can read or control the screen)."
            }
        }
        r.check("overlay_apps", C, "Apps allowed to draw over other apps") {
            if (Build.VERSION.SDK_INT < 29) return@check "info" to "Requires Android 10+."
            val aops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val hits = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS).mapNotNull { p ->
                val ai = p.applicationInfo ?: return@mapNotNull null
                val user = (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0
                val wants = p.requestedPermissions?.contains("android.permission.SYSTEM_ALERT_WINDOW") == true
                if (user && wants && p.packageName != ctx.packageName &&
                    aops.unsafeCheckOpNoThrow("android:system_alert_window", ai.uid, p.packageName) == AppOpsManager.MODE_ALLOWED
                ) pm.getApplicationLabel(ai).toString() else null
            }
            if (hits.isEmpty()) "pass" to "None granted."
            else "warn" to "${hits.joinToString()}. Play Integrity reports these as OVERLAYS."
        }
        r.check("remote_apps", C, "Remote-control / screen-sharing apps installed") {
            val hits = REMOTE_PACKAGES.filter { installed(pm, it) }
            if (hits.isEmpty()) "pass" to "None found." else "warn" to hits.joinToString()
        }
        r.check("casting", C, "Screen mirroring or casting active") {
            val dm = ctx.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
            val n = dm.displays.size
            if (n <= 1) "pass" to "Single display." else "warn" to "$n displays attached (casting or external display)."
        }

        // ========================= DEVICE / SIM BINDING ====================
        val B = "BINDING"
        r.check("sim", B, "SIM ready (bank SIM binding)", true) {
            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            val slots = maxOf(tm.phoneCount, 1)
            val states = (0 until slots).map { simName(tm.getSimState(it)) }
            val d = states.mapIndexed { i, s -> "slot${i + 1}: $s" }.joinToString(", ")
            if (states.any { it == "READY" }) "pass" to d else "fail" to d
        }

        // ============================== NETWORK ============================
        val N = "NETWORK"
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        r.check("connected", N, "Network connected") {
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            if (caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true) "pass" to "Online."
            else "warn" to "No active internet connection."
        }
        r.check("vpn", N, "No VPN active") {
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) "warn" to "VPN active. Many banks reject VPN traffic."
            else "pass" to "No VPN."
        }
        r.check("proxy", N, "No HTTP proxy") {
            val p = cm.defaultProxy
            val sys = System.getProperty("http.proxyHost")
            if (p != null || !sys.isNullOrEmpty()) "warn" to "Proxy: ${p?.host ?: sys}" else "pass" to "None."
        }
        r.check("user_ca", N, "No user-installed CA certificates") {
            val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            val n = ks.aliases().toList().count { it.startsWith("user:") }
            if (n == 0) "pass" to "None. TLS interception unlikely."
            else "warn" to "$n user CA certificate(s). Pinned apps will fail; interception possible."
        }
        r.check("private_dns", N, "Private DNS mode") {
            "info" to (Settings.Global.getString(cr, "private_dns_mode") ?: "unknown") +
                ". If login fails with network errors, try turning this off."
        }

        r.check("clock_skew", N, "Clock matches server time and link is stable") {
            val conn = java.net.URL("https://www.google.com/generate_204").openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.requestMethod = "HEAD"
            val t0 = System.currentTimeMillis()
            conn.connect()
            val serverDate = conn.date
            val t1 = System.currentTimeMillis()
            conn.disconnect()
            if (serverDate == 0L) return@check "info" to "Server sent no Date header."
            val skewSec = Math.abs(serverDate - (t0 + t1) / 2) / 1000
            val rtt = t1 - t0
            val d = "Skew ${skewSec}s, round trip ${rtt} ms."
            when {
                skewSec > 300 -> "fail" to "$d TLS and OTP checks can fail."
                skewSec > 60 -> "warn" to d
                rtt > 2000 -> "warn" to "$d Slow link; expect timeouts."
                else -> "pass" to d
            }
        }

        // ============================ SERVER-SIDE ==========================
        val V = "SERVER"
        r.add("pi_device", V, "Play Integrity: device verdict", "info",
            "MEETS_DEVICE_INTEGRITY. On Android 13+ = hardware-proven locked bootloader + certified OS. Your attestation rows above approximate this; the real verdict comes from Google via the bank's server.", false)
        r.add("pi_strong", V, "Play Integrity: strong verdict", "info",
            "MEETS_STRONG_INTEGRITY. Device integrity plus security patches within the last year on all partitions (see patch rows).", false)
        r.add("pi_app", V, "Play Integrity: app and licensing", "info",
            "appRecognitionVerdict = PLAY_RECOGNIZED and appLicensingVerdict = LICENSED. Fails for sideloaded or re-signed bank apps.", false)
        r.add("pi_risk", V, "Play Integrity: app access risk", "info",
            "Reports apps that capture, control or overlay the screen (see SCREEN rows). Accessibility services verified by Google Play are excluded.", false)
        r.add("pi_protect", V, "Play Integrity: Play Protect verdict", "info",
            "NO_ISSUES / NO_DATA / POSSIBLE_RISK (off) / MEDIUM_RISK / HIGH_RISK.", false)
        r.add("pi_activity", V, "Play Integrity: device activity and recall", "info",
            "Request-rate level and server-set device bits. Only the bank's backend sees these.", false)

        // ============================= DEVICE INFO =========================
        val D = "DEVICE"
        r.add("dev_model", D, "Device", "info", "${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})", false)
        r.add("dev_fp", D, "Build fingerprint", "info", Build.FINGERPRINT, false)
        r.add("dev_patch", D, "Reported security patch", "info", Build.VERSION.SECURITY_PATCH, false)
        r.add("dev_att", D, "Attestation", "info",
            "chain=${att.chainLength}, level=${att.securityLevel ?: "n/a"}, state=${att.bootState ?: "n/a"}" +
                (att.error?.let { ", error=$it" } ?: ""), false)

        // ============================== SUMMARY ============================
        val result = Arguments.createMap()
        result.putString(
            "bootloader",
            when (att.locked ?: propsUnlocked?.not()) {
                true -> "LOCKED"
                false -> "UNLOCKED"
                null -> "UNKNOWN"
            }
        )
        result.putString(
            "overall",
            when {
                r.blockingFail > 0 -> "LIKELY_BLOCKED"
                r.fail > 0 || r.warn > 0 -> "REVIEW"
                else -> "LIKELY_PASS"
            }
        )
        result.putInt("pass", r.pass)
        result.putInt("fail", r.fail)
        result.putInt("warn", r.warn)
        result.putInt("info", r.info)
        result.putInt("blockingFail", r.blockingFail)
        result.putArray("checks", r.items)
        return result
    }

    // ----------------------------------------------------------------- helpers

    private fun getProp(name: String): String? = exec(arrayOf("getprop", name))?.ifEmpty { null }

    private fun exec(cmd: Array<String>): String? = try {
        Runtime.getRuntime().exec(cmd).inputStream.bufferedReader().readText().trim()
    } catch (e: Exception) {
        null
    }

    private fun gInt(cr: android.content.ContentResolver, key: String): Int =
        Settings.Global.getInt(cr, key, 0)

    private fun installed(pm: PackageManager, pkg: String): Boolean = try {
        @Suppress("DEPRECATION") pm.getPackageInfo(pkg, 0); true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    private fun scanMaps(keys: List<String>): List<String> = try {
        val found = LinkedHashSet<String>()
        File("/proc/self/maps").useLines { lines ->
            lines.forEach { l ->
                val low = l.lowercase()
                keys.forEach { k -> if (low.contains(k)) found.add(k) }
            }
        }
        found.toList()
    } catch (e: Exception) {
        emptyList()
    }

    private fun portOpen(port: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 150); true }
    } catch (e: Exception) {
        false
    }

    private fun simName(s: Int) = when (s) {
        TelephonyManager.SIM_STATE_READY -> "READY"
        TelephonyManager.SIM_STATE_ABSENT -> "ABSENT"
        TelephonyManager.SIM_STATE_PIN_REQUIRED -> "PIN_REQUIRED"
        TelephonyManager.SIM_STATE_PUK_REQUIRED -> "PUK_REQUIRED"
        TelephonyManager.SIM_STATE_NETWORK_LOCKED -> "NETWORK_LOCKED"
        else -> "UNKNOWN"
    }

    private fun monthsSince(yyyymm: Int): Int {
        val y = yyyymm / 100
        val m = yyyymm % 100
        val c = Calendar.getInstance()
        return (c.get(Calendar.YEAR) - y) * 12 + (c.get(Calendar.MONTH) + 1 - m)
    }

    // ------------------------------------------------------------- attestation

    private fun attest(): Attestation {
        val alias = "bootloader_check_key"
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return try {
            val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }
                .generateKeyPair()

            val chain = ks.getCertificateChain(alias)
            val leaf = chain[0] as X509Certificate
            val ext = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                ?: return Attestation(null, null, null, null, null, null, chain.size, "No attestation extension in certificate")

            val outer = readTlv(ext, 0)
            val keyDesc = readTlv(ext, outer.start)
            val kids = children(ext, keyDesc)

            val secLevel = when (enumValue(ext, kids[1])) {
                0 -> "Software"
                1 -> "TrustedEnvironment"
                2 -> "StrongBox"
                else -> "Unknown"
            }

            var locked: Boolean? = null
            var state: String? = null
            var os: Int? = null
            var vendor: Int? = null
            var boot: Int? = null
            for (i in 6 until kids.size) { // softwareEnforced, teeEnforced
                for (c in children(ext, kids[i])) {
                    if (c.cls != 2) continue
                    when (c.tag) {
                        704 -> {
                            val f = children(ext, readTlv(ext, c.start))
                            locked = ext[f[1].start].toInt() != 0
                            state = when (enumValue(ext, f[2])) {
                                0 -> "Verified"
                                1 -> "SelfSigned"
                                2 -> "Unverified"
                                3 -> "Failed"
                                else -> "Unknown"
                            }
                        }
                        706 -> os = enumValue(ext, readTlv(ext, c.start))
                        718 -> vendor = enumValue(ext, readTlv(ext, c.start))
                        719 -> boot = enumValue(ext, readTlv(ext, c.start))
                    }
                }
            }
            Attestation(locked, state, secLevel, os, vendor, boot, chain.size,
                if (locked == null) "RootOfTrust not found" else null)
        } catch (e: Throwable) {
            Attestation(null, null, null, null, null, null, 0, e.message ?: e.javaClass.simpleName)
        } finally {
            runCatching { ks.deleteEntry(alias) }
        }
    }

    private fun readTlv(b: ByteArray, pos: Int): Tlv {
        var p = pos
        val first = b[p++].toInt() and 0xFF
        val cls = first shr 6
        var tag = first and 0x1F
        if (tag == 0x1F) {
            tag = 0
            var more: Boolean
            do {
                val x = b[p++].toInt() and 0xFF
                tag = (tag shl 7) or (x and 0x7F)
                more = (x and 0x80) != 0
            } while (more)
        }
        var len = b[p++].toInt() and 0xFF
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            len = 0
            repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xFF) }
        }
        return Tlv(cls, tag, p, p + len)
    }

    private fun children(b: ByteArray, parent: Tlv): List<Tlv> {
        val out = ArrayList<Tlv>()
        var pos = parent.start
        while (pos < parent.end) {
            val t = readTlv(b, pos)
            out.add(t)
            pos = t.end
        }
        return out
    }

    private fun enumValue(b: ByteArray, t: Tlv): Int {
        var v = 0
        for (i in t.start until t.end) v = (v shl 8) or (b[i].toInt() and 0xFF)
        return v
    }

    // -------------------------------------------------------------- signatures

    companion object {
        private val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su", "/system/app/Superuser.apk", "/data/local/su",
            "/data/local/bin/su", "/data/local/xbin/su", "/su/bin/su", "/vendor/bin/su",
            "/system_ext/bin/su", "/product/bin/su", "/odm/bin/su",
        )
        private val MAGISK_PATHS = listOf(
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu",
            "/data/adb/ap", "/cache/magisk.log", "/data/adb/magisk.db",
            // /debug_ramdisk itself exists on stock Android 10+, so only flag Magisk's contents.
            "/debug_ramdisk/.magisk", "/debug_ramdisk/magisk",
        )
        private val ROOT_PACKAGES = listOf(
            "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.noshufou.android.su", "com.koushikdutta.superuser", "com.thirdparty.superuser",
            "com.yellowes.su", "com.kingroot.kinguser", "com.kingo.root", "com.zhiqupk.root.global",
        )
        private val HOOK_PACKAGES = listOf(
            "de.robv.android.xposed.installer", "org.lsposed.manager", "io.va.exposed",
            "com.saurik.substrate", "de.robv.android.xposed", "com.devadvance.rootcloak",
            "com.amphoras.hidemyroot", "com.formyhm.hideroot", "me.phh.superuser",
        )
        private val REMOTE_PACKAGES = listOf(
            "com.anydesk.anydeskandroid", "com.teamviewer.quicksupport.market",
            "com.teamviewer.teamviewer.market.mobile", "com.rustdesk.rustdesk",
            "com.sand.airdroid", "com.sand.airmirror", "com.splashtop.remote.pad",
            "com.koushikdutta.vysor", "com.google.android.apps.chromeremotedesktop",
            "com.microsoft.rdc.androidx", "com.realvnc.viewer.android", "net.christianbeier.droidvnc_ng",
        )
        private val RESIDUE_DIRS = listOf(
            "TWRP", "Fox", "OrangeFox", "PBRP", "Magisk", "KernelSU", "APatch", "SuperSU",
            "LSPosed", "Download/Magisk", "Android/data/com.topjohnwu.magisk",
        )
        private val RESIDUE_FILE_KEYS = listOf(
            "magisk", "kernelsu", "apatch", "twrp", "orangefox", "lsposed", "zygisk",
            "boot.img", "init_boot", "vbmeta", "patched",
        )
        private val DANGEROUS_PACKAGES = listOf(
            "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch", "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro", "com.android.vendinc", "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot", "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot", "com.noshufou.android.su.elite", "com.smedialink.oneclickroot",
            "com.alephzain.framaroot", "catch_.me_.if_.you_.can_", "org.sbtools.gamehack",
            "com.cih.game_cih", "com.devadvance.rootcloakplus", "com.holdingkc.hideroot",
            "com.android.vending.billing.InAppBillingService.COIN",
            "com.android.vending.billing.InAppBillingService.LUCK",
            "com.android.vending.billing.InAppBillingService.CLON",
        )
        private val RO_MOUNTS = setOf("/system", "/vendor", "/product", "/system_ext", "/odm")
        private val ROOT_MOUNT_KEYS = listOf("magisk", "core/mirror", "ksu", "apatch", "zygisk")
        private val SAFE_A11Y = listOf(
            "com.google.android.marvin.talkback", "com.google.android.accessibility",
            "com.android.talkback", "com.android.systemui", "com.samsung.accessibility",
            "com.miui.accessibility", "com.xiaomi.accessibility",
        )
    }
}