package com.inspect_mobile // TODO: change to your app's package

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

class BootloaderCheckModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "BootloaderCheck"

    private class Tlv(val cls: Int, val tag: Int, val start: Int, val end: Int)

    private class Attestation(
        val locked: Boolean?,
        val bootState: String?,
        val securityLevel: String?,
        val error: String?,
    )

    @ReactMethod
    fun check(promise: Promise) {
        Thread {
            try {
                val result = Arguments.createMap()

                // 1) System properties (quick, but can be spoofed)
                val props = Arguments.createMap()
                PROPS.forEach { props.putString(it, getProp(it)) }
                result.putMap("props", props)

                val flashLocked = getProp("ro.boot.flash.locked")
                val vbmetaState = getProp("ro.boot.vbmeta.device_state")
                val vbState = getProp("ro.boot.verifiedbootstate")
                val propsUnlocked: Boolean? = when {
                    flashLocked == "0" || vbmetaState == "unlocked" || vbState == "orange" -> true
                    flashLocked == "1" || vbmetaState == "locked" || vbState == "green" -> false
                    else -> null
                }

                // 2) Hardware-backed key attestation (RootOfTrust)
                val att = attest()
                val attMap = Arguments.createMap()
                if (att.locked != null) attMap.putBoolean("deviceLocked", att.locked)
                else attMap.putNull("deviceLocked")
                attMap.putString("verifiedBootState", att.bootState)
                attMap.putString("securityLevel", att.securityLevel)
                attMap.putString("error", att.error)
                result.putMap("attestation", attMap)

                // Verdict: attestation wins, props are the fallback
                val unlocked: Boolean? = when {
                    att.locked != null -> !att.locked
                    else -> propsUnlocked
                }
                result.putString(
                    "verdict",
                    when (unlocked) {
                        true -> "UNLOCKED"
                        false -> "LOCKED"
                        null -> "UNKNOWN"
                    }
                )
                result.putString(
                    "source",
                    if (att.locked != null) "attestation" else if (propsUnlocked != null) "props" else "none"
                )
                promise.resolve(result)
            } catch (e: Throwable) {
                promise.reject("E_BOOTLOADER_CHECK", e.message, e)
            }
        }.start()
    }

    private fun getProp(name: String): String? = try {
        val p = Runtime.getRuntime().exec(arrayOf("getprop", name))
        p.inputStream.bufferedReader().readText().trim().ifEmpty { null }
    } catch (e: Exception) {
        null
    }

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

            val leaf = ks.getCertificateChain(alias)[0] as X509Certificate
            val ext = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                ?: return Attestation(null, null, null, "No attestation extension in certificate")

            val outer = readTlv(ext, 0)              // OCTET STRING wrapper
            val keyDesc = readTlv(ext, outer.start)  // KeyDescription SEQUENCE
            val kids = children(ext, keyDesc)

            val secLevel = when (enumValue(ext, kids[1])) {
                0 -> "Software"
                1 -> "TrustedEnvironment"
                2 -> "StrongBox"
                else -> "Unknown"
            }

            var locked: Boolean? = null
            var state: String? = null
            // softwareEnforced = kids[6], teeEnforced = kids[7]
            for (i in 6 until kids.size) {
                for (c in children(ext, kids[i])) {
                    if (c.cls == 2 && c.tag == 704) { // [704] rootOfTrust (explicit)
                        val rot = readTlv(ext, c.start)
                        val f = children(ext, rot)
                        locked = ext[f[1].start].toInt() != 0
                        state = when (enumValue(ext, f[2])) {
                            0 -> "Verified"
                            1 -> "SelfSigned"
                            2 -> "Unverified"
                            3 -> "Failed"
                            else -> "Unknown"
                        }
                    }
                }
            }

            if (locked == null) Attestation(null, null, secLevel, "RootOfTrust not found")
            else Attestation(locked, state, secLevel, null)
        } catch (e: Throwable) {
            Attestation(null, null, null, e.message ?: e.javaClass.simpleName)
        } finally {
            runCatching { ks.deleteEntry(alias) }
        }
    }

    // ---- Minimal DER reader ----

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

    companion object {
        private val PROPS = listOf(
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state",
            "ro.boot.verifiedbootstate",
            "ro.boot.veritymode",
            "ro.oem_unlock_supported",
        )
    }
}