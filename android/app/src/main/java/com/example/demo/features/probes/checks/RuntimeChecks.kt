package com.example.demo.features.probes.checks

import android.content.Context
import android.system.Os
import com.example.demo.features.attestation.AttestationSession
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.network.TrustPayload
import com.example.demo.features.probes.support.NEEDS_NATIVE
import com.example.demo.features.probes.support.NEEDS_UI
import com.example.demo.features.probes.support.Proc
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import java.io.File
import java.lang.reflect.Modifier
import java.net.InetSocketAddress
import java.net.Socket

/** Runtime / hooking checks (catalogue group 4) that Kotlin can do without native code. */
internal object RuntimeChecks {

    fun get(id: String, name: String, context: Context): SignalResult? = when (id) {
        "F131" -> fridaHandshake(id, name)
        "F137" -> injectorMarks(id, name)
        "F145" -> nativeBridge(id, name)
        "F166" -> nativeFlag(id, name)
        "F171" -> hookClasses(id, name, context)
        "F167" -> unknown(id, name, "needs the release build manifest on the backend")
        "F173", "F174", "F175" -> unknown(id, name, NEEDS_UI)
        "F136", "F146", "F147", "F148", "F149", "F150", "F151", "F152", "F153", "F154",
        "F155", "F156", "F157", "F159", "F160", "F161", "F162", "F163", "F164",
        "F165", "F168", "F169", "F172" -> unknown(id, name, NEEDS_NATIVE)
        else -> null
    }

    /**
     * Talks to local ports the way a Frida client does, so a renamed server is still recognised:
     *  - Frida 15+: WebSocket upgrade on /ws is accepted ("101 Switching Protocols")
     *  - older Frida: raw D-Bus AUTH is answered with "REJECTED"
     */
    private fun fridaHandshake(id: String, name: String): SignalResult {
        val ws = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        for (port in 27042..27052) {
            exchange(port, ws.toByteArray())?.let { reply ->
                if (reply.startsWith("HTTP/1.1 101")) {
                    return measured(id, name, "Frida WebSocket endpoint on port $port", true, RiskLevel.ALERT,
                        "A local service accepted a WebSocket upgrade on /ws like frida-server 15+ does.")
                }
            } ?: continue  // nothing listening: skip the second probe
            exchange(port, byteArrayOf(0) + "AUTH\r\n".toByteArray())?.let { reply ->
                if (reply.contains("REJECTED")) {
                    return measured(id, name, "Frida D-Bus endpoint on port $port", true, RiskLevel.ALERT,
                        "A local service answered a D-Bus AUTH handshake like older frida-server does.")
                }
            }
        }
        return measured(id, name, "No Frida protocol on 27042-27052", false, RiskLevel.SAFE,
            "Frida WebSocket and D-Bus handshake probes on local ports (recognises a renamed server).")
    }

    /** Sends [request] to 127.0.0.1:[port] and returns the start of the reply, or null if nothing listens. */
    private fun exchange(port: Int, request: ByteArray): String? = try {
        Socket().use { s ->
            s.connect(InetSocketAddress("127.0.0.1", port), 80)
            s.soTimeout = 300
            s.getOutputStream().apply { write(request); flush() }
            val buf = ByteArray(128)
            val n = try { s.getInputStream().read(buf) } catch (_: Exception) { -1 }
            if (n > 0) String(buf, 0, n, Charsets.ISO_8859_1) else ""
        }
    } catch (_: Exception) {
        null
    }

    private val INJECTOR = listOf("frida", "gadget", "linjector", "gum-js", "re.frida")

    private fun injectorMarks(id: String, name: String): SignalResult {
        val hits = mutableSetOf<String>()
        Proc.maps()?.forEach { m -> INJECTOR.firstOrNull { m.path.contains(it, true) }?.let { hits.add("maps:$it") } }
        File("/proc/self/fd").listFiles()?.forEach { fd ->
            val target = try { Os.readlink(fd.path) } catch (_: Exception) { "" }
            INJECTOR.firstOrNull { target.contains(it, true) }?.let { hits.add("fd:$it") }
        }
        listOf("/data/local/tmp/re.frida.server", "/data/local/tmp/frida-server").forEach {
            if (File(it).exists()) hits.add("file:$it")
        }
        return measured(id, name, if (hits.isEmpty()) "None" else hits.joinToString(), hits.size,
            if (hits.isEmpty()) RiskLevel.SAFE else RiskLevel.ALERT,
            "Frida injector traces in memory maps, open file descriptors and its working directory.")
    }

    private val LEGIT_BRIDGES = setOf("", "0", "libhoudini.so", "libndk_translation.so", "libnb.so")

    private fun nativeBridge(id: String, name: String): SignalResult {
        val bridge = DeviceChecks.prop("ro.dalvik.vm.native.bridge")
        val odd = bridge !in LEGIT_BRIDGES
        return measured(id, name, if (bridge.isEmpty()) "Not set" else bridge, bridge.take(64),
            if (odd) RiskLevel.ALERT else RiskLevel.SAFE,
            "ro.dalvik.vm.native.bridge: Riru-style hook loaders replace the ARM translation bridge.")
    }

    /** Classic Xposed marks hooked Java methods ACC_NATIVE. None of these methods is native. */
    private fun nativeFlag(id: String, name: String): SignalResult {
        val methods = try {
            listOf(
                TrustPayload::class.java.getDeclaredMethod("build", Context::class.java,
                    com.example.demo.features.scanner.ScanSummary::class.java, String::class.java,
                    String::class.java, String::class.java, Long::class.javaPrimitiveType),
                AttestationSession::class.java.getDeclaredMethod("sign", ByteArray::class.java),
                File::class.java.getDeclaredMethod("exists"),
                File::class.java.getDeclaredMethod("canRead"),
            )
        } catch (_: Exception) {
            return unknown(id, name, "reference methods not found")
        }
        val hooked = methods.filter { Modifier.isNative(it.modifiers) }.map { "${it.declaringClass.simpleName}.${it.name}" }
        return measured(id, name, if (hooked.isEmpty()) "No native flag (${methods.size} checked)" else hooked.joinToString(),
            hooked.size, if (hooked.isEmpty()) RiskLevel.SAFE else RiskLevel.ALERT,
            "Java methods that suddenly carry the native modifier have been hooked.")
    }

    private val HOOK_CLASSES = listOf(
        "de.robv.android.xposed.XposedBridge", "de.robv.android.xposed.XposedHelpers",
        "io.github.libxposed.api.XposedInterface", "org.lsposed.lspd.core.Main",
        "org.lsposed.lspatch.loader.LSPApplication", "com.saurik.substrate.MS\$2",
        "top.canyie.pine.Pine", "me.weishu.epic.art.EpicNative", "com.swift.sandhook.SandHook",
    )

    private fun hookClasses(id: String, name: String, context: Context): SignalResult {
        val loaders = listOfNotNull(context.classLoader, ClassLoader.getSystemClassLoader(), Thread.currentThread().contextClassLoader)
        val found = HOOK_CLASSES.filter { cls ->
            loaders.any { l -> try { Class.forName(cls, false, l); true } catch (_: Throwable) { false } }
        }
        return measured(id, name, if (found.isEmpty()) "None loadable" else found.joinToString { it.substringAfterLast('.') },
            found.size, if (found.isEmpty()) RiskLevel.SAFE else RiskLevel.ALERT,
            "Hook-framework classes reachable from this app's class loaders.")
    }
}
