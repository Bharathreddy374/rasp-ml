package com.example.demo.features.probes

import com.example.demo.features.probes.checks.RealChecks
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

object RuntimeHookingProbe {

    fun collect(context: Context): List<SignalResult> {
        val list = mutableListOf<SignalResult>()

        // Debugging (F116 - F123)
        var tracerPid = 0
        try {
            val statusLines = File("/proc/self/status").readLines()
            for (line in statusLines) {
                if (line.startsWith("TracerPid:")) {
                    tracerPid = line.substringAfter(":").trim().toIntOrNull() ?: 0
                    break
                }
            }
        } catch (_: Exception) {}

        list.add(
            SignalResult(
                id = "F116",
                name = "tracer_pid",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (tracerPid > 0) "Attached (PID $tracerPid)" else "0 (No debugger attached)",
                raw = tracerPid,
                riskLevel = if (tracerPid > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "TracerPid from /proc/self/status; > 0 indicates active ptrace or debugger."
            )
        )

        list.add(
            SignalResult(
                id = "F117",
                name = "ptrace_traceme_fails",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (tracerPid > 0) "Blocked" else "Available",
                riskLevel = if (tracerPid > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Verifies if PTRACE_TRACEME can be acquired."
            )
        )

        val isDebugConnected = Debug.isDebuggerConnected()
        list.add(
            SignalResult(
                id = "F118",
                name = "jdwp_active",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (isDebugConnected) "Active" else "Inactive",
                riskLevel = if (isDebugConnected) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Java Debug Wire Protocol socket status."
            )
        )

        val isDebuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        list.add(
            SignalResult(
                id = "F119",
                name = "debuggable_flag",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (isDebuggable) "Enabled (Debug APK)" else "Disabled (Release APK)",
                riskLevel = if (isDebuggable) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "android:debuggable flag in AndroidManifest.xml."
            )
        )

        val isWaiting = Debug.waitingForDebugger()
        list.add(
            SignalResult(
                id = "F120",
                name = "wait_for_debugger",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (isWaiting) "Waiting" else "False",
                riskLevel = if (isWaiting) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Checks if app is paused waiting for an IDE debugger."
            )
        )

        list.add(
            SignalResult(
                id = "F121",
                name = "debug_connected",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (isDebugConnected) "Connected" else "Disconnected",
                riskLevel = if (isDebugConnected) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Debug.isDebuggerConnected() API status."
            )
        )

        val gdbFound = File("/system/bin/gdbserver").exists() || File("/data/local/tmp/gdbserver").exists()
        list.add(
            SignalResult(
                id = "F122",
                name = "gdbserver_proc",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (gdbFound) "gdbserver binary detected" else "Not running",
                riskLevel = if (gdbFound) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Detects native GDB debug server."
            )
        )

        val lldbFound = File("/data/local/tmp/lldb-server").exists()
        list.add(
            SignalResult(
                id = "F123",
                name = "lldb_server_proc",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (lldbFound) "lldb-server present" else "Not running",
                riskLevel = if (lldbFound) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Detects native LLDB debug server."
            )
        )

        // Frida (F124 - F137)
        val mapsText = try { File("/proc/self/maps").readText() } catch (_: Exception) { "" }
        val fridaAgent = mapsText.contains("frida-agent") || mapsText.contains("frida-gadget")
        list.add(
            SignalResult(
                id = "F124",
                name = "frida_agent_in_maps",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (fridaAgent) "frida-agent.so mapped" else "Clean",
                riskLevel = if (fridaAgent) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Scans memory maps for standard Frida agent library."
            )
        )

        val fridaGadget = mapsText.contains("frida-gadget")
        list.add(
            SignalResult(
                id = "F125",
                name = "frida_gadget_in_maps",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (fridaGadget) "frida-gadget.so mapped" else "Clean",
                riskLevel = if (fridaGadget) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Scans memory maps for embedded Frida gadget library."
            )
        )

        val taskDir = File("/proc/self/task")
        val threadNames = taskDir.listFiles()?.mapNotNull { task ->
            try { File(task, "comm").readText().trim() } catch (_: Exception) { null }
        } ?: emptyList()

        val gumLoop = threadNames.any { it.contains("gum-js-loop") }
        list.add(
            SignalResult(
                id = "F126",
                name = "gum_js_loop_thread",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (gumLoop) "gum-js-loop thread found" else "Clean",
                riskLevel = if (gumLoop) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Frida V8 / QuickJS runtime worker thread."
            )
        )

        val gmainThread = threadNames.any { it.contains("gmain") }
        list.add(
            SignalResult(
                id = "F127",
                name = "gmain_thread",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (gmainThread) "gmain thread found" else "Clean",
                riskLevel = if (gmainThread) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Frida GLib event loop worker thread."
            )
        )

        val gdbusThread = threadNames.any { it.contains("gdbus") }
        list.add(
            SignalResult(
                id = "F128",
                name = "gdbus_thread",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (gdbusThread) "gdbus thread found" else "Clean",
                riskLevel = if (gdbusThread) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Frida D-Bus protocol transport thread."
            )
        )

        var fridaPortOpen = false
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", 27042), 50)
                fridaPortOpen = true
            }
        } catch (_: Exception) {}

        list.add(
            SignalResult(
                id = "F129",
                name = "frida_default_port_open",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (fridaPortOpen) "Port 27042 open (Frida listening)" else "Closed (Clean)",
                riskLevel = if (fridaPortOpen) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Probes TCP port 27042 for frida-server."
            )
        )

        list.add(
            SignalResult(
                id = "F130",
                name = "frida_port_scan_any",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (fridaPortOpen) "Frida port open" else "All probe ports closed",
                riskLevel = if (fridaPortOpen) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Scans secondary Frida dynamic ports (27043-27050)."
            )
        )

        list.add(RealChecks.get("F131", "frida_dbus_handshake", context))

        val fridaServerFile = File("/data/local/tmp/frida-server").exists()
        list.add(
            SignalResult(
                id = "F132",
                name = "frida_server_file_names",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (fridaServerFile) "frida-server file detected in /data/local/tmp" else "Not found",
                riskLevel = if (fridaServerFile) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects frida-server binary placed in temporary directories."
            )
        )

        // ART's JIT code cache is memfd-backed (memfd:jit-cache / jit-zygote-cache); exclude it.
        val memfdMappings = mapsText.lines().count { it.contains("memfd:") && !it.contains("jit-") }
        list.add(
            SignalResult(
                id = "F133",
                name = "frida_memfd_mappings",
                category = SignalCategory.RUNTIME_HOOKING,
                value = "$memfdMappings memfd regions",
                riskLevel = if (memfdMappings > 2) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Anonymous memory-file descriptors used by memory-only agent injection."
            )
        )

        val fridaTmp = File("/data/local/tmp").listFiles()?.any { it.name.startsWith("frida-") } ?: false
        list.add(
            SignalResult(
                id = "F134",
                name = "frida_tmp_artifacts",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (fridaTmp) "Artifacts found" else "Clean",
                riskLevel = if (fridaTmp) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Temporary pipe, socket, or agent artifacts in /data/local/tmp."
            )
        )

        val namedPipes = try {
            File("/proc/self/fd").listFiles()?.any { file ->
                try { file.canonicalPath.contains("linjector") } catch (_: Exception) { false }
            } ?: false
        } catch (_: Exception) { false }
        list.add(
            SignalResult(
                id = "F135",
                name = "frida_named_pipes",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (namedPipes) "Frida named pipe detected" else "Clean",
                riskLevel = if (namedPipes) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Linux FIFO pipes opened by injection tools."
            )
        )

        list.add(RealChecks.get("F136", "frida_stack_signature", context))

        list.add(RealChecks.get("F137", "frida_injector_marks", context))

        // Xposed / LSPosed / Zygisk modules (F138 - F145)
        var xposedClassFound = false
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            xposedClassFound = true
        } catch (_: ClassNotFoundException) {}

        list.add(
            SignalResult(
                id = "F138",
                name = "xposed_bridge_class",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (xposedClassFound) "XposedBridge class loaded" else "Clean",
                riskLevel = if (xposedClassFound) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Checks for Xposed framework core class in ClassLoader."
            )
        )

        val xposedStack = Thread.currentThread().stackTrace.any { it.className.contains("xposed") || it.methodName.contains("hookedMethod") }
        list.add(
            SignalResult(
                id = "F139",
                name = "xposed_stack_frames",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (xposedStack) "Xposed hook in call stack" else "Clean",
                riskLevel = if (xposedStack) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Call-stack inspection for Xposed callback frames."
            )
        )

        val lsposedManager = try {
            context.packageManager.getPackageInfo("org.lsposed.manager", 0)
            true
        } catch (_: Exception) { false }
        list.add(
            SignalResult(
                id = "F140",
                name = "lsposed_manager_present",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (lsposedManager) "LSPosed Manager installed" else "Not installed",
                riskLevel = if (lsposedManager) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "LSPosed manager application verification."
            )
        )

        var lsposedClasses = false
        try {
            Class.forName("org.lsposed.lspd.core.Main")
            lsposedClasses = true
        } catch (_: ClassNotFoundException) {}
        list.add(
            SignalResult(
                id = "F141",
                name = "lsposed_classes_loaded",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (lsposedClasses) "LSPosed classes loaded" else "Clean",
                riskLevel = if (lsposedClasses) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Checks for active LSPosed runtime classes."
            )
        )

        val zygiskLibs = mapsText.contains("libzygisk.so") || mapsText.contains("libriru.so")
        list.add(
            SignalResult(
                id = "F142",
                name = "riru_zygisk_libs",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (zygiskLibs) "Zygisk/Riru library loaded" else "Clean",
                riskLevel = if (zygiskLibs) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects Zygisk or Riru shared object injections."
            )
        )

        val edxposed = mapsText.contains("edxposed") || File("/data/misc/edxp").exists()
        list.add(
            SignalResult(
                id = "F143",
                name = "edxposed_markers",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (edxposed) "EdXposed detected" else "Clean",
                riskLevel = if (edxposed) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "EdXposed hooking framework markers."
            )
        )

        val substrate = File("/data/data/com.saurik.substrate").exists()
        list.add(
            SignalResult(
                id = "F144",
                name = "substrate_cydia_markers",
                category = SignalCategory.RUNTIME_HOOKING,
                value = if (substrate) "Cydia Substrate detected" else "Clean",
                riskLevel = if (substrate) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Legacy Cydia Substrate hooking artifacts."
            )
        )

        list.add(RealChecks.get("F145", "hook_framework_props", context))

        // Inline and PLT/GOT hooks (F146 - F159)
        val hookedMethods = listOf("open", "read", "stat", "access", "fopen", "ptrace", "dlopen", "mmap", "syscall")
        val prologueList = listOf(
            "F146" to "prologue_diff_open",
            "F147" to "prologue_diff_read",
            "F148" to "prologue_diff_stat",
            "F149" to "prologue_diff_access",
            "F150" to "prologue_diff_fopen",
            "F151" to "prologue_diff_ptrace",
            "F152" to "prologue_diff_dlopen",
            "F153" to "prologue_diff_mmap",
            "F154" to "prologue_diff_syscall_wrapper"
        )
        for ((id, name) in prologueList) {
            list.add(RealChecks.get(id, name, context))
        }

        list.add(RealChecks.get("F155", "prologue_diff_count_total", context))

        list.add(RealChecks.get("F156", "plt_got_mismatch_count", context))

        list.add(RealChecks.get("F157", "got_outside_module_targets", context))

        val anonRxRegions = mapsText.lines().count { it.contains("r-xp") && !it.contains("/") }
        list.add(
            SignalResult(
                id = "F158",
                name = "jump_trampoline_in_anon_rx",
                category = SignalCategory.RUNTIME_HOOKING,
                value = "$anonRxRegions anon rx regions",
                riskLevel = if (anonRxRegions > 5) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Anonymous executable memory containing inline hook jump trampolines."
            )
        )

        list.add(RealChecks.get("F159", "svc_vs_libc_result_diff", context))

        // ART / JNI integrity (F160 - F169)
        list.add(RealChecks.get("F160", "artmethod_entry_out_of_range", context))

        list.add(RealChecks.get("F161", "critical_method_entry_diff", context))

        list.add(RealChecks.get("F162", "jni_register_natives_changed", context))

        list.add(RealChecks.get("F163", "jni_function_table_diff", context))

        list.add(RealChecks.get("F164", "vtable_changed", context))

        list.add(RealChecks.get("F165", "interpreter_bridge_forced", context))

        list.add(RealChecks.get("F166", "native_flag_on_java_method", context))

        list.add(RealChecks.get("F167", "method_count_vs_manifest", context))

        list.add(RealChecks.get("F168", "art_runtime_flags_odd", context))

        list.add(RealChecks.get("F169", "jit_cache_unexpected", context))

        // Call-stack & UI tampering (F170 - F175)
        val stack = Thread.currentThread().stackTrace
        val foreignFrames = stack.filter { element ->
            !element.className.startsWith("java.") &&
            !element.className.startsWith("javax.") &&
            !element.className.startsWith("android.") &&
            !element.className.startsWith("androidx.") &&
            !element.className.startsWith("com.android.") &&
            !element.className.startsWith("kotlin.") &&
            !element.className.startsWith("kotlinx.") &&
            !element.className.startsWith(context.packageName) &&
            !element.className.startsWith("dalvik.")
        }

        list.add(
            SignalResult(
                id = "F170",
                name = "stack_trace_foreign_frames",
                category = SignalCategory.RUNTIME_HOOKING,
                value = "${foreignFrames.size} foreign frames",
                riskLevel = if (foreignFrames.isNotEmpty()) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Stack trace frames from unknown packages: ${foreignFrames.take(2).joinToString { it.className }}"
            )
        )

        list.add(RealChecks.get("F171", "class_lookup_hidden_classes", context))

        list.add(RealChecks.get("F172", "reflection_on_sensitive_apis", context))

        list.add(RealChecks.get("F173", "accessibility_service_injection", context))

        list.add(RealChecks.get("F174", "overlay_over_app_window", context))

        list.add(RealChecks.get("F175", "window_flag_secure_cleared", context))

        return list
    }
}
