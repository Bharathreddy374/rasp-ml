package com.example.demo.features.probes.support

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Reads the installed APK from disk, independently of PackageManager.
 *
 * Digests are SHA-256 over sorted "name:crc32:size" lines taken from the zip central
 * directory (no decompression), truncated to 32 hex chars. backend/tools/apk_manifest.py
 * computes the same digests from a release APK so the backend can compare them.
 */
object ApkInspector {

    data class Facts(
        val apkSize: Long,
        val dexCount: Int,
        val dexDigest: String,
        val soCount: Int,
        val soDigest: String,
        val assetsDigest: String,
        val arscCrc: String?,
        val manifestCrc: String?,
        /** Signature scheme IDs found in the APK Signing Block: 2, 3, 31. */
        val schemes: Set<Int>,
        val v1Signed: Boolean,
        val sigBlockPresent: Boolean,
    )

    private val DEX = Regex("^classes\\d*\\.dex$")
    private const val V2 = 0x7109871a
    private const val V3 = 0xf05368c0.toInt()
    private const val V31 = 0x1b93ad61

    @Volatile private var cache: Pair<String, Facts>? = null

    fun inspect(path: String): Facts {
        val f = File(path)
        val key = "$path:${f.length()}:${f.lastModified()}"
        cache?.let { if (it.first == key) return it.second }

        val dex = mutableListOf<String>()
        val so = mutableListOf<String>()
        val assets = mutableListOf<String>()
        var arsc: String? = null
        var manifest: String? = null
        var v1Sf = false
        var v1Sig = false
        ZipFile(f).use { zip ->
            for (e in zip.entries()) {
                val n = e.name
                val line = "$n:${"%08x".format(e.crc)}:${e.size}"
                when {
                    DEX.matches(n) -> dex.add(line)
                    n.startsWith("lib/") && n.endsWith(".so") -> so.add(line)
                    n.startsWith("assets/") -> assets.add(line)
                    n == "resources.arsc" -> arsc = "%08x".format(e.crc)
                    n == "AndroidManifest.xml" -> manifest = "%08x".format(e.crc)
                    n.startsWith("META-INF/") && n.endsWith(".SF") -> v1Sf = true
                    n.startsWith("META-INF/") && (n.endsWith(".RSA") || n.endsWith(".EC") || n.endsWith(".DSA")) -> v1Sig = true
                }
            }
        }
        val schemes = signingBlockIds(f)
        val facts = Facts(
            apkSize = f.length(),
            dexCount = dex.size, dexDigest = digest(dex),
            soCount = so.size, soDigest = digest(so),
            assetsDigest = digest(assets),
            arscCrc = arsc, manifestCrc = manifest,
            schemes = schemes.mapNotNull {
                when (it) { V2 -> 2; V3 -> 3; V31 -> 31; else -> null }
            }.toSet(),
            v1Signed = v1Sf && v1Sig,
            sigBlockPresent = schemes.isNotEmpty(),
        )
        cache = key to facts
        return facts
    }

    fun digest(lines: List<String>): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(lines.sorted().joinToString("\n").toByteArray())
        return md.digest().joinToString("") { "%02x".format(it) }.take(32)
    }

    /** IDs of the key/value pairs in the APK Signing Block, or empty if there is none. */
    private fun signingBlockIds(f: File): List<Int> = try {
        RandomAccessFile(f, "r").use { raf ->
            val len = raf.length()
            // End of central directory: last 22..65557 bytes.
            val tailLen = minOf(len, 22L + 65535L).toInt()
            val tail = ByteArray(tailLen)
            raf.seek(len - tailLen)
            raf.readFully(tail)
            var eocd = -1
            for (i in tailLen - 22 downTo 0) {
                if (tail[i] == 0x50.toByte() && tail[i + 1] == 0x4b.toByte() &&
                    tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()) { eocd = i; break }
            }
            if (eocd < 0) return emptyList()
            val cdOffset = ByteBuffer.wrap(tail, eocd + 16, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xffffffffL
            if (cdOffset < 32) return emptyList()
            val footer = ByteArray(24)
            raf.seek(cdOffset - 24)
            raf.readFully(footer)
            if (String(footer, 8, 16, Charsets.US_ASCII) != "APK Sig Block 42") return emptyList()
            val blockSize = ByteBuffer.wrap(footer, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
            if (blockSize < 24 || blockSize > cdOffset) return emptyList()
            val pairsLen = (blockSize - 24).toInt()
            val pairs = ByteArray(pairsLen)
            raf.seek(cdOffset - blockSize)  // start of block + 8 (skip leading size)
            raf.readFully(pairs)
            val buf = ByteBuffer.wrap(pairs).order(ByteOrder.LITTLE_ENDIAN)
            val ids = mutableListOf<Int>()
            while (buf.remaining() >= 12) {
                val pairLen = buf.long
                if (pairLen < 4 || pairLen > buf.remaining()) break
                ids.add(buf.int)
                buf.position(buf.position() + (pairLen - 4).toInt())
            }
            ids
        }
    } catch (_: Exception) {
        emptyList()
    }
}
