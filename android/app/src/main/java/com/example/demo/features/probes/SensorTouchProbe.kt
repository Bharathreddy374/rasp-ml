package com.example.demo.features.probes

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.BatteryManager
import android.os.Handler
import android.os.HandlerThread
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.support.NEEDS_COHORT
import com.example.demo.features.probes.support.NEEDS_UI
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.round
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Catalogue group 7 (F231 - F270).
 *
 * Samples accelerometer, gyroscope and magnetometer for [WINDOW_MS] and sends summary
 * statistics only: raw samples never leave the phone. Real MEMS sensors have a noise floor;
 * emulators and sensor-less devices are too clean, too periodic, or absent.
 *
 * Touch dynamics (F259 - F266) need capture inside the app's own screens and are unknown here.
 */
object SensorTouchProbe {

    private const val WINDOW_MS = 1500L
    private const val MIN_SAMPLES = 20
    private const val G = 9.80665

    private class Series {
        val t = ArrayList<Long>()
        val x = ArrayList<Double>()
        val y = ArrayList<Double>()
        val z = ArrayList<Double>()
        val size get() = t.size
        fun mag() = x.indices.map { sqrt(x[it] * x[it] + y[it] * y[it] + z[it] * z[it]) }
        fun axes() = listOf(x, y, z)
    }

    fun collect(context: Context): List<SignalResult> {
        val list = mutableListOf<SignalResult>()
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        val allSensors = sm?.getSensorList(Sensor.TYPE_ALL) ?: emptyList()
        val accel = sm?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val gyro = sm?.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
        val mag = sm?.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)

        val data = if (sm != null) sample(sm, listOfNotNull(accel, gyro, mag)) else emptyMap()
        val a = data[Sensor.TYPE_ACCELEROMETER]?.takeIf { it.size >= MIN_SAMPLES }
        val g = data[Sensor.TYPE_GYROSCOPE]?.takeIf { it.size >= MIN_SAMPLES }
        val m = data[Sensor.TYPE_MAGNETIC_FIELD]?.takeIf { it.size >= 3 }

        // ---- Accelerometer F231 - F240 ----
        val accelWhy = if (accel == null) "no accelerometer" else "too few accelerometer samples"
        listOf("F231" to "accel_std_x", "F232" to "accel_std_y", "F233" to "accel_std_z").forEachIndexed { i, (id, name) ->
            list.add(if (a == null) unknown(id, name, accelWhy) else {
                val sd = r(std(a.axes()[i]), 5)
                measured(id, name, "$sd m/s²", sd, if (sd == 0.0) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                    "Standard deviation over ${a.size} samples; exactly 0 means a synthetic sensor.")
            })
        }
        listOf("F234" to "accel_kurtosis_x", "F235" to "accel_kurtosis_y", "F236" to "accel_kurtosis_z").forEachIndexed { i, (id, name) ->
            list.add(if (a == null) unknown(id, name, accelWhy) else {
                val k = r(kurtosis(a.axes()[i]), 3)
                measured(id, name, "$k", k, details = "Kurtosis of the axis (about 3 for Gaussian sensor noise).")
            })
        }
        list.add(if (a == null) unknown("F237", "gravity_magnitude_error", accelWhy) else {
            val err = r(abs(a.mag().average() - G), 4)
            measured("F237", "gravity_magnitude_error", "$err m/s²", err,
                if (err > 2.0) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                "Mean |acceleration| minus standard gravity; a real phone at rest reads close to 9.81.")
        })
        val aRate = a?.let { rate(it) }
        list.add(if (a == null) unknown("F238", "accel_spectral_flatness", accelWhy) else {
            val f = r(spectralFlatness(a.mag()), 4)
            measured("F238", "accel_spectral_flatness", "$f", f, details = "Spectral flatness of |a| (1 = white noise, 0 = pure tone).")
        })
        list.add(if (a == null || aRate == null) unknown("F239", "accel_dominant_freq_hz", accelWhy) else {
            val hz = r(dominantFreq(a.mag(), aRate), 2)
            measured("F239", "accel_dominant_freq_hz", "$hz Hz", hz, details = "Strongest frequency in |a|.")
        })
        list.add(if (a == null) unknown("F240", "accel_repeat_sample_count", accelWhy) else {
            val rep = repeats(a)
            measured("F240", "accel_repeat_sample_count", "$rep of ${a.size}", rep,
                if (rep > a.size / 2) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                "Consecutive identical samples; replayed or emulated sensors repeat values.")
        })

        // ---- Gyroscope F241 - F248 ----
        val gyroWhy = if (gyro == null) "no gyroscope" else "too few gyroscope samples"
        listOf("F241" to "gyro_std_x", "F242" to "gyro_std_y", "F243" to "gyro_std_z").forEachIndexed { i, (id, name) ->
            list.add(if (g == null) unknown(id, name, gyroWhy) else {
                val sd = r(std(g.axes()[i]), 6)
                measured(id, name, "$sd rad/s", sd, if (sd == 0.0) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                    "Standard deviation over ${g.size} samples.")
            })
        }
        list.add(if (g == null) unknown("F244", "gyro_bias_estimate", gyroWhy) else {
            val b = r(g.mag().average(), 6)
            measured("F244", "gyro_bias_estimate", "$b rad/s", b, details = "Mean |ω| over the window (bias plus motion).")
        })
        list.add(if (g == null) unknown("F245", "gyro_spectral_flatness", gyroWhy) else {
            val f = r(spectralFlatness(g.mag()), 4)
            measured("F245", "gyro_spectral_flatness", "$f", f, details = "Spectral flatness of |ω|.")
        })
        list.add(if (g == null) unknown("F246", "gyro_dominant_freq_hz", gyroWhy) else {
            val hz = r(dominantFreq(g.mag(), rate(g)), 2)
            measured("F246", "gyro_dominant_freq_hz", "$hz Hz", hz, details = "Strongest frequency in |ω|.")
        })
        list.add(if (g == null) unknown("F247", "gyro_repeat_sample_count", gyroWhy) else {
            val rep = repeats(g)
            measured("F247", "gyro_repeat_sample_count", "$rep of ${g.size}", rep,
                if (rep > g.size / 2) RiskLevel.SUSPICIOUS else RiskLevel.SAFE, "Consecutive identical gyroscope samples.")
        })
        list.add(if (g == null) unknown("F248", "gyro_zero_rate_noise", gyroWhy) else {
            val n = r(std(g.mag()), 6)
            measured("F248", "gyro_zero_rate_noise", "$n rad/s", n, details = "Standard deviation of |ω|.")
        })

        // ---- Cross-sensor F249 - F254 ----
        list.add(if (a == null || g == null) unknown("F249", "accel_gyro_xcorr_lag0", "needs accelerometer and gyroscope samples") else {
            val c = r(xcorr(a, g), 4)
            measured("F249", "accel_gyro_xcorr_lag0", "$c", c, details = "Pearson correlation of |a| and |ω| paired by timestamp.")
        })
        list.add(if (m == null) unknown("F250", "accel_mag_consistency", if (mag == null) "no magnetometer" else "too few magnetometer samples") else {
            val field = r(m.mag().average(), 2)
            val ok = field in 20.0..80.0
            measured("F250", "accel_mag_consistency", "$field µT", field, if (ok) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                "Magnetic field strength; Earth's field is about 25-65 µT.")
        })
        list.add(if (a == null || aRate == null || aRate < 25) unknown("F251", "tremor_band_energy_8_12hz", "needs ≥25 Hz accelerometer samples") else {
            val e = r(bandEnergy(a.mag(), aRate, 8.0, 12.0), 4)
            measured("F251", "tremor_band_energy_8_12hz", "$e of total", e, details = "Share of |a| energy in the 8-12 Hz hand-tremor band.")
        })
        list.add(if (a == null) unknown("F252", "sensor_timestamp_jitter_cv", accelWhy) else {
            val dts = a.t.zipWithNext { p, q -> (q - p).toDouble() }
            val cv = r(std(dts) / dts.average(), 4)
            measured("F252", "sensor_timestamp_jitter_cv", "$cv", cv, details = "Coefficient of variation of sample intervals.")
        })
        list.add(if (a == null || aRate == null) unknown("F253", "sensor_sample_rate_actual", accelWhy) else
            measured("F253", "sensor_sample_rate_actual", "${r(aRate, 1)} Hz", r(aRate, 1), details = "Delivered accelerometer rate (requested SENSOR_DELAY_GAME)."))
        list.add(if (a == null) unknown("F254", "sensor_quantization_step", accelWhy) else {
            val q = r(quantStep(a.x), 6)
            measured("F254", "sensor_quantization_step", "$q m/s²", q, details = "Smallest step between distinct X readings (ADC resolution).")
        })

        // ---- Presence F255 - F258 ----
        list.add(measured("F255", "sensor_count", "${allSensors.size} sensors registered", allSensors.size,
            if (allSensors.size >= 5) RiskLevel.SAFE else RiskLevel.SUSPICIOUS, "Total sensors reported by SensorManager."))
        val vendor = accel?.vendor ?: "none"
        val knownVendor = listOf("Bosch", "STMicro", "InvenSense", "Qualcomm", "TDK", "AKM", "Samsung", "Sony", "MEMSIC")
            .any { vendor.contains(it, true) }
        list.add(measured("F256", "sensor_vendor_known", vendor, vendor.take(64),
            if (accel == null || knownVendor) RiskLevel.SAFE else RiskLevel.INFO, "Accelerometer vendor string."))
        list.add(unknown("F257", "sensor_vendor_vs_model", NEEDS_COHORT))
        list.add(if (accel == null) unknown("F258", "sensor_power_draw_plausible", "no accelerometer") else {
            val p = r(accel.power.toDouble(), 3)
            measured("F258", "sensor_power_draw_plausible", "$p mA", p,
                if (p > 0 && p < 5) RiskLevel.SAFE else RiskLevel.SUSPICIOUS, "Declared accelerometer power draw.")
        })

        // ---- Touch F259 - F266 ----
        listOf("F259" to "touch_pressure_mean", "F260" to "touch_pressure_var", "F261" to "touch_size_mean",
            "F262" to "touch_inter_event_ms_cv", "F263" to "touch_velocity_profile", "F264" to "touch_down_up_ms",
            "F265" to "touch_pos_entropy", "F266" to "touch_synthetic_flag").forEach { (id, name) -> list.add(unknown(id, name, NEEDS_UI)) }

        // ---- Battery F267 - F270 ----
        val battery = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = battery?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = battery?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        if (battery == null || level < 0) {
            list.add(unknown("F267", "battery_level_delta", "battery state unavailable"))
            list.add(unknown("F268", "battery_temp_variation", "battery state unavailable"))
            list.add(unknown("F269", "charging_state_changes", "battery state unavailable"))
        } else {
            val pct = if (scale > 0) level * 100 / scale else level
            val tempC = battery.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) / 10.0
            val status = battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            val charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
            list.add(measured("F267", "battery_level_delta", "$pct%", pct,
                details = "Battery level now; the backend tracks the change across requests."))
            list.add(measured("F268", "battery_temp_variation", "$tempC °C", tempC,
                if (tempC in 15.0..55.0) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                "Battery temperature now (emulators often report 0 or exactly 25.0)."))
            list.add(measured("F269", "charging_state_changes", if (charging) "Charging" else "Not charging", charging,
                details = "Charging state now; the backend counts changes across requests."))
        }
        list.add(unknown("F270", "battery_static_over_session", "needs this install's history on the backend"))
        return list
    }

    // ---------- sampling ----------

    private fun sample(sm: SensorManager, sensors: List<Sensor>): Map<Int, Series> {
        if (sensors.isEmpty()) return emptyMap()
        val series = sensors.associate { it.type to Series() }
        val thread = HandlerThread("probe-sensors").apply { start() }
        val listener = object : SensorEventListener {
            override fun onSensorChanged(e: SensorEvent) {
                val s = series[e.sensor.type] ?: return
                synchronized(s) {
                    s.t.add(e.timestamp)
                    s.x.add(e.values[0].toDouble()); s.y.add(e.values[1].toDouble()); s.z.add(e.values[2].toDouble())
                }
            }
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }
        try {
            val handler = Handler(thread.looper)
            sensors.forEach { sm.registerListener(listener, it, SensorManager.SENSOR_DELAY_GAME, handler) }
            Thread.sleep(WINDOW_MS)
        } finally {
            sm.unregisterListener(listener)
            thread.quitSafely()
        }
        return series.mapValues { (_, s) -> synchronized(s) { s } }
    }

    // ---------- statistics ----------

    private fun r(x: Double, digits: Int): Double {
        if (x.isNaN() || x.isInfinite()) return 0.0
        val f = Math.pow(10.0, digits.toDouble())
        return round(x * f) / f
    }

    private fun std(v: List<Double>): Double {
        if (v.size < 2) return 0.0
        val m = v.average()
        return sqrt(v.sumOf { (it - m) * (it - m) } / v.size)
    }

    private fun kurtosis(v: List<Double>): Double {
        val m = v.average()
        val m2 = v.sumOf { (it - m) * (it - m) } / v.size
        if (m2 == 0.0) return 0.0
        return v.sumOf { val d = it - m; d * d * d * d } / v.size / (m2 * m2)
    }

    private fun rate(s: Series): Double {
        val span = (s.t.last() - s.t.first()) / 1e9
        return if (span > 0) (s.size - 1) / span else 0.0
    }

    private fun repeats(s: Series): Int = (1 until s.size).count { s.x[it] == s.x[it - 1] && s.y[it] == s.y[it - 1] && s.z[it] == s.z[it - 1] }

    /** Power spectrum (bins 1..n/2) of the de-meaned series, by direct DFT on the last 128 points. */
    private fun power(v: List<Double>): DoubleArray {
        val x = v.takeLast(128)
        val n = x.size
        val m = x.average()
        return DoubleArray(n / 2) { k0 ->
            val k = k0 + 1
            var re = 0.0; var im = 0.0
            for (t in 0 until n) {
                val ang = 2 * PI * k * t / n
                re += (x[t] - m) * cos(ang); im -= (x[t] - m) * sin(ang)
            }
            re * re + im * im
        }
    }

    private fun spectralFlatness(v: List<Double>): Double {
        val p = power(v).map { it + 1e-18 }
        if (p.isEmpty()) return 0.0
        val geo = exp(p.sumOf { ln(it) } / p.size)
        return geo / p.average()
    }

    private fun dominantFreq(v: List<Double>, fs: Double): Double {
        val p = power(v)
        if (p.isEmpty() || fs <= 0) return 0.0
        val k = p.indices.maxByOrNull { p[it] }!! + 1
        return k * fs / minOf(v.size, 128)
    }

    private fun bandEnergy(v: List<Double>, fs: Double, lo: Double, hi: Double): Double {
        val p = power(v)
        val n = minOf(v.size, 128)
        val total = p.sum()
        if (total <= 0) return 0.0
        return p.indices.filter { val f = (it + 1) * fs / n; f in lo..hi }.sumOf { p[it] } / total
    }

    private fun xcorr(a: Series, g: Series): Double {
        val am = a.mag(); val gm = g.mag()
        var j = 0
        val pairs = a.t.indices.map { i ->
            while (j + 1 < g.size && abs(g.t[j + 1] - a.t[i]) <= abs(g.t[j] - a.t[i])) j++
            am[i] to gm[j]
        }
        val xs = pairs.map { it.first }; val ys = pairs.map { it.second }
        val mx = xs.average(); val my = ys.average()
        val cov = pairs.sumOf { (it.first - mx) * (it.second - my) }
        val den = sqrt(xs.sumOf { (it - mx) * (it - mx) } * ys.sumOf { (it - my) * (it - my) })
        return if (den == 0.0) 0.0 else cov / den
    }

    private fun quantStep(v: List<Double>): Double =
        v.distinct().sorted().zipWithNext { p, q -> q - p }.filter { it > 0 }.minOrNull() ?: 0.0
}
