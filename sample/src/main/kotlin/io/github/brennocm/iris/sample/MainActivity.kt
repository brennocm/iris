package io.github.brennocm.iris.sample

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import io.github.brennocm.iris.Iris

/**
 * Runs Iris once and shows the result. For scripted runs it also logs the output to logcat
 * (tag IrisSample), split into chunks because logcat truncates long lines:
 *
 *   adb shell am start -W -n io.github.brennocm.iris.sample/.MainActivity --es challenge <hex>
 *
 * Without a challenge it logs the report; with one it logs the signed message. Launching it
 * again while it is on top (no `-S`) runs a new inspection in the same process, which is how
 * the Frida scenario inspects after injecting into a running app.
 */
class MainActivity : Activity() {
    private lateinit var text: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        text = TextView(this).apply { setTextIsSelectable(true); setPadding(32, 32, 32, 32) }
        setContentView(ScrollView(this).apply { addView(text) })
        run(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        run(intent)
    }

    private fun run(intent: Intent) {
        val challenge = intent.getStringExtra("challenge")?.let(::hexToBytes)

        Thread {
            val iris = Iris()
            val (label, json) = if (challenge == null) {
                "report" to iris.inspect(applicationContext).toJson()
            } else {
                "message" to iris.inspectAndSign(applicationContext, challenge).toJson()
            }
            logChunked(label, json)
            runOnUiThread { text.text = json }
        }.start()
    }

    private fun logChunked(label: String, json: String) {
        val chunks = json.chunked(CHUNK)
        chunks.forEachIndexed { i, c -> Log.i(TAG, "$label ${i + 1}/${chunks.size} $c") }
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private companion object {
        const val TAG = "IrisSample"
        const val CHUNK = 3000
    }
}
