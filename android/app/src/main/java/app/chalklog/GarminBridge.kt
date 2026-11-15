package app.chalklog

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.webkit.JavascriptInterface
import android.webkit.WebView
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Garmin Connect Personal API client, exposed to the page as window.ChalkNative.
 *
 * Flow, as documented by Garmin: the user's Personal API key is exchanged for an access token
 * (valid 24 hours, no refresh token), and the token authorises GET requests for their own data.
 *
 * The page can store or clear a key and ask for a GET path on Garmin's host. It can never read
 * the key or token back, and it cannot point a request at any other host.
 */
class GarminBridge(context: Context, private val web: WebView) {

    private val prefs = context.getSharedPreferences("garmin", Context.MODE_PRIVATE)
    private val io = Executors.newSingleThreadExecutor()

    @JavascriptInterface
    fun garminStatus(): String =
        JSONObject().put("hasKey", prefs.getString(KEY, null)?.let(::open) != null).toString()

    @JavascriptInterface
    fun garminSetKey(key: String) {
        prefs.edit().putString(KEY, seal(key.trim())).remove(TOKEN).remove(TOKEN_AT).apply()
    }

    @JavascriptInterface
    fun garminClearKey() {
        prefs.edit().clear().apply()
    }

    /** Runs GET [path] on Garmin and answers through window.__chalkNative(id, httpStatus, body). Status 0 means no connection. */
    @JavascriptInterface
    fun garminRequest(id: String, path: String) {
        io.execute {
            val (status, body) = try {
                request(path)
            } catch (e: HttpFailure) {
                e.status to ""
            } catch (e: Exception) {
                0 to (e.message ?: "")
            }
            web.post {
                web.evaluateJavascript(
                    "window.__chalkNative && window.__chalkNative(${JSONObject.quote(id)}, $status, ${JSONObject.quote(body)})",
                    null,
                )
            }
        }
    }

    private fun request(path: String): Pair<Int, String> {
        val safe = path.startsWith("/") && !path.startsWith("//") && !path.contains("..") &&
            path.none { it.isWhitespace() || it == '\\' || it == '@' }
        if (!safe) return 400 to "bad path"

        var result = get(path, token(refresh = false))
        if (result.first == 401) result = get(path, token(refresh = true))
        return result
    }

    private fun token(refresh: Boolean): String {
        val age = System.currentTimeMillis() - prefs.getLong(TOKEN_AT, 0)
        if (!refresh && age in 0 until TOKEN_LIFE_MS) {
            prefs.getString(TOKEN, null)?.let(::open)?.let { return it }
        }
        val key = prefs.getString(KEY, null)?.let(::open) ?: throw HttpFailure(401)

        val conn = connect("/personalapitoken-service/personal-api/personal-api-key/token")
        conn.requestMethod = "POST"
        conn.setRequestProperty("Authorization", "ApiKey $key")
        conn.setRequestProperty("Content-Length", "0")
        conn.doOutput = true
        conn.outputStream.close()
        val (status, body) = read(conn)
        if (status !in 200..299) throw HttpFailure(if (status == 403) 403 else 401)

        // Garmin documents the call but not the response shape, so accept the usual field names or a bare token.
        val token = runCatching {
            val json = JSONObject(body)
            listOf("access_token", "accessToken", "token").map { json.optString(it) }.firstOrNull { it.isNotBlank() }
        }.getOrNull() ?: body.trim().trim('"').takeIf { it.isNotBlank() && !it.startsWith("{") }
            ?: throw HttpFailure(502)

        prefs.edit().putString(TOKEN, seal(token)).putLong(TOKEN_AT, System.currentTimeMillis()).apply()
        return token
    }

    private fun get(path: String, token: String): Pair<Int, String> {
        val conn = connect(path)
        conn.setRequestProperty("Authorization", "Bearer $token")
        conn.setRequestProperty("Accept", "application/json")
        return read(conn)
    }

    private fun connect(path: String): HttpURLConnection =
        (URL(BASE + path).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 20_000
            instanceFollowRedirects = false
        }

    private fun read(conn: HttpURLConnection): Pair<Int, String> = try {
        val status = conn.responseCode
        val stream = if (status in 200..299) conn.inputStream else conn.errorStream
        status to (stream?.bufferedReader()?.use { it.readText() } ?: "")
    } finally {
        conn.disconnect()
    }

    // The key and token are encrypted with an AES key that never leaves the Android Keystore.
    private fun secret(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(spec)
            generateKey()
        }
    }

    private fun seal(plain: String): String {
        val cipher = Cipher.getInstance(AES_GCM).apply { init(Cipher.ENCRYPT_MODE, secret()) }
        return Base64.encodeToString(cipher.iv + cipher.doFinal(plain.toByteArray()), Base64.NO_WRAP)
    }

    /** Null when the stored value cannot be decrypted, for example after restoring a backup onto a new phone. */
    private fun open(sealed: String): String? = runCatching {
        val bytes = Base64.decode(sealed, Base64.NO_WRAP)
        val cipher = Cipher.getInstance(AES_GCM).apply {
            init(Cipher.DECRYPT_MODE, secret(), GCMParameterSpec(128, bytes, 0, IV_SIZE))
        }
        String(cipher.doFinal(bytes, IV_SIZE, bytes.size - IV_SIZE))
    }.getOrNull()

    private class HttpFailure(val status: Int) : Exception()

    private companion object {
        const val BASE = "https://personal.connectapi.garmin.com"
        const val KEY = "key"
        const val TOKEN = "token"
        const val TOKEN_AT = "tokenAt"
        const val TOKEN_LIFE_MS = 23L * 60 * 60 * 1000
        const val ALIAS = "chalklog_garmin"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val IV_SIZE = 12
    }
}
