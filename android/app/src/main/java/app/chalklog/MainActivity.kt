package app.chalklog

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowInsets
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import java.io.ByteArrayInputStream
import java.io.SequenceInputStream
import java.util.Collections

/**
 * Hosts the tracker page (assets/index.html) in a WebView and gives it one native
 * capability the web cannot have: calling Garmin's Personal API (see GarminBridge).
 */
class MainActivity : Activity() {

    private lateinit var web: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        setContentView(web)

        // Keep the page clear of the status bar, navigation bar and keyboard.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            web.setOnApplyWindowInsetsListener { v, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                insets
            }
        }

        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(GarminBridge(applicationContext, web), "ChalkNative")
        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                val url = request.url
                if (url.host != HOST) return null
                return if (url.path == "/") page() else notFound()
            }

            // Anything that is not the app's own page (the Garmin key page, for one) opens in the browser,
            // so no other site ever runs inside this WebView next to the native bridge.
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (request.url.host == HOST) return false
                runCatching { startActivity(Intent(Intent.ACTION_VIEW, request.url)) }
                return true
            }
        }

        if (savedInstanceState == null) web.loadUrl("https://$HOST/") else web.restoreState(savedInstanceState)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web.saveState(outState)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Let the page close its own sheet or screen first; leave the app only when it has nothing open.
        web.evaluateJavascript("window.__chalkBack ? window.__chalkBack() : false") { handled ->
            if (handled != "true") finish()
        }
    }

    /** The asset is a page fragment; wrap it in the same document skeleton it was written for. */
    private fun page(): WebResourceResponse {
        val head = "<!doctype html><html><head><meta charset=\"utf-8\">" +
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">" +
            "<style>body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style></head><body>"
        val stream = SequenceInputStream(
            Collections.enumeration(
                listOf(
                    ByteArrayInputStream(head.toByteArray()),
                    assets.open("index.html"),
                    ByteArrayInputStream("</body></html>".toByteArray()),
                )
            )
        )
        return WebResourceResponse("text/html", "utf-8", stream)
    }

    private fun notFound() = WebResourceResponse(
        "text/plain", "utf-8", 404, "Not Found", emptyMap(), ByteArrayInputStream(ByteArray(0))
    )

    private companion object {
        // A made-up https origin served from assets, so the page gets a secure context and its own storage.
        const val HOST = "chalklog.localapp"
    }
}
