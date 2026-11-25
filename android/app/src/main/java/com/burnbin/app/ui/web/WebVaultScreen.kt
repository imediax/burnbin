package com.burnbin.app.ui.web

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BgSurfaceElevated
import com.burnbin.app.theme.TextSecondary

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WebVaultScreen(
  serverUrl: String,
  onOpenSecretInApp: (String) -> Unit,
) {
  var isLoading by remember { mutableStateOf(true) }
  var webViewRef by remember { mutableStateOf<WebView?>(null) }
  var loadedBaseUrl by remember { mutableStateOf(serverUrl) }
  val currentServerUrl by rememberUpdatedState(serverUrl)

  DisposableEffect(Unit) {
    onDispose {
      webViewRef?.apply {
        stopLoading()
        clearHistory()
        destroy()
      }
      webViewRef = null
    }
  }

  Column(modifier = Modifier.fillMaxSize()) {
    Row(
      modifier =
        Modifier
          .fillMaxWidth()
          .background(BgSurfaceElevated)
          .padding(horizontal = 16.dp, vertical = 8.dp),
      horizontalArrangement = Arrangement.SpaceBetween,
      verticalAlignment = Alignment.CenterVertically,
    ) {
      Text(
        text = serverUrl,
        color = TextSecondary,
        fontFamily = FontFamily.Monospace,
        fontSize = 12.sp,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = Modifier.weight(1f),
      )
      TextButton(
        onClick = { webViewRef?.reload() },
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
      ) {
        Text(text = "↻ Reload", color = AccentPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
      }
    }

    if (isLoading) {
      LinearProgressIndicator(
        color = AccentPrimary,
        trackColor = BgSurface,
        modifier = Modifier.fillMaxWidth().height(2.dp),
      )
    }

    AndroidView(
      factory = { ctx ->
        WebView(ctx).apply {
          settings.javaScriptEnabled = true
          settings.domStorageEnabled = true
          settings.allowFileAccess = false
          settings.allowContentAccess = false
          webViewClient =
            object : WebViewClient() {
              override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val uri = request?.url ?: return false
                val urlStr = uri.toString()
                val activeHost = Uri.parse(currentServerUrl).host.orEmpty()
                if (urlStr.startsWith("intent://", ignoreCase = true)) {
                  val cleanHttps = "https://" + urlStr.removePrefix("intent://").substringBefore("#Intent")
                  val parsed = Uri.parse(cleanHttps)
                  val hostMatches =
                    activeHost.isNotBlank() && parsed.host.equals(activeHost, ignoreCase = true)
                  val pathMatches = (parsed.path ?: "").startsWith("/secret/")
                  if (hostMatches && pathMatches) {
                    onOpenSecretInApp(cleanHttps)
                  }
                  return true
                }
                val scheme = uri.scheme?.lowercase().orEmpty()
                if (scheme == "http" || scheme == "https") {
                  if (activeHost.isNotBlank() && uri.host.equals(activeHost, ignoreCase = true)) {
                    return false
                  }
                  try {
                    val externalIntent =
                      Intent(Intent.ACTION_VIEW, uri).apply {
                        addCategory(Intent.CATEGORY_BROWSABLE)
                        if (ctx !is Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                      }
                    ctx.startActivity(externalIntent)
                  } catch (_: Exception) {
                    // Ignore when no external browser is available
                  }
                  return true
                }
                return true
              }

              override fun onPageFinished(view: WebView?, url: String?) {
                isLoading = false
              }
            }
          webChromeClient = WebChromeClient()
          loadUrl(serverUrl)
          webViewRef = this
        }
      },
      update = { view ->
        if (loadedBaseUrl != serverUrl) {
          loadedBaseUrl = serverUrl
          isLoading = true
          view.loadUrl(serverUrl)
        }
      },
      modifier = Modifier.fillMaxSize(),
    )
  }
}
