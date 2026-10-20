package com.burnbin.app

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import com.burnbin.app.theme.BurnBinTheme

class MainActivity : ComponentActivity() {
  private val incomingSharedText = mutableStateOf<String?>(null)
  private val incomingDeepLinkUrl = mutableStateOf<String?>(null)

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    handleIncomingIntent(intent)

    enableEdgeToEdge()
    setContent {
      BurnBinTheme {
        Surface(
          modifier = Modifier.fillMaxSize(),
          color = MaterialTheme.colorScheme.background,
        ) {
          MainNavigation(
            initialSharedText = incomingSharedText.value,
            initialDeepLinkUrl = incomingDeepLinkUrl.value,
            onToggleSecureScreen = { enableSecure ->
              if (enableSecure) {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
              } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
              }
            },
          )
        }
      }
    }
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    handleIncomingIntent(intent)
  }

  private fun handleIncomingIntent(intent: Intent?) {
    if (intent == null) return
    when (intent.action) {
      Intent.ACTION_VIEW -> {
        val uriString = intent.dataString
        if (!uriString.isNullOrBlank()) {
          incomingDeepLinkUrl.value = uriString
        }
      }
      Intent.ACTION_SEND -> {
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)?.trim()
        if (!text.isNullOrEmpty() && text.contains("/secret/") && text.contains("#key=")) {
          incomingDeepLinkUrl.value = text
        } else if (!text.isNullOrEmpty()) {
          incomingSharedText.value = text
        }
      }
    }
  }
}
