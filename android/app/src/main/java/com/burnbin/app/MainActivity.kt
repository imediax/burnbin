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
import androidx.compose.ui.Modifier
import com.burnbin.app.theme.BurnBinTheme

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    val (sharedText, deepLinkUrl) = parseIncomingIntent(intent)

    enableEdgeToEdge()
    setContent {
      BurnBinTheme {
        Surface(
          modifier = Modifier.fillMaxSize(),
          color = MaterialTheme.colorScheme.background,
        ) {
          MainNavigation(
            initialSharedText = sharedText,
            initialDeepLinkUrl = deepLinkUrl,
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

  private fun parseIncomingIntent(intent: Intent?): Pair<String?, String?> {
    if (intent == null) return null to null
    return when (intent.action) {
      Intent.ACTION_VIEW -> {
        val uriString = intent.dataString
        null to uriString
      }
      Intent.ACTION_SEND -> {
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)?.trim()
        if (!text.isNullOrEmpty() && text.contains("/secret/") && text.contains("#key=")) {
          null to text
        } else {
          text to null
        }
      }
      else -> null to null
    }
  }
}
