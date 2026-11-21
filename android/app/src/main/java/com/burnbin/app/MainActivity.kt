package com.burnbin.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.core.content.IntentCompat
import androidx.fragment.app.FragmentActivity
import com.burnbin.app.theme.BurnBinTheme
import com.burnbin.app.ui.main.MainScreen

class MainActivity : FragmentActivity() {
  private val incomingSharedText = mutableStateOf<String?>(null)
  private val sharedTextTrigger = mutableStateOf(0L)
  private val incomingSharedFileUri = mutableStateOf<Uri?>(null)
  private val sharedFileTrigger = mutableStateOf(0L)
  private val incomingDeepLinkUrl = mutableStateOf<String?>(null)
  private val deepLinkTrigger = mutableStateOf(0L)
  private var nextTriggerId = 1L

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
          MainScreen(
            modifier = Modifier.fillMaxSize().safeDrawingPadding(),
            initialSharedText = incomingSharedText.value,
            sharedTextTrigger = sharedTextTrigger.value,
            initialSharedFileUri = incomingSharedFileUri.value,
            sharedFileTrigger = sharedFileTrigger.value,
            initialDeepLinkUrl = incomingDeepLinkUrl.value,
            deepLinkTrigger = deepLinkTrigger.value,
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
        val uriString = intent.data?.toString() ?: intent.dataString
        if (!uriString.isNullOrBlank()) {
          incomingDeepLinkUrl.value = uriString
          deepLinkTrigger.value = nextTriggerId++
        }
      }
      Intent.ACTION_SEND -> {
        val streamUri = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)?.trim()
        if (streamUri != null) {
          incomingSharedFileUri.value = streamUri
          sharedFileTrigger.value = nextTriggerId++
          if (!text.isNullOrEmpty() && !text.contains("/secret/")) {
            incomingSharedText.value = text
            sharedTextTrigger.value = nextTriggerId++
          }
        } else if (!text.isNullOrEmpty() && text.contains("/secret/")) {
          incomingDeepLinkUrl.value = text
          deepLinkTrigger.value = nextTriggerId++
        } else if (!text.isNullOrEmpty()) {
          incomingSharedText.value = text
          sharedTextTrigger.value = nextTriggerId++
        }
      }
    }
  }
}
