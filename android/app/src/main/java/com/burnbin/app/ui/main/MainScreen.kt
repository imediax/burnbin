package com.burnbin.app.ui.main

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.navigation3.runtime.NavKey
import com.burnbin.app.crypto.DecodedAttachment
import com.burnbin.app.crypto.ParsedSecretLink
import com.burnbin.app.crypto.SecretCrypto
import com.burnbin.app.data.BurnBinApiClient
import com.burnbin.app.data.ConsumedSecretResponse
import com.burnbin.app.data.SecretMetaResponse
import com.burnbin.app.security.authenticateForReveal
import com.burnbin.app.security.canAuthenticateDeviceOrBiometric
import com.burnbin.app.security.clearClipboard
import com.burnbin.app.security.copyToClipboard
import com.burnbin.app.security.formatByteSize
import com.burnbin.app.security.generateQrBitmap
import com.burnbin.app.security.readClipboard
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.burnbin.app.theme.AccentDarkText
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BgSurfaceElevated
import com.burnbin.app.theme.BorderColor
import com.burnbin.app.theme.BurnBinTheme
import com.burnbin.app.theme.DangerPrimary
import com.burnbin.app.theme.DangerTextLight
import com.burnbin.app.theme.InfoPrimary
import com.burnbin.app.theme.InfoTextLight
import com.burnbin.app.theme.SecretGreenText
import com.burnbin.app.theme.TextMuted
import com.burnbin.app.theme.TextPrimary
import com.burnbin.app.theme.TextSecondary
import com.burnbin.app.theme.WarningPrimary
import com.burnbin.app.theme.WarningTextLight
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

enum class BurnBinTab {
  CREATE,
  REVEAL,
  WEB,
}

@Serializable
private data class TrackedSecretItem(
  val id: String,
  val baseUrl: String,
  val label: String = "",
  val createdAtMs: Long,
  val expiresAtMs: Long,
  val maxViews: Int,
  val viewsLeft: Int,
  val deleteToken: String = "",
  val hasAttachment: Boolean = false,
  val status: String = "active",
)

private const val SENT_SECRETS_PREF_KEY = "burnbin_sent_secrets"
private val trackerJson = Json { ignoreUnknownKeys = true }

private fun loadTrackedSecrets(prefs: SharedPreferences): List<TrackedSecretItem> {
  val raw = prefs.getString(SENT_SECRETS_PREF_KEY, null) ?: return emptyList()
  return try {
    val parsed = trackerJson.decodeFromString<List<TrackedSecretItem>>(raw)
    val cutoff = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000
    parsed.filter { it.expiresAtMs > cutoff }
  } catch (_: Exception) {
    emptyList()
  }
}

private fun saveTrackedSecrets(prefs: SharedPreferences, items: List<TrackedSecretItem>) {
  val encoded = trackerJson.encodeToString(items.take(25))
  prefs.edit().putString(SENT_SECRETS_PREF_KEY, encoded).apply()
}

private fun formatExpiryCountdown(expiresAtMs: Long): String {
  val diffSec = (expiresAtMs - System.currentTimeMillis()) / 1000L
  return when {
    diffSec <= 0L -> "Expired"
    diffSec < 60L -> "${diffSec}s left"
    diffSec < 3600L -> "${(diffSec + 59) / 60}m left"
    diffSec < 86400L -> "${(diffSec + 3599) / 3600}h left"
    else -> "${(diffSec + 86399) / 86400}d left"
  }
}

private fun readAttachmentFromUri(context: Context, uri: Uri): Result<DecodedAttachment> {
  return try {
    val resolver = context.contentResolver
    var fileName = "attachment.bin"
    var declaredSize = -1L
    resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
      if (cursor.moveToFirst()) {
        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (nameIdx >= 0) {
          cursor.getString(nameIdx)?.takeIf { it.isNotBlank() }?.let { fileName = it }
        }
        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
        if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) {
          declaredSize = cursor.getLong(sizeIdx)
        }
      }
    }
    if (declaredSize > SecretCrypto.MAX_ATTACHMENT_BYTES) {
      return Result.failure(IllegalArgumentException("File \"$fileName\" exceeds the 1 MB attachment limit."))
    }
    val bytes =
      resolver.openInputStream(uri)?.use { stream ->
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (true) {
          val read = stream.read(buf)
          if (read <= 0) break
          total += read
          if (total > SecretCrypto.MAX_ATTACHMENT_BYTES) {
            return Result.failure(IllegalArgumentException("File \"$fileName\" exceeds the 1 MB attachment limit."))
          }
          out.write(buf, 0, read)
        }
        out.toByteArray()
      } ?: return Result.failure(IllegalArgumentException("Could not open selected file."))

    val mime = resolver.getType(uri)?.takeIf { it.isNotBlank() } ?: "application/octet-stream"
    Result.success(
      DecodedAttachment(
        name = fileName,
        mime = mime,
        size = bytes.size,
        bytes = bytes,
      )
    )
  } catch (e: Exception) {
    Result.failure(IllegalArgumentException("Failed to read file: ${e.message ?: "Unknown error"}"))
  }
}

private sealed interface RevealUiState {
  data object Idle : RevealUiState
  data object CheckingVault : RevealUiState
  data class Error(val message: String) : RevealUiState
  data class PreReveal(
    val parsedLink: ParsedSecretLink,
    val meta: SecretMetaResponse,
    val cachedConsumed: ConsumedSecretResponse? = null,
    val passphraseError: String? = null,
    val isRevealing: Boolean = false,
  ) : RevealUiState
  data class Revealed(
    val plaintext: String,
    val attachment: DecodedAttachment? = null,
    val burned: Boolean,
    val viewsLeft: Int,
  ) : RevealUiState
}

@Composable
fun MainScreen(
  onItemClick: (NavKey) -> Unit = {},
  modifier: Modifier = Modifier,
  initialSharedText: String? = null,
  sharedTextTrigger: Long = 0L,
  initialDeepLinkUrl: String? = null,
  deepLinkTrigger: Long = 0L,
  onToggleSecureScreen: (Boolean) -> Unit = {},
) {
  val context = LocalContext.current
  val prefs = remember { context.getSharedPreferences("burnbin_prefs", Context.MODE_PRIVATE) }

  var serverUrl by rememberSaveable {
    mutableStateOf(prefs.getString("server_url", BurnBinApiClient.DEFAULT_SERVER_URL) ?: BurnBinApiClient.DEFAULT_SERVER_URL)
  }
  var secureScreenEnabled by rememberSaveable {
    mutableStateOf(prefs.getBoolean("secure_screen", false))
  }
  var autoClearClipboardEnabled by rememberSaveable {
    mutableStateOf(prefs.getBoolean("auto_clear_clipboard", true))
  }
  var biometricRevealEnabled by rememberSaveable {
    mutableStateOf(prefs.getBoolean("biometric_reveal", false))
  }
  var isRevealedVisible by remember { mutableStateOf(false) }
  var showSettingsDialog by rememberSaveable { mutableStateOf(false) }

  var activeTab by rememberSaveable {
    mutableStateOf(if (!initialDeepLinkUrl.isNullOrBlank()) BurnBinTab.REVEAL else BurnBinTab.CREATE)
  }
  var revealInputUrl by rememberSaveable { mutableStateOf(initialDeepLinkUrl ?: "") }
  var autoCheckTrigger by rememberSaveable { mutableIntStateOf(0) }
  var lastHandledDeepLinkTrigger by rememberSaveable { mutableStateOf(-1L) }
  var lastHandledSharedTextTrigger by rememberSaveable { mutableStateOf(-1L) }
  var sharedSecretInput by rememberSaveable { mutableStateOf(initialSharedText ?: "") }

  LaunchedEffect(secureScreenEnabled, activeTab, isRevealedVisible) {
    onToggleSecureScreen(
      secureScreenEnabled || (activeTab == BurnBinTab.REVEAL && isRevealedVisible)
    )
  }

  LaunchedEffect(initialDeepLinkUrl, deepLinkTrigger) {
    if (!initialDeepLinkUrl.isNullOrBlank() && deepLinkTrigger != lastHandledDeepLinkTrigger) {
      lastHandledDeepLinkTrigger = deepLinkTrigger
      revealInputUrl = initialDeepLinkUrl
      autoCheckTrigger++
      activeTab = BurnBinTab.REVEAL
    }
  }

  LaunchedEffect(initialSharedText, sharedTextTrigger) {
    if (!initialSharedText.isNullOrBlank() && sharedTextTrigger != lastHandledSharedTextTrigger) {
      lastHandledSharedTextTrigger = sharedTextTrigger
      sharedSecretInput = initialSharedText
      activeTab = BurnBinTab.CREATE
    }
  }

  Column(
    modifier =
      modifier
        .fillMaxSize()
        .background(BgPrimary)
  ) {
    // Sticky Header Bar
    BurnBinHeader(
      onLogoClick = { activeTab = BurnBinTab.CREATE },
      onSettingsClick = { showSettingsDialog = true },
    )

    // Mode Navigation Bar
    BurnBinTabBar(
      activeTab = activeTab,
      onTabSelected = { activeTab = it },
    )

    // Active Content
    Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
      when (activeTab) {
        BurnBinTab.CREATE -> {
          CreateSecretView(
            serverUrl = serverUrl,
            initialText = sharedSecretInput,
            sharedTextTrigger = sharedTextTrigger,
            onOpenInReveal = { generatedLink ->
              revealInputUrl = generatedLink
              autoCheckTrigger++
              activeTab = BurnBinTab.REVEAL
            },
          )
        }
        BurnBinTab.REVEAL -> {
          RevealSecretView(
            serverUrl = serverUrl,
            linkInput = revealInputUrl,
            onLinkInputChange = { revealInputUrl = it },
            autoCheckTrigger = autoCheckTrigger,
            onAutoCheckConsumed = { autoCheckTrigger = 0 },
            biometricRevealEnabled = biometricRevealEnabled,
            autoClearClipboardEnabled = autoClearClipboardEnabled,
            onRevealedVisibilityChanged = { visible -> isRevealedVisible = visible },
            onCreateNewClick = {
              revealInputUrl = ""
              autoCheckTrigger = 0
              activeTab = BurnBinTab.CREATE
            },
          )
        }
        BurnBinTab.WEB -> {
          WebVaultView(
            serverUrl = serverUrl,
            onOpenSecretInApp = { secretUrl ->
              revealInputUrl = secretUrl
              autoCheckTrigger++
              activeTab = BurnBinTab.REVEAL
            },
          )
        }
      }
    }
  }

  if (showSettingsDialog) {
    ServerSettingsDialog(
      currentServerUrl = serverUrl,
      secureScreenEnabled = secureScreenEnabled,
      autoClearClipboardEnabled = autoClearClipboardEnabled,
      biometricRevealEnabled = biometricRevealEnabled,
      onDismiss = { showSettingsDialog = false },
      onSave = { newUrl, newSecure, newAutoClear, newBiometric ->
        val cleaned = newUrl.trim().trimEnd('/').ifEmpty { BurnBinApiClient.DEFAULT_SERVER_URL }
        serverUrl = cleaned
        secureScreenEnabled = newSecure
        autoClearClipboardEnabled = newAutoClear
        biometricRevealEnabled = newBiometric
        prefs.edit()
          .putString("server_url", cleaned)
          .putBoolean("secure_screen", newSecure)
          .putBoolean("auto_clear_clipboard", newAutoClear)
          .putBoolean("biometric_reveal", newBiometric)
          .apply()
        showSettingsDialog = false
        Toast.makeText(context, "Settings saved", Toast.LENGTH_SHORT).show()
      },
    )
  }
}

@Composable
private fun BurnBinHeader(
  onLogoClick: () -> Unit,
  onSettingsClick: () -> Unit,
) {
  Column(
    modifier =
      Modifier
        .fillMaxWidth()
        .background(BgSurface.copy(alpha = 0.95f))
  ) {
    Row(
      modifier =
        Modifier
          .fillMaxWidth()
          .padding(horizontal = 16.dp, vertical = 14.dp),
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.SpaceBetween,
    ) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.clickable { onLogoClick() },
      ) {
        Text(text = "🔥", fontSize = 22.sp)
        Spacer(modifier = Modifier.width(8.dp))
        Text(
          text = "BurnBin",
          color = TextPrimary,
          fontSize = 20.sp,
          fontWeight = FontWeight.Bold,
        )
      }

      Row(verticalAlignment = Alignment.CenterVertically) {
        // E2EE Badge
        Box(
          modifier =
            Modifier
              .background(AccentPrimary.copy(alpha = 0.12f), CircleShape)
              .border(1.dp, AccentPrimary.copy(alpha = 0.35f), CircleShape)
              .padding(horizontal = 10.dp, vertical = 4.dp)
        ) {
          Text(
            text = "🛡️ ZERO-KNOWLEDGE",
            color = AccentPrimary,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.5.sp,
          )
        }

        Spacer(modifier = Modifier.width(8.dp))

        // Settings gear icon
        Surface(
          onClick = onSettingsClick,
          color = BgSurfaceElevated,
          shape = RoundedCornerShape(8.dp),
          border = BorderStroke(1.dp, BorderColor),
        ) {
          Text(
            text = "⚙️",
            fontSize = 15.sp,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
          )
        }
      }
    }
    HorizontalDivider(color = BorderColor, thickness = 1.dp)
  }
}

@Composable
private fun BurnBinTabBar(
  activeTab: BurnBinTab,
  onTabSelected: (BurnBinTab) -> Unit,
) {
  Row(
    modifier =
      Modifier
        .fillMaxWidth()
        .padding(horizontal = 16.dp, vertical = 10.dp)
        .background(BgSurface, RoundedCornerShape(12.dp))
        .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
        .padding(4.dp),
    horizontalArrangement = Arrangement.spacedBy(4.dp),
  ) {
    val tabs =
      listOf(
        BurnBinTab.CREATE to "🔒 Create Secret",
        BurnBinTab.REVEAL to "🔓 Reveal Secret",
        BurnBinTab.WEB to "🌐 Web Vault",
      )
    tabs.forEach { (tab, title) ->
      val selected = activeTab == tab
      Box(
        modifier =
          Modifier
            .weight(1f)
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) AccentPrimary else Color.Transparent)
            .clickable { onTabSelected(tab) }
            .padding(vertical = 9.dp),
        contentAlignment = Alignment.Center,
      ) {
        Text(
          text = title,
          color = if (selected) AccentDarkText else TextSecondary,
          fontSize = 13.sp,
          fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
    }
  }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CreateSecretView(
  serverUrl: String,
  initialText: String,
  sharedTextTrigger: Long = 0L,
  onOpenInReveal: (String) -> Unit,
) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val scrollState = rememberScrollState()

  var secretText by rememberSaveable { mutableStateOf(initialText) }
  var selectedTtlSeconds by rememberSaveable { mutableIntStateOf(3600) }
  var selectedMaxViews by rememberSaveable { mutableIntStateOf(1) }
  var usePassphrase by rememberSaveable { mutableStateOf(false) }
  var passphrase by rememberSaveable { mutableStateOf("") }
  var showPassphraseText by rememberSaveable { mutableStateOf(false) }

  var isSubmitting by rememberSaveable { mutableStateOf(false) }
  var statusLabel by rememberSaveable { mutableStateOf("") }
  var errorBanner by rememberSaveable { mutableStateOf<String?>(null) }
  var generatedShareUrl by rememberSaveable { mutableStateOf<String?>(null) }
  var generatedSecretId by rememberSaveable { mutableStateOf<String?>(null) }
  var generatedUrlKey by rememberSaveable { mutableStateOf<String?>(null) }
  var useQueryKeyFormat by rememberSaveable { mutableStateOf(true) }
  var copyFeedback by rememberSaveable { mutableStateOf(false) }
  var lastAppliedShareTrigger by rememberSaveable { mutableStateOf(sharedTextTrigger) }
  var localLabel by rememberSaveable { mutableStateOf("") }
  var selectedAttachment by remember { mutableStateOf<DecodedAttachment?>(null) }
  var showQrCard by rememberSaveable { mutableStateOf(false) }
  var trackedExpanded by rememberSaveable { mutableStateOf(false) }
  var lastUsedPassphrase by rememberSaveable { mutableStateOf(false) }

  val prefs = remember { context.getSharedPreferences("burnbin_prefs", Context.MODE_PRIVATE) }
  var trackedSecrets by remember { mutableStateOf(loadTrackedSecrets(prefs)) }

  val attachmentPickerLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
      if (uri != null) {
        scope.launch {
          val fileRes = withContext(Dispatchers.IO) { readAttachmentFromUri(context, uri) }
          fileRes
            .onSuccess { attachment ->
              selectedAttachment = attachment
              errorBanner = null
            }
            .onFailure { err ->
              errorBanner = err.message ?: "Could not attach selected file."
            }
        }
      }
    }

  LaunchedEffect(initialText, sharedTextTrigger) {
    if (sharedTextTrigger > 0L && sharedTextTrigger != lastAppliedShareTrigger && initialText.isNotBlank()) {
      lastAppliedShareTrigger = sharedTextTrigger
      secretText = initialText
      generatedShareUrl = null
      generatedSecretId = null
      generatedUrlKey = null
      errorBanner = null
      copyFeedback = false
    }
  }

  val ttlOptions =
    listOf(
      600 to "10 mins",
      3600 to "1 hour",
      86400 to "24 hours",
      604800 to "7 days",
    )

  val viewOptions =
    listOf(
      1 to "1 view (Single-use)",
      3 to "3 views",
      5 to "5 views",
    )

  Column(
    modifier =
      Modifier
        .fillMaxSize()
        .verticalScroll(scrollState)
        .padding(horizontal = 16.dp, vertical = 6.dp),
    verticalArrangement = Arrangement.spacedBy(16.dp),
  ) {
    if (generatedShareUrl == null) {
      // Creation Form Card
      Surface(
        color = BgSurface,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderColor),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Column(modifier = Modifier.padding(20.dp)) {
          Text(
            text = "Share a Self-Destructing Secret",
            color = TextPrimary,
            fontSize = 21.sp,
            fontWeight = FontWeight.Bold,
          )
          Spacer(modifier = Modifier.height(6.dp))
          Text(
            text = "Paste confidential data below. It will be encrypted locally on your device before transmission and permanently wiped once viewed.",
            color = TextSecondary,
            fontSize = 14.sp,
            lineHeight = 20.sp,
          )

          Spacer(modifier = Modifier.height(18.dp))

          // Label + Generate + Paste helpers
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Text(
              text = "Secret Content",
              color = TextSecondary,
              fontSize = 13.sp,
              fontWeight = FontWeight.SemiBold,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
              Text(
                text = "🎲 Generate",
                color = AccentPrimary,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier =
                  Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .clickable {
                      secretText = SecretCrypto.generateStrongPassword(24)
                      errorBanner = null
                    }
                    .padding(horizontal = 6.dp, vertical = 2.dp),
              )
              Text(
                text = "📋 Paste",
                color = AccentPrimary,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier =
                  Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .clickable {
                      val clip = readClipboard(context)
                      if (!clip.isNullOrEmpty()) {
                        secretText = clip
                      } else {
                        Toast.makeText(context, "Clipboard is empty", Toast.LENGTH_SHORT).show()
                      }
                    }
                    .padding(horizontal = 6.dp, vertical = 2.dp),
              )
            }
          }

          Spacer(modifier = Modifier.height(6.dp))

          OutlinedTextField(
            value = secretText,
            onValueChange = {
              secretText = it
              errorBanner = null
            },
            placeholder = {
              Text(
                text = "e.g. sk_live_51Msz...",
                color = TextMuted,
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp,
              )
            },
            textStyle =
              TextStyle(
                color = TextPrimary,
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp,
                lineHeight = 20.sp,
              ),
            minLines = 6,
            maxLines = 12,
            shape = RoundedCornerShape(10.dp),
            colors = burnBinTextFieldColors(),
            modifier = Modifier.fillMaxWidth(),
          )

          Row(
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
          ) {
            if (secretText.isNotEmpty()) {
              Text(
                text = "Clear",
                color = TextMuted,
                fontSize = 12.sp,
                modifier = Modifier.clickable { secretText = "" },
              )
            } else {
              Spacer(modifier = Modifier.width(1.dp))
            }
            Text(
              text = "${secretText.length} characters",
              color = TextMuted,
              fontSize = 12.sp,
            )
          }

          Spacer(modifier = Modifier.height(12.dp))

          // Optional File Attachment Picker (Max 1 MB)
          Surface(
            color = BgSurfaceElevated,
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, BorderColor),
            modifier = Modifier.fillMaxWidth(),
          ) {
            Row(
              modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically,
            ) {
              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = selectedAttachment?.name ?: "Optional File Attachment (Max 1 MB)",
                  color = if (selectedAttachment != null) TextPrimary else TextSecondary,
                  fontSize = 13.sp,
                  fontWeight = FontWeight.SemiBold,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                )
                Text(
                  text =
                    selectedAttachment?.let {
                      "${it.mime} • ${formatByteSize(it.size)} • Encrypted locally"
                    } ?: "Attach an image, key, config, or doc before encrypting",
                  color = TextMuted,
                  fontSize = 11.sp,
                )
              }
              Spacer(modifier = Modifier.width(8.dp))
              if (selectedAttachment != null) {
                TextButton(
                  onClick = { selectedAttachment = null },
                  contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                ) {
                  Text(text = "✕ Remove", color = DangerTextLight, fontSize = 12.sp)
                }
              } else {
                OutlinedButton(
                  onClick = { attachmentPickerLauncher.launch(arrayOf("*/*")) },
                  shape = RoundedCornerShape(8.dp),
                  border = BorderStroke(1.dp, BorderColor),
                  contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                ) {
                  Text(text = "📎 Attach", color = AccentPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }
              }
            }
          }

          Spacer(modifier = Modifier.height(14.dp))

          // Options Box
          Column(
            modifier =
              Modifier
                .fillMaxWidth()
                .background(BgSurfaceElevated, RoundedCornerShape(10.dp))
                .border(1.dp, BorderColor, RoundedCornerShape(10.dp))
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
          ) {
            // Expires After
            Column {
              Text(
                text = "Expires After",
                color = TextSecondary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
              )
              Spacer(modifier = Modifier.height(8.dp))
              FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
              ) {
                ttlOptions.forEach { (seconds, label) ->
                  SelectableChip(
                    label = label,
                    selected = selectedTtlSeconds == seconds,
                    onClick = { selectedTtlSeconds = seconds },
                  )
                }
              }
            }

            // Destruction Rule
            Column {
              Text(
                text = "Destruction Rule",
                color = TextSecondary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
              )
              Spacer(modifier = Modifier.height(8.dp))
              FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
              ) {
                viewOptions.forEach { (views, label) ->
                  SelectableChip(
                    label = "Burn after $label",
                    selected = selectedMaxViews == views,
                    onClick = { selectedMaxViews = views },
                  )
                }
              }
            }
          }

          Spacer(modifier = Modifier.height(12.dp))

          // Passphrase Toggle
          Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier =
              Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .clickable {
                  usePassphrase = !usePassphrase
                  if (!usePassphrase) passphrase = ""
                }
                .padding(vertical = 4.dp),
          ) {
            Checkbox(
              checked = usePassphrase,
              onCheckedChange = {
                usePassphrase = it
                if (!it) passphrase = ""
              },
              colors =
                CheckboxDefaults.colors(
                  checkedColor = AccentPrimary,
                  checkmarkColor = AccentDarkText,
                  uncheckedColor = TextSecondary,
                ),
            )
            Text(
              text = "Protect with a custom passphrase (optional)",
              color = TextSecondary,
              fontSize = 14.sp,
              fontWeight = FontWeight.SemiBold,
            )
          }

          if (usePassphrase) {
            Spacer(modifier = Modifier.height(6.dp))
            OutlinedTextField(
              value = passphrase,
              onValueChange = { passphrase = it },
              placeholder = { Text("Enter a secret passphrase", color = TextMuted, fontSize = 14.sp) },
              singleLine = true,
              visualTransformation =
                if (showPassphraseText) VisualTransformation.None else PasswordVisualTransformation(),
              trailingIcon = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                  TextButton(
                    onClick = {
                      passphrase = SecretCrypto.generateShareablePassphrase()
                      showPassphraseText = true
                    },
                    contentPadding = PaddingValues(horizontal = 6.dp),
                  ) {
                    Text(text = "🎲 Gen", color = AccentPrimary, fontSize = 12.sp)
                  }
                  TextButton(
                    onClick = { showPassphraseText = !showPassphraseText },
                    contentPadding = PaddingValues(horizontal = 6.dp),
                  ) {
                    Text(
                      text = if (showPassphraseText) "Hide" else "Show",
                      color = AccentPrimary,
                      fontSize = 12.sp,
                    )
                  }
                }
              },
              shape = RoundedCornerShape(8.dp),
              colors = burnBinTextFieldColors(),
              modifier = Modifier.fillMaxWidth(),
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = "The recipient will be required to enter this passphrase to decrypt the content.",
              color = TextMuted,
              fontSize = 12.sp,
            )
          }

          Spacer(modifier = Modifier.height(12.dp))

          OutlinedTextField(
            value = localLabel,
            onValueChange = { if (it.length <= 80) localLabel = it },
            label = { Text("Local Tracker Label (optional — stays on this device)", fontSize = 12.sp) },
            placeholder = { Text("e.g. Staging API key for Alex", color = TextMuted, fontSize = 13.sp) },
            singleLine = true,
            shape = RoundedCornerShape(8.dp),
            colors = burnBinTextFieldColors(),
            modifier = Modifier.fillMaxWidth(),
          )

          if (errorBanner != null) {
            Spacer(modifier = Modifier.height(12.dp))
            AlertBox(
              type = AlertType.DANGER,
              title = "Error:",
              message = errorBanner ?: "",
            )
          }

          Spacer(modifier = Modifier.height(18.dp))

          Button(
            onClick = {
              val trimmedSecret = secretText.trim()
              val attachmentToSend = selectedAttachment
              if (trimmedSecret.isEmpty() && attachmentToSend == null) {
                errorBanner = "Please enter a secret message or attach an encrypted file."
                return@Button
              }
              val trimmedPass = if (usePassphrase) passphrase.trim() else null
              if (usePassphrase && trimmedPass.isNullOrEmpty()) {
                errorBanner = "Please enter a passphrase or uncheck passphrase protection."
                return@Button
              }

              errorBanner = null
              isSubmitting = true
              statusLabel = "Encrypting locally..."

              scope.launch {
                try {
                  val encrypted =
                    withContext(Dispatchers.Default) {
                      val payload = SecretCrypto.encodeBundle(trimmedSecret, attachmentToSend)
                      SecretCrypto.encrypt(payload, trimmedPass)
                    }

                  statusLabel = "Saving to vault..."

                  val apiResult =
                    BurnBinApiClient.createSecret(
                      baseUrl = serverUrl,
                      ciphertext = encrypted.ciphertext,
                      iv = encrypted.iv,
                      salt = encrypted.salt,
                      maxViews = selectedMaxViews,
                      ttlSeconds = selectedTtlSeconds,
                    )

                  apiResult
                    .onSuccess { created ->
                      val cleanServer = serverUrl.trim().trimEnd('/')
                      generatedSecretId = created.id
                      generatedUrlKey = encrypted.urlKey
                      lastUsedPassphrase = trimmedPass != null
                      showQrCard = false
                      val sep = if (useQueryKeyFormat) "?key=" else "#key="
                      generatedShareUrl = "$cleanServer/secret/${created.id}$sep${encrypted.urlKey}"
                      copyFeedback = false

                      val trackedEntry =
                        TrackedSecretItem(
                          id = created.id,
                          baseUrl = cleanServer,
                          label = localLabel.trim(),
                          createdAtMs = System.currentTimeMillis(),
                          expiresAtMs =
                            if (created.expiresAt > 0L) created.expiresAt * 1000L
                            else System.currentTimeMillis() + selectedTtlSeconds * 1000L,
                          maxViews = created.maxViews,
                          viewsLeft = created.maxViews,
                          deleteToken = created.deleteToken ?: "",
                          hasAttachment = attachmentToSend != null,
                          status = "active",
                        )
                      val updated = listOf(trackedEntry) + trackedSecrets.filterNot { it.id == created.id }
                      trackedSecrets = updated
                      saveTrackedSecrets(prefs, updated)
                      selectedAttachment = null
                    }
                    .onFailure { err ->
                      errorBanner = err.message ?: "Failed to save secret to vault."
                    }
                } catch (e: Exception) {
                  errorBanner = "Encryption error: ${e.message}"
                } finally {
                  isSubmitting = false
                }
              }
            },
            enabled = !isSubmitting,
            shape = RoundedCornerShape(10.dp),
            colors =
              ButtonDefaults.buttonColors(
                containerColor = AccentPrimary,
                contentColor = AccentDarkText,
                disabledContainerColor = AccentPrimary.copy(alpha = 0.4f),
                disabledContentColor = AccentDarkText,
              ),
            contentPadding = PaddingValues(vertical = 14.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            if (isSubmitting) {
              CircularProgressIndicator(
                color = AccentDarkText,
                strokeWidth = 2.dp,
                modifier = Modifier.size(18.dp),
              )
              Spacer(modifier = Modifier.width(10.dp))
              Text(
                text = statusLabel,
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
              )
            } else {
              Text(
                text = "🔒 Create Encrypted Secret Link",
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
              )
            }
          }
        }
      }
    } else {
      // Result Card (Secret Created & Armed)
      val shareUrl = generatedShareUrl ?: ""
      Surface(
        color = BgSurface,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, BorderColor),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Column(modifier = Modifier.padding(20.dp)) {
          Text(
            text = "🔥 Secret Created & Armed",
            color = TextPrimary,
            fontSize = 21.sp,
            fontWeight = FontWeight.Bold,
          )
          Spacer(modifier = Modifier.height(6.dp))
          Text(
            text = "Your secret has been encrypted and stored. Share this one-time link with your recipient:",
            color = TextSecondary,
            fontSize = 14.sp,
          )

          Spacer(modifier = Modifier.height(14.dp))

          // Format Selector Chips
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Text(
              text = "Format:",
              color = TextSecondary,
              fontSize = 12.sp,
              fontWeight = FontWeight.SemiBold,
            )
            SelectableChip(
              label = "💬 Chat-Safe (?key=)",
              selected = useQueryKeyFormat,
              onClick = {
                useQueryKeyFormat = true
                val id = generatedSecretId
                val key = generatedUrlKey
                if (id != null && key != null) {
                  val cleanServer = serverUrl.trim().trimEnd('/')
                  generatedShareUrl = "$cleanServer/secret/$id?key=$key"
                  copyFeedback = false
                }
              },
            )
            SelectableChip(
              label = "🔒 Hash (#key=)",
              selected = !useQueryKeyFormat,
              onClick = {
                useQueryKeyFormat = false
                val id = generatedSecretId
                val key = generatedUrlKey
                if (id != null && key != null) {
                  val cleanServer = serverUrl.trim().trimEnd('/')
                  generatedShareUrl = "$cleanServer/secret/$id#key=$key"
                  copyFeedback = false
                }
              },
            )
          }

          Spacer(modifier = Modifier.height(6.dp))

          Text(
            text =
              "Chat-Safe (?key=): Best for WhatsApp/SMS so links aren't cut off. Hash (#key=): Key never leaves browser URL fragments.",
            color = TextMuted,
            fontSize = 11.sp,
            lineHeight = 15.sp,
          )

          Spacer(modifier = Modifier.height(10.dp))

          // Monospace Link Box
          SelectionContainer {
            Box(
              modifier =
                Modifier
                  .fillMaxWidth()
                  .background(BgPrimary, RoundedCornerShape(8.dp))
                  .border(1.dp, AccentPrimary, RoundedCornerShape(8.dp))
                  .padding(12.dp)
            ) {
              Text(
                text = shareUrl,
                color = AccentPrimary,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                lineHeight = 18.sp,
              )
            }
          }

          Spacer(modifier = Modifier.height(12.dp))

          // Copy & Native Android Share Row
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
          ) {
            Button(
              onClick = {
                copyToClipboard(context, "BurnBin Secret Link", shareUrl, sensitive = true)
                copyFeedback = true
              },
              shape = RoundedCornerShape(10.dp),
              colors =
                ButtonDefaults.buttonColors(
                  containerColor = if (copyFeedback) AccentPrimary else BgSurfaceElevated,
                  contentColor = if (copyFeedback) AccentDarkText else TextPrimary,
                ),
              border = BorderStroke(1.dp, if (copyFeedback) AccentPrimary else BorderColor),
              contentPadding = PaddingValues(vertical = 12.dp),
              modifier = Modifier.weight(1f),
            ) {
              Text(
                text = if (copyFeedback) "✓ Copied!" else "📋 Copy Link",
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp,
              )
            }

            Button(
              onClick = {
                val key = generatedUrlKey
                val shareBody = if (!useQueryKeyFormat && key != null) {
                  "$shareUrl\n(Key: $key)"
                } else {
                  shareUrl
                }
                shareTextIntent(context, shareBody)
              },
              shape = RoundedCornerShape(10.dp),
              colors =
                ButtonDefaults.buttonColors(
                  containerColor = AccentPrimary,
                  contentColor = AccentDarkText,
                ),
              contentPadding = PaddingValues(vertical = 12.dp),
              modifier = Modifier.weight(1f),
            ) {
              Text(
                text = "📤 Share Link",
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp,
              )
            }
          }

          Spacer(modifier = Modifier.height(10.dp))

          // Rich Share with Safety Note & Collapsible QR Code
          OutlinedButton(
            onClick = {
              val viewsNote =
                if (selectedMaxViews == 1) "This secret self-destructs after 1 view."
                else "This secret self-destructs after $selectedMaxViews views."
              val passNote =
                if (lastUsedPassphrase) "\nA separate passphrase is required to unlock it."
                else ""
              val body =
                "I shared an end-to-end encrypted secret with you via BurnBin.\n" +
                  "$viewsNote$passNote\n$shareUrl"
              shareTextIntent(context, body)
            },
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, BorderColor),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
            contentPadding = PaddingValues(vertical = 11.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(text = "✉️ Share + Safety Note", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
          }

          Spacer(modifier = Modifier.height(10.dp))

          OutlinedButton(
            onClick = { showQrCard = !showQrCard },
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, BorderColor),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = AccentPrimary),
            contentPadding = PaddingValues(vertical = 10.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = if (showQrCard) "▲ Hide QR Code" else "📱 Show QR Code (In-Person Scan)",
              fontWeight = FontWeight.SemiBold,
              fontSize = 13.sp,
            )
          }

          if (showQrCard) {
            val qrBitmap = remember(shareUrl) { generateQrBitmap(shareUrl, 512) }
            if (qrBitmap != null) {
              Spacer(modifier = Modifier.height(10.dp))
              Surface(
                color = Color.White,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.align(Alignment.CenterHorizontally),
              ) {
                Image(
                  bitmap = qrBitmap.asImageBitmap(),
                  contentDescription = "QR Code for BurnBin secret link",
                  modifier = Modifier.size(220.dp).padding(12.dp),
                )
              }
            }
          }

          Spacer(modifier = Modifier.height(14.dp))

          AlertBox(
            type = AlertType.WARNING,
            title = "Burn Warning:",
            message =
              "The server will permanently delete this secret once the view limit is reached. Do not open the link yourself if you selected 1 view!",
          )

          Spacer(modifier = Modifier.height(14.dp))

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
          ) {
            OutlinedButton(
              onClick = { onOpenInReveal(shareUrl) },
              shape = RoundedCornerShape(10.dp),
              border = BorderStroke(1.dp, BorderColor),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
              contentPadding = PaddingValues(vertical = 12.dp),
              modifier = Modifier.weight(1f),
            ) {
              Text(text = "🔓 Open Secret", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            }

            OutlinedButton(
              onClick = {
                secretText = ""
                passphrase = ""
                localLabel = ""
                selectedAttachment = null
                usePassphrase = false
                generatedShareUrl = null
                generatedSecretId = null
                generatedUrlKey = null
                showQrCard = false
                copyFeedback = false
                errorBanner = null
              },
              shape = RoundedCornerShape(10.dp),
              border = BorderStroke(1.dp, BorderColor),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
              contentPadding = PaddingValues(vertical = 12.dp),
              modifier = Modifier.weight(1f),
            ) {
              Text(text = "+ Create Another", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            }
          }
        }
      }
    }

    // Sent Secrets Tracker & Early Revocation Card
    Surface(
      color = BgSurface,
      shape = RoundedCornerShape(16.dp),
      border = BorderStroke(1.dp, BorderColor),
      modifier = Modifier.fillMaxWidth(),
    ) {
      Column(modifier = Modifier.padding(16.dp)) {
        Row(
          modifier =
            Modifier
              .fillMaxWidth()
              .clip(RoundedCornerShape(8.dp))
              .clickable { trackedExpanded = !trackedExpanded }
              .padding(vertical = 4.dp),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Text(
            text = "📜 Sent Secrets Tracker (${trackedSecrets.size})",
            color = TextPrimary,
            fontSize = 15.sp,
            fontWeight = FontWeight.Bold,
          )
          Text(
            text = if (trackedExpanded) "▲ Hide" else "▼ Status / Burn",
            color = AccentPrimary,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
          )
        }

        if (trackedExpanded) {
          Spacer(modifier = Modifier.height(8.dp))
          Text(
            text = "Only non-secret metadata (ID, expiry, revocation token) is saved on this device. Plaintext and decryption keys are never stored.",
            color = TextMuted,
            fontSize = 11.sp,
            lineHeight = 15.sp,
          )
          Spacer(modifier = Modifier.height(10.dp))

          if (trackedSecrets.isEmpty()) {
            Text(
              text = "No secrets tracked on this device yet.",
              color = TextSecondary,
              fontSize = 13.sp,
            )
          } else {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
              trackedSecrets.forEach { item ->
                val isExpired = System.currentTimeMillis() >= item.expiresAtMs
                val effectiveStatus =
                  when {
                    item.status == "burned" -> "burned"
                    isExpired -> "expired"
                    else -> item.status
                  }
                val statusLabelText =
                  when (effectiveStatus) {
                    "burned" -> "🔥 Burned"
                    "expired" -> "⏱️ Expired"
                    else -> "● Active (${item.viewsLeft} left)"
                  }
                val statusColor =
                  when (effectiveStatus) {
                    "burned" -> DangerPrimary
                    "active" -> AccentPrimary
                    else -> TextSecondary
                  }

                Surface(
                  color = BgSurfaceElevated,
                  shape = RoundedCornerShape(10.dp),
                  border = BorderStroke(1.dp, BorderColor),
                  modifier = Modifier.fillMaxWidth(),
                ) {
                  Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                  ) {
                    Row(
                      modifier = Modifier.fillMaxWidth(),
                      horizontalArrangement = Arrangement.SpaceBetween,
                      verticalAlignment = Alignment.CenterVertically,
                    ) {
                      Text(
                        text = if (item.label.isNotBlank()) "${item.label} (${item.id})" else "Secret #${item.id}",
                        color = TextPrimary,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                      )
                      Spacer(modifier = Modifier.width(8.dp))
                      Text(
                        text = statusLabelText,
                        color = statusColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                      )
                    }

                    Text(
                      text =
                        buildString {
                          append(formatExpiryCountdown(item.expiresAtMs))
                          if (item.hasAttachment) append(" • 📎 File")
                        },
                      color = TextMuted,
                      fontSize = 11.sp,
                    )

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                      OutlinedButton(
                        onClick = {
                          scope.launch {
                            val metaRes = BurnBinApiClient.getSecretMeta(item.baseUrl, item.id)
                            val updatedItem =
                              metaRes.fold(
                                onSuccess = { meta ->
                                  item.copy(
                                    status = "active",
                                    viewsLeft = meta.viewsLeft,
                                    expiresAtMs = if (meta.expiresAt > 0L) meta.expiresAt * 1000L else item.expiresAtMs,
                                  )
                                },
                                onFailure = {
                                  item.copy(status = "burned", viewsLeft = 0)
                                },
                              )
                            val updatedList = trackedSecrets.map { if (it.id == item.id) updatedItem else it }
                            trackedSecrets = updatedList
                            saveTrackedSecrets(prefs, updatedList)
                          }
                        },
                        shape = RoundedCornerShape(8.dp),
                        border = BorderStroke(1.dp, BorderColor),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                      ) {
                        Text(text = "🔄 Status", color = TextPrimary, fontSize = 11.sp)
                      }

                      if (effectiveStatus == "active" && item.deleteToken.isNotBlank()) {
                        OutlinedButton(
                          onClick = {
                            scope.launch {
                              val revokeRes =
                                BurnBinApiClient.revokeSecret(
                                  baseUrl = item.baseUrl,
                                  secretId = item.id,
                                  deleteToken = item.deleteToken,
                                )
                              revokeRes
                                .onSuccess {
                                  val updatedList =
                                    trackedSecrets.map {
                                      if (it.id == item.id) it.copy(status = "burned", viewsLeft = 0) else it
                                    }
                                  trackedSecrets = updatedList
                                  saveTrackedSecrets(prefs, updatedList)
                                  Toast.makeText(context, "Secret burned on server", Toast.LENGTH_SHORT).show()
                                }
                                .onFailure { err ->
                                  Toast.makeText(context, err.message ?: "Failed to burn secret", Toast.LENGTH_LONG).show()
                                }
                            }
                          },
                          shape = RoundedCornerShape(8.dp),
                          border = BorderStroke(1.dp, DangerPrimary.copy(alpha = 0.5f)),
                          contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        ) {
                          Text(text = "🔥 Burn Now", color = DangerTextLight, fontSize = 11.sp)
                        }
                      }

                      TextButton(
                        onClick = {
                          val updatedList = trackedSecrets.filterNot { it.id == item.id }
                          trackedSecrets = updatedList
                          saveTrackedSecrets(prefs, updatedList)
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                      ) {
                        Text(text = "✕", color = TextMuted, fontSize = 12.sp)
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    // Security Highlights Section
    SecurityHighlightsSection()

    // Footer
    Text(
      text = "Zero-Knowledge BurnBin • AES-256-GCM + PBKDF2 • No cookies or trackers",
      color = TextMuted,
      fontSize = 12.sp,
      textAlign = TextAlign.Center,
      modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
    )
  }
}

@Composable
private fun RevealSecretView(
  serverUrl: String,
  linkInput: String,
  onLinkInputChange: (String) -> Unit,
  autoCheckTrigger: Int,
  onAutoCheckConsumed: () -> Unit,
  biometricRevealEnabled: Boolean,
  autoClearClipboardEnabled: Boolean,
  onRevealedVisibilityChanged: (Boolean) -> Unit,
  onCreateNewClick: () -> Unit,
) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val scrollState = rememberScrollState()

  var uiState by remember { mutableStateOf<RevealUiState>(RevealUiState.Idle) }
  var decryptPassphrase by rememberSaveable { mutableStateOf("") }
  var manualKeyInput by rememberSaveable { mutableStateOf("") }
  var showPassphrase by rememberSaveable { mutableStateOf(false) }
  var copiedSecretFeedback by rememberSaveable { mutableStateOf(false) }
  var clipboardCountdownSeconds by rememberSaveable { mutableIntStateOf(0) }
  var clipboardClearedBanner by rememberSaveable { mutableStateOf(false) }
  var clipboardTimerNonce by rememberSaveable { mutableIntStateOf(0) }

  LaunchedEffect(uiState) {
    onRevealedVisibilityChanged(uiState is RevealUiState.Revealed)
  }

  LaunchedEffect(clipboardTimerNonce) {
    if (clipboardTimerNonce > 0 && autoClearClipboardEnabled) {
      clipboardClearedBanner = false
      for (sec in 45 downTo 1) {
        clipboardCountdownSeconds = sec
        delay(1_000L)
      }
      clipboardCountdownSeconds = 0
      clearClipboard(context)
      copiedSecretFeedback = false
      clipboardClearedBanner = true
    } else {
      clipboardCountdownSeconds = 0
    }
  }

  fun checkSecretLink(rawUrl: String) {
    val parsedRes = SecretCrypto.parseSecretLink(rawUrl, serverUrl)
    parsedRes
      .onFailure { err ->
        uiState = RevealUiState.Error(err.message ?: "Invalid BurnBin link.")
      }
      .onSuccess { parsed ->
        uiState = RevealUiState.CheckingVault
        decryptPassphrase = ""
        manualKeyInput = parsed.urlKey ?: ""
        copiedSecretFeedback = false
        clipboardTimerNonce = 0
        clipboardCountdownSeconds = 0
        clipboardClearedBanner = false
        scope.launch {
          val metaRes = BurnBinApiClient.getSecretMeta(parsed.baseUrl, parsed.secretId)
          metaRes
            .onSuccess { meta ->
              uiState = RevealUiState.PreReveal(parsedLink = parsed, meta = meta)
            }
            .onFailure { err ->
              uiState =
                RevealUiState.Error(
                  err.message ?: "This secret does not exist, has expired, or has already been burned."
                )
            }
        }
      }
  }

  LaunchedEffect(autoCheckTrigger) {
    if (autoCheckTrigger > 0) {
      val currentLink = linkInput
      onAutoCheckConsumed()
      if (currentLink.isNotBlank()) {
        checkSecretLink(currentLink)
      }
    }
  }

  Column(
    modifier =
      Modifier
        .fillMaxSize()
        .verticalScroll(scrollState)
        .padding(horizontal = 16.dp, vertical = 6.dp),
    verticalArrangement = Arrangement.spacedBy(16.dp),
  ) {
    // Link Input Card
    Surface(
      color = BgSurface,
      shape = RoundedCornerShape(16.dp),
      border = BorderStroke(1.dp, BorderColor),
      modifier = Modifier.fillMaxWidth(),
    ) {
      Column(modifier = Modifier.padding(16.dp)) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Text(
            text = "BurnBin Secret Link",
            color = TextSecondary,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
          )
          val qrScanLauncher =
            rememberLauncherForActivityResult(ScanContract()) { scanResult ->
              val scanned = scanResult.contents?.trim()
              if (!scanned.isNullOrBlank()) {
                onLinkInputChange(scanned)
                checkSecretLink(scanned)
              }
            }
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
              text = "📷 Scan QR",
              color = AccentPrimary,
              fontSize = 12.sp,
              fontWeight = FontWeight.SemiBold,
              modifier =
                Modifier
                  .clip(RoundedCornerShape(6.dp))
                  .clickable {
                    val opts =
                      ScanOptions().apply {
                        setPrompt("Scan BurnBin Secret QR Code")
                        setBeepEnabled(false)
                        setOrientationLocked(false)
                      }
                    qrScanLauncher.launch(opts)
                  }
                  .padding(horizontal = 6.dp, vertical = 2.dp),
            )
            Text(
              text = "📋 Paste & Check",
              color = AccentPrimary,
              fontSize = 12.sp,
              fontWeight = FontWeight.SemiBold,
              modifier =
                Modifier
                  .clip(RoundedCornerShape(6.dp))
                  .clickable {
                    val clip = readClipboard(context)
                    if (!clip.isNullOrBlank()) {
                      onLinkInputChange(clip)
                      checkSecretLink(clip)
                    } else {
                      Toast.makeText(context, "Clipboard is empty", Toast.LENGTH_SHORT).show()
                    }
                  }
                  .padding(horizontal = 6.dp, vertical = 2.dp),
            )
          }
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedTextField(
          value = linkInput,
          onValueChange = {
            onLinkInputChange(it)
            if (uiState !is RevealUiState.Idle) {
              uiState = RevealUiState.Idle
            }
          },
          placeholder = {
            Text(
              text = "$serverUrl/secret/...#key=...",
              color = TextMuted,
              fontFamily = FontFamily.Monospace,
              fontSize = 13.sp,
            )
          },
          trailingIcon = {
            if (linkInput.isNotEmpty()) {
              TextButton(
                onClick = {
                  onLinkInputChange("")
                  uiState = RevealUiState.Idle
                },
                contentPadding = PaddingValues(horizontal = 8.dp),
              ) {
                Text(text = "✕ Clear", color = TextMuted, fontSize = 12.sp)
              }
            }
          },
          textStyle =
            TextStyle(
              color = TextPrimary,
              fontFamily = FontFamily.Monospace,
              fontSize = 13.sp,
            ),
          singleLine = true,
          shape = RoundedCornerShape(10.dp),
          colors = burnBinTextFieldColors(),
          modifier = Modifier.fillMaxWidth(),
        )

        Spacer(modifier = Modifier.height(10.dp))

        Button(
          onClick = { checkSecretLink(linkInput) },
          shape = RoundedCornerShape(10.dp),
          colors =
            ButtonDefaults.buttonColors(
              containerColor = BgSurfaceElevated,
              contentColor = TextPrimary,
            ),
          border = BorderStroke(1.dp, BorderColor),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Text(
            text = "🔍 Verify Secret Status (Without Burning)",
            fontWeight = FontWeight.SemiBold,
            fontSize = 14.sp,
          )
        }
      }
    }

    // Dynamic State Card
    when (val state = uiState) {
      RevealUiState.Idle -> {
        Surface(
          color = BgSurface,
          shape = RoundedCornerShape(16.dp),
          border = BorderStroke(1.dp, BorderColor),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
          ) {
            Text(text = "🔐", fontSize = 32.sp)
            Spacer(modifier = Modifier.height(8.dp))
            Text(
              text = "Paste a BurnBin Link Above",
              color = TextPrimary,
              fontSize = 17.sp,
              fontWeight = FontWeight.Bold,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = "We will first verify the secret metadata without burning it, then let you reveal and decrypt it locally on your device.",
              color = TextSecondary,
              fontSize = 13.sp,
              textAlign = TextAlign.Center,
            )
          }
        }
      }

      RevealUiState.CheckingVault -> {
        Surface(
          color = BgSurface,
          shape = RoundedCornerShape(16.dp),
          border = BorderStroke(1.dp, BorderColor),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
          ) {
            CircularProgressIndicator(color = AccentPrimary, strokeWidth = 3.dp)
            Spacer(modifier = Modifier.height(14.dp))
            Text(
              text = "Checking Secret Vault...",
              color = TextPrimary,
              fontSize = 18.sp,
              fontWeight = FontWeight.Bold,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = "Verifying status and encryption envelope.",
              color = TextSecondary,
              fontSize = 14.sp,
            )
          }
        }
      }

      is RevealUiState.Error -> {
        Surface(
          color = BgSurface,
          shape = RoundedCornerShape(16.dp),
          border = BorderStroke(1.dp, BorderColor),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(modifier = Modifier.padding(20.dp)) {
            Text(
              text = "❌ Secret Not Found or Destroyed",
              color = DangerPrimary,
              fontSize = 19.sp,
              fontWeight = FontWeight.Bold,
            )
            Spacer(modifier = Modifier.height(12.dp))
            AlertBox(
              type = AlertType.DANGER,
              title = null,
              message = state.message,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
              text = "BurnBin permanently purges secrets once read. Once gone, it cannot be recovered by anyone—even the server operator.",
              color = TextSecondary,
              fontSize = 13.sp,
            )
            Spacer(modifier = Modifier.height(14.dp))
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
              Button(
                onClick = {
                  onLinkInputChange("")
                  uiState = RevealUiState.Idle
                },
                shape = RoundedCornerShape(10.dp),
                colors =
                  ButtonDefaults.buttonColors(
                    containerColor = BgSurfaceElevated,
                    contentColor = TextPrimary,
                  ),
                border = BorderStroke(1.dp, BorderColor),
                contentPadding = PaddingValues(vertical = 12.dp),
                modifier = Modifier.weight(1f),
              ) {
                Text(text = "✕ Clear Link", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
              }

              OutlinedButton(
                onClick = onCreateNewClick,
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, BorderColor),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
                contentPadding = PaddingValues(vertical = 12.dp),
                modifier = Modifier.weight(1f),
              ) {
                Text(text = "+ Create Secret", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
              }
            }
          }
        }
      }

      is RevealUiState.PreReveal -> {
        Surface(
          color = BgSurface,
          shape = RoundedCornerShape(16.dp),
          border = BorderStroke(1.dp, BorderColor),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(modifier = Modifier.padding(20.dp)) {
            Text(
              text = "Confidential Secret Waiting",
              color = TextPrimary,
              fontSize = 21.sp,
              fontWeight = FontWeight.Bold,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = "A self-destructing secret has been delivered for you.",
              color = TextSecondary,
              fontSize = 14.sp,
            )

            Spacer(modifier = Modifier.height(14.dp))

            val destructMsg =
              if (state.meta.viewsLeft == 1) {
                "This is a single-use secret. It will be permanently burned from the server immediately when revealed."
              } else {
                "This secret has ${state.meta.viewsLeft} view(s) remaining before being permanently destroyed."
              }

            AlertBox(
              type = AlertType.WARNING,
              title = "Self-Destruct Notice:",
              message = destructMsg,
            )

            val needsManualKey = state.parsedLink.urlKey.isNullOrBlank()
            if (needsManualKey) {
              Spacer(modifier = Modifier.height(14.dp))
              AlertBox(
                type = AlertType.WARNING,
                title = "🔑 Key Missing in Link:",
                message =
                  "The link opened without an encryption key (chat apps often cut links at #). Paste the 64-character hex key below to decrypt.",
              )
              Spacer(modifier = Modifier.height(8.dp))
              Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
              ) {
                Text(
                  text = "Decryption Key (64 hex characters):",
                  color = TextSecondary,
                  fontSize = 13.sp,
                  fontWeight = FontWeight.SemiBold,
                )
                Text(
                  text = "📋 Paste Key",
                  color = AccentPrimary,
                  fontSize = 12.sp,
                  fontWeight = FontWeight.SemiBold,
                  modifier =
                    Modifier
                      .clip(RoundedCornerShape(6.dp))
                      .clickable {
                        val clip = readClipboard(context)
                        if (!clip.isNullOrBlank()) {
                          val extracted =
                            SecretCrypto.parseSecretLink(clip, serverUrl).getOrNull()?.urlKey
                              ?: clip.trim()
                          manualKeyInput = extracted
                        } else {
                          Toast.makeText(context, "Clipboard is empty", Toast.LENGTH_SHORT).show()
                        }
                      }
                      .padding(horizontal = 6.dp, vertical = 2.dp),
                )
              }
              Spacer(modifier = Modifier.height(6.dp))
              OutlinedTextField(
                value = manualKeyInput,
                onValueChange = {
                  manualKeyInput = it.trim()
                  if (!state.passphraseError.isNullOrBlank()) {
                    uiState = state.copy(passphraseError = null)
                  }
                },
                placeholder = {
                  Text(
                    text = "e.g. 8f4a1c0d... (64 hex characters)",
                    color = TextMuted,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                  )
                },
                singleLine = true,
                textStyle =
                  TextStyle(
                    color = TextPrimary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                  ),
                shape = RoundedCornerShape(8.dp),
                colors = burnBinTextFieldColors(),
                modifier = Modifier.fillMaxWidth(),
              )
            }

            if (state.meta.requiresPassphrase) {
              Spacer(modifier = Modifier.height(14.dp))
              Text(
                text = "Enter Secret Passphrase:",
                color = TextSecondary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
              )
              Spacer(modifier = Modifier.height(6.dp))
              OutlinedTextField(
                value = decryptPassphrase,
                onValueChange = {
                  decryptPassphrase = it
                  if (!state.passphraseError.isNullOrBlank()) {
                    uiState = state.copy(passphraseError = null)
                  }
                },
                placeholder = { Text("Required by the sender", color = TextMuted, fontSize = 14.sp) },
                singleLine = true,
                visualTransformation =
                  if (showPassphrase) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                  TextButton(onClick = { showPassphrase = !showPassphrase }) {
                    Text(
                      text = if (showPassphrase) "Hide" else "Show",
                      color = AccentPrimary,
                      fontSize = 12.sp,
                    )
                  }
                },
                shape = RoundedCornerShape(8.dp),
                colors = burnBinTextFieldColors(),
                modifier = Modifier.fillMaxWidth(),
              )
            }

            if (!state.passphraseError.isNullOrBlank()) {
              Spacer(modifier = Modifier.height(10.dp))
              AlertBox(
                type = AlertType.DANGER,
                title = "Error:",
                message = state.passphraseError,
              )
            }

            Spacer(modifier = Modifier.height(18.dp))

            Button(
              onClick = {
                val effectiveKey =
                  if (!state.parsedLink.urlKey.isNullOrBlank()) {
                    state.parsedLink.urlKey
                  } else {
                    manualKeyInput.trim()
                  }

                if (effectiveKey.isNullOrBlank() || !effectiveKey.matches(Regex("^[a-fA-F0-9]{64}$"))) {
                  uiState =
                    state.copy(
                      passphraseError =
                        "Missing or invalid decryption key. Please enter a valid 64-character hexadecimal key.",
                    )
                  return@Button
                }

                val pass = if (state.meta.requiresPassphrase) decryptPassphrase.trim() else null
                if (state.meta.requiresPassphrase && pass.isNullOrEmpty()) {
                  uiState =
                    state.copy(passphraseError = "Please enter the passphrase to unlock this secret.")
                  return@Button
                }

                val executeConsumeAndDecrypt: () -> Unit = {
                  uiState = state.copy(isRevealing = true, passphraseError = null)
                  scope.launch {
                    val payload =
                      if (state.cachedConsumed != null) {
                        state.cachedConsumed
                      } else {
                        val res =
                          BurnBinApiClient.consumeSecret(
                            baseUrl = state.parsedLink.baseUrl,
                            secretId = state.parsedLink.secretId,
                          )
                        val consumed = res.getOrNull()
                        if (consumed == null) {
                          uiState =
                            RevealUiState.Error(
                              res.exceptionOrNull()?.message
                                ?: "This secret could not be retrieved. It may have just been burned or expired."
                            )
                          return@launch
                        }
                        consumed
                      }

                    try {
                      val decoded =
                        withContext(Dispatchers.Default) {
                          val plaintext =
                            SecretCrypto.decrypt(
                              ciphertextB64 = payload.ciphertext,
                              ivCombined = payload.iv,
                              saltHex = payload.salt,
                              urlKeyHex = effectiveKey,
                              passphrase = pass,
                            )
                          SecretCrypto.decodeBundle(plaintext)
                        }
                      uiState =
                        RevealUiState.Revealed(
                          plaintext = decoded.text,
                          attachment = decoded.attachment,
                          burned = payload.burned,
                          viewsLeft = payload.viewsLeft,
                        )
                    } catch (e: Exception) {
                      // Keep cachedConsumed so user can retry passphrase or key without losing the secret!
                      val isPassphraseFailure = e.message?.contains("passphrase", ignoreCase = true) == true
                      val updatedLink =
                        if (!isPassphraseFailure) {
                          manualKeyInput = effectiveKey
                          state.parsedLink.copy(urlKey = null)
                        } else {
                          state.parsedLink
                        }
                      uiState =
                        state.copy(
                          parsedLink = updatedLink,
                          cachedConsumed = payload,
                          isRevealing = false,
                          passphraseError =
                            e.message ?: "Failed to decrypt secret. Please verify your key and passphrase.",
                        )
                    }
                  }
                }

                if (biometricRevealEnabled && state.cachedConsumed == null) {
                  authenticateForReveal(
                    context = context,
                    onSuccess = executeConsumeAndDecrypt,
                    onErrorOrCancel = { errMsg ->
                      uiState = state.copy(passphraseError = errMsg)
                    },
                  )
                } else {
                  executeConsumeAndDecrypt()
                }
              },
              enabled = !state.isRevealing,
              shape = RoundedCornerShape(10.dp),
              colors =
                ButtonDefaults.buttonColors(
                  containerColor = DangerPrimary,
                  contentColor = Color.White,
                ),
              contentPadding = PaddingValues(vertical = 14.dp),
              modifier = Modifier.fillMaxWidth(),
            ) {
              if (state.isRevealing) {
                CircularProgressIndicator(
                  color = Color.White,
                  strokeWidth = 2.dp,
                  modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(text = "Retrieving & Decrypting...", fontWeight = FontWeight.Bold, fontSize = 15.sp)
              } else {
                val label =
                  when {
                    state.cachedConsumed == null -> "👁️ Reveal Secret Now"
                    state.meta.requiresPassphrase && !state.parsedLink.urlKey.isNullOrBlank() -> "👁️ Try Passphrase Again"
                    else -> "👁️ Try Decrypting Again"
                  }
                Text(text = label, fontWeight = FontWeight.Bold, fontSize = 15.sp)
              }
            }
          }
        }
      }

      is RevealUiState.Revealed -> {
        Surface(
          color = BgSurface,
          shape = RoundedCornerShape(16.dp),
          border = BorderStroke(1.dp, BorderColor),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(modifier = Modifier.padding(20.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically,
            ) {
              Text(
                text = "🔓 Decrypted Secret",
                color = TextPrimary,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
              )

              val stampColor = if (state.burned) DangerPrimary else WarningPrimary
              val stampLabel = if (state.burned) "🔥 DESTROYED" else "👁️ ${state.viewsLeft} LEFT"
              Box(
                modifier =
                  Modifier
                    .border(1.5.dp, stampColor, RoundedCornerShape(6.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
              ) {
                Text(
                  text = stampLabel,
                  color = stampColor,
                  fontSize = 11.sp,
                  fontWeight = FontWeight.ExtraBold,
                  letterSpacing = 0.8.sp,
                )
              }
            }

            Spacer(modifier = Modifier.height(12.dp))

            val bannerMsg =
              if (state.burned) {
                "This secret has been burned and completely purged from the server database."
              } else {
                "This secret can still be viewed ${state.viewsLeft} more time(s) before burning."
              }

            AlertBox(
              type = AlertType.INFO,
              title = null,
              message = bannerMsg,
            )

            Spacer(modifier = Modifier.height(14.dp))

            // Decrypted Secret Content Display
            if (state.plaintext.isNotBlank()) {
              SelectionContainer {
                Box(
                  modifier =
                    Modifier
                      .fillMaxWidth()
                      .background(BgPrimary, RoundedCornerShape(10.dp))
                      .border(1.dp, BorderColor, RoundedCornerShape(10.dp))
                      .padding(16.dp)
                ) {
                  Text(
                    text = state.plaintext,
                    color = SecretGreenText,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp,
                    lineHeight = 20.sp,
                  )
                }
              }

              Spacer(modifier = Modifier.height(14.dp))
            }

            state.attachment?.let { attachment ->
              val saveFileLauncher =
                rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
                  if (uri != null) {
                    scope.launch {
                      val saved =
                        withContext(Dispatchers.IO) {
                          try {
                            context.contentResolver.openOutputStream(uri)?.use { it.write(attachment.bytes) }
                            true
                          } catch (_: Exception) {
                            false
                          }
                        }
                      Toast.makeText(
                        context,
                        if (saved) "Saved ${attachment.name}" else "Failed to save file",
                        Toast.LENGTH_SHORT,
                      ).show()
                    }
                  }
                }

              Surface(
                color = BgSurfaceElevated,
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, BorderColor),
                modifier = Modifier.fillMaxWidth(),
              ) {
                Column(
                  modifier = Modifier.padding(14.dp),
                  verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                  Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                  ) {
                    Column(modifier = Modifier.weight(1f)) {
                      Text(
                        text = "📎 ${attachment.name}",
                        color = TextPrimary,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                      )
                      Text(
                        text = "${attachment.mime} • ${formatByteSize(attachment.size)}",
                        color = TextMuted,
                        fontSize = 12.sp,
                      )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                      onClick = { saveFileLauncher.launch(attachment.name) },
                      shape = RoundedCornerShape(8.dp),
                      colors =
                        ButtonDefaults.buttonColors(
                          containerColor = AccentPrimary,
                          contentColor = AccentDarkText,
                        ),
                      contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    ) {
                      Text(text = "⬇ Save", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                  }
                }
              }

              Spacer(modifier = Modifier.height(14.dp))
            }

            // Copy Action (when secret text is present)
            if (state.plaintext.isNotBlank()) {
              Button(
                onClick = {
                  copyToClipboard(context, "Decrypted Secret", state.plaintext, sensitive = true)
                  copiedSecretFeedback = true
                  if (autoClearClipboardEnabled) {
                    clipboardClearedBanner = false
                    clipboardTimerNonce++
                  }
                },
                shape = RoundedCornerShape(10.dp),
                colors =
                  ButtonDefaults.buttonColors(
                    containerColor = AccentPrimary,
                    contentColor = AccentDarkText,
                  ),
                contentPadding = PaddingValues(vertical = 12.dp),
                modifier = Modifier.fillMaxWidth(),
              ) {
                Text(
                  text = if (copiedSecretFeedback) "✓ Copied!" else "📋 Copy Secret",
                  fontWeight = FontWeight.Bold,
                  fontSize = 14.sp,
                )
              }
            }

            if (clipboardCountdownSeconds > 0 || clipboardClearedBanner) {
              Spacer(modifier = Modifier.height(8.dp))
              Surface(
                color = BgSurfaceElevated,
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, BorderColor),
                modifier = Modifier.fillMaxWidth(),
              ) {
                Row(
                  modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                  horizontalArrangement = Arrangement.SpaceBetween,
                  verticalAlignment = Alignment.CenterVertically,
                ) {
                  Text(
                    text =
                      if (clipboardCountdownSeconds > 0) {
                        "🔒 Auto-clearing clipboard in ${clipboardCountdownSeconds}s"
                      } else {
                        "✓ Clipboard wiped"
                      },
                    color = if (clipboardCountdownSeconds > 0) WarningTextLight else AccentPrimary,
                    fontSize = 12.sp,
                    modifier = Modifier.weight(1f),
                  )
                  if (clipboardCountdownSeconds > 0) {
                    Text(
                      text = "Clear Now",
                      color = AccentPrimary,
                      fontSize = 12.sp,
                      fontWeight = FontWeight.Bold,
                      modifier =
                        Modifier
                          .clip(RoundedCornerShape(6.dp))
                          .clickable {
                            clipboardTimerNonce = 0
                            clipboardCountdownSeconds = 0
                            clearClipboard(context)
                            copiedSecretFeedback = false
                            clipboardClearedBanner = true
                          }
                          .padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                  }
                }
              }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Reveal Another & Clear Row
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
              Button(
                onClick = {
                  onLinkInputChange("")
                  decryptPassphrase = ""
                  manualKeyInput = ""
                  clipboardTimerNonce = 0
                  clipboardCountdownSeconds = 0
                  clipboardClearedBanner = false
                  uiState = RevealUiState.Idle
                },
                shape = RoundedCornerShape(10.dp),
                colors =
                  ButtonDefaults.buttonColors(
                    containerColor = BgSurfaceElevated,
                    contentColor = TextPrimary,
                  ),
                border = BorderStroke(1.dp, BorderColor),
                contentPadding = PaddingValues(vertical = 12.dp),
                modifier = Modifier.weight(1f),
              ) {
                Text(
                  text = "🔓 Reveal Another",
                  fontWeight = FontWeight.SemiBold,
                  fontSize = 13.sp,
                )
              }

              Button(
                onClick = {
                  onLinkInputChange("")
                  decryptPassphrase = ""
                  manualKeyInput = ""
                  if (clipboardCountdownSeconds > 0) {
                    clearClipboard(context)
                  }
                  clipboardTimerNonce = 0
                  clipboardCountdownSeconds = 0
                  clipboardClearedBanner = false
                  uiState = RevealUiState.Idle
                  Toast.makeText(context, "Secret cleared from screen", Toast.LENGTH_SHORT).show()
                },
                shape = RoundedCornerShape(10.dp),
                colors =
                  ButtonDefaults.buttonColors(
                    containerColor = DangerPrimary.copy(alpha = 0.15f),
                    contentColor = DangerTextLight,
                  ),
                border = BorderStroke(1.dp, DangerPrimary.copy(alpha = 0.35f)),
                contentPadding = PaddingValues(vertical = 12.dp),
                modifier = Modifier.weight(1f),
              ) {
                Text(
                  text = "✕ Clear",
                  fontWeight = FontWeight.SemiBold,
                  fontSize = 13.sp,
                )
              }
            }

            Spacer(modifier = Modifier.height(10.dp))

            OutlinedButton(
              onClick = onCreateNewClick,
              shape = RoundedCornerShape(10.dp),
              border = BorderStroke(1.dp, BorderColor),
              colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
              contentPadding = PaddingValues(vertical = 12.dp),
              modifier = Modifier.fillMaxWidth(),
            ) {
              Text(text = "+ Create a Secret", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            }
          }
        }
      }
    }
  }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
private fun WebVaultView(
  serverUrl: String,
  onOpenSecretInApp: (String) -> Unit,
) {
  var isLoading by remember { mutableStateOf(true) }
  var webViewRef by remember { mutableStateOf<WebView?>(null) }
  var loadedBaseUrl by remember { mutableStateOf(serverUrl) }

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
          webViewClient =
            object : WebViewClient() {
              override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val urlStr = request?.url?.toString() ?: return false
                if (urlStr.startsWith("intent://", ignoreCase = true)) {
                  val cleanHttps = "https://" + urlStr.removePrefix("intent://").substringBefore("#Intent")
                  onOpenSecretInApp(cleanHttps)
                  return true
                }
                return false
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

@Composable
private fun ServerSettingsDialog(
  currentServerUrl: String,
  secureScreenEnabled: Boolean,
  autoClearClipboardEnabled: Boolean,
  biometricRevealEnabled: Boolean,
  onDismiss: () -> Unit,
  onSave: (String, Boolean, Boolean, Boolean) -> Unit,
) {
  val context = LocalContext.current
  var urlInput by rememberSaveable { mutableStateOf(currentServerUrl) }
  var secureToggle by rememberSaveable { mutableStateOf(secureScreenEnabled) }
  var autoClearToggle by rememberSaveable { mutableStateOf(autoClearClipboardEnabled) }
  var biometricToggle by rememberSaveable { mutableStateOf(biometricRevealEnabled) }

  AlertDialog(
    onDismissRequest = onDismiss,
    containerColor = BgSurface,
    titleContentColor = TextPrimary,
    textContentColor = TextSecondary,
    title = {
      Text(text = "⚙️ BurnBin Vault Settings", fontWeight = FontWeight.Bold, fontSize = 18.sp)
    },
    text = {
      Column(
        modifier = Modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        Text(
          text = "Vault Server URL:",
          color = TextSecondary,
          fontSize = 13.sp,
          fontWeight = FontWeight.SemiBold,
        )
        OutlinedTextField(
          value = urlInput,
          onValueChange = { urlInput = it },
          singleLine = true,
          textStyle = TextStyle(color = TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 13.sp),
          colors = burnBinTextFieldColors(),
          modifier = Modifier.fillMaxWidth(),
        )
        TextButton(
          onClick = { urlInput = BurnBinApiClient.DEFAULT_SERVER_URL },
          contentPadding = PaddingValues(0.dp),
        ) {
          Text(
            text = "Reset to default (${BurnBinApiClient.DEFAULT_SERVER_URL})",
            color = AccentPrimary,
            fontSize = 12.sp,
          )
        }

        HorizontalDivider(color = BorderColor)

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Column(modifier = Modifier.weight(1f)) {
            Text(
              text = "Always Block Screenshots",
              color = TextPrimary,
              fontSize = 14.sp,
              fontWeight = FontWeight.SemiBold,
            )
            Text(
              text = "Enable FLAG_SECURE across all screens (revealed secrets are always protected automatically).",
              color = TextMuted,
              fontSize = 12.sp,
            )
          }
          Spacer(modifier = Modifier.width(8.dp))
          Switch(
            checked = secureToggle,
            onCheckedChange = { secureToggle = it },
            colors =
              SwitchDefaults.colors(
                checkedThumbColor = AccentDarkText,
                checkedTrackColor = AccentPrimary,
              ),
          )
        }

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Column(modifier = Modifier.weight(1f)) {
            Text(
              text = "Auto-Clear Clipboard (45s)",
              color = TextPrimary,
              fontSize = 14.sp,
              fontWeight = FontWeight.SemiBold,
            )
            Text(
              text = "Wipe copied decrypted secrets automatically after 45 seconds (also tagged sensitive on Android 13+).",
              color = TextMuted,
              fontSize = 12.sp,
            )
          }
          Spacer(modifier = Modifier.width(8.dp))
          Switch(
            checked = autoClearToggle,
            onCheckedChange = { autoClearToggle = it },
            colors =
              SwitchDefaults.colors(
                checkedThumbColor = AccentDarkText,
                checkedTrackColor = AccentPrimary,
              ),
          )
        }

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Column(modifier = Modifier.weight(1f)) {
            Text(
              text = "Biometric / Lock to Reveal",
              color = TextPrimary,
              fontSize = 14.sp,
              fontWeight = FontWeight.SemiBold,
            )
            Text(
              text = "Require fingerprint, face, or screen lock before burning and decrypting a secret.",
              color = TextMuted,
              fontSize = 12.sp,
            )
          }
          Spacer(modifier = Modifier.width(8.dp))
          Switch(
            checked = biometricToggle,
            onCheckedChange = { wantEnabled ->
              if (wantEnabled && !canAuthenticateDeviceOrBiometric(context)) {
                Toast.makeText(
                  context,
                  "Set up a screen lock or biometric in Android Settings first.",
                  Toast.LENGTH_LONG,
                ).show()
              } else {
                biometricToggle = wantEnabled
              }
            },
            colors =
              SwitchDefaults.colors(
                checkedThumbColor = AccentDarkText,
                checkedTrackColor = AccentPrimary,
              ),
          )
        }
      }
    },
    confirmButton = {
      Button(
        onClick = { onSave(urlInput, secureToggle, autoClearToggle, biometricToggle) },
        colors = ButtonDefaults.buttonColors(containerColor = AccentPrimary, contentColor = AccentDarkText),
      ) {
        Text(text = "Save", fontWeight = FontWeight.Bold)
      }
    },
    dismissButton = {
      TextButton(onClick = onDismiss) {
        Text(text = "Cancel", color = TextSecondary)
      }
    },
  )
}

@Composable
private fun SelectableChip(
  label: String,
  selected: Boolean,
  onClick: () -> Unit,
) {
  Surface(
    onClick = onClick,
    color = if (selected) AccentPrimary.copy(alpha = 0.16f) else BgPrimary,
    shape = RoundedCornerShape(8.dp),
    border = BorderStroke(1.dp, if (selected) AccentPrimary else BorderColor),
  ) {
    Text(
      text = label,
      color = if (selected) AccentPrimary else TextSecondary,
      fontSize = 12.sp,
      fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
      modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
    )
  }
}

private enum class AlertType {
  WARNING,
  DANGER,
  INFO,
}

@Composable
private fun AlertBox(
  type: AlertType,
  title: String?,
  message: String,
) {
  val (bgColor, borderColor, textColor, icon) =
    when (type) {
      AlertType.WARNING ->
        Quad(
          WarningPrimary.copy(alpha = 0.1f),
          WarningPrimary.copy(alpha = 0.35f),
          WarningTextLight,
          "⚠️",
        )
      AlertType.DANGER ->
        Quad(
          DangerPrimary.copy(alpha = 0.12f),
          DangerPrimary.copy(alpha = 0.35f),
          DangerTextLight,
          "🚫",
        )
      AlertType.INFO ->
        Quad(
          InfoPrimary.copy(alpha = 0.1f),
          InfoPrimary.copy(alpha = 0.35f),
          InfoTextLight,
          "✓",
        )
    }

  Row(
    modifier =
      Modifier
        .fillMaxWidth()
        .background(bgColor, RoundedCornerShape(10.dp))
        .border(1.dp, borderColor, RoundedCornerShape(10.dp))
        .padding(14.dp),
    verticalAlignment = Alignment.Top,
  ) {
    Text(text = icon, fontSize = 16.sp)
    Spacer(modifier = Modifier.width(10.dp))
    Text(
      text = if (title != null) "$title $message" else message,
      color = textColor,
      fontSize = 13.sp,
      lineHeight = 18.sp,
    )
  }
}

private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

@Composable
private fun SecurityHighlightsSection() {
  Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
    SecurityHighlightCard(
      title = "🔒 End-to-End Encrypted",
      description =
        "Encryption happens locally on your Android device with AES-256-GCM. Use Hash (#key=) to keep the key purely client-side, or Chat-Safe (?key=) so messaging apps don't cut links short.",
    )
    SecurityHighlightCard(
      title = "🔥 True Burn-on-Read",
      description =
        "Data is stored in atomic SQLite transactions. Once retrieved, the ciphertext is permanently purged from disk and memory.",
    )
    SecurityHighlightCard(
      title = "⏱️ Automatic TTL Purge",
      description =
        "Unopened secrets expire automatically and are cleaned up by a continuous background process.",
    )
  }
}

@Composable
private fun SecurityHighlightCard(title: String, description: String) {
  Surface(
    color = BgSurface.copy(alpha = 0.6f),
    shape = RoundedCornerShape(12.dp),
    border = BorderStroke(1.dp, BorderColor),
    modifier = Modifier.fillMaxWidth(),
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Text(
        text = title,
        color = TextPrimary,
        fontSize = 14.sp,
        fontWeight = FontWeight.Bold,
      )
      Spacer(modifier = Modifier.height(4.dp))
      Text(
        text = description,
        color = TextMuted,
        fontSize = 12.sp,
        lineHeight = 17.sp,
      )
    }
  }
}

@Composable
private fun burnBinTextFieldColors() =
  OutlinedTextFieldDefaults.colors(
    focusedContainerColor = BgPrimary,
    unfocusedContainerColor = BgPrimary,
    focusedBorderColor = AccentPrimary,
    unfocusedBorderColor = BorderColor,
    cursorColor = AccentPrimary,
    focusedTextColor = TextPrimary,
    unfocusedTextColor = TextPrimary,
  )

private fun shareTextIntent(context: Context, text: String) {
  val sendIntent =
    Intent(Intent.ACTION_SEND).apply {
      putExtra(Intent.EXTRA_TEXT, text)
      type = "text/plain"
    }
  val shareIntent = Intent.createChooser(sendIntent, "Share BurnBin Secret Link")
  context.startActivity(shareIntent)
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
  BurnBinTheme { MainScreen() }
}
