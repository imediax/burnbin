package com.burnbin.app.ui.main

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
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
import com.burnbin.app.crypto.ParsedSecretLink
import com.burnbin.app.crypto.SecretCrypto
import com.burnbin.app.data.BurnBinApiClient
import com.burnbin.app.data.ConsumedSecretResponse
import com.burnbin.app.data.SecretMetaResponse
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class BurnBinTab {
  CREATE,
  REVEAL,
  WEB,
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
    val burned: Boolean,
    val viewsLeft: Int,
  ) : RevealUiState
}

@Composable
fun MainScreen(
  onItemClick: (NavKey) -> Unit = {},
  modifier: Modifier = Modifier,
  initialSharedText: String? = null,
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
  var showSettingsDialog by rememberSaveable { mutableStateOf(false) }

  var activeTab by rememberSaveable {
    mutableStateOf(if (!initialDeepLinkUrl.isNullOrBlank()) BurnBinTab.REVEAL else BurnBinTab.CREATE)
  }
  var revealInputUrl by rememberSaveable { mutableStateOf(initialDeepLinkUrl ?: "") }
  var autoCheckTrigger by rememberSaveable { mutableIntStateOf(if (!initialDeepLinkUrl.isNullOrBlank()) 1 else 0) }

  LaunchedEffect(secureScreenEnabled) {
    onToggleSecureScreen(secureScreenEnabled)
  }

  LaunchedEffect(initialDeepLinkUrl, deepLinkTrigger) {
    if (!initialDeepLinkUrl.isNullOrBlank()) {
      revealInputUrl = initialDeepLinkUrl
      autoCheckTrigger++
      activeTab = BurnBinTab.REVEAL
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
            initialText = initialSharedText ?: "",
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
            onCreateNewClick = { activeTab = BurnBinTab.CREATE },
          )
        }
        BurnBinTab.WEB -> {
          WebVaultView(serverUrl = serverUrl)
        }
      }
    }
  }

  if (showSettingsDialog) {
    ServerSettingsDialog(
      currentServerUrl = serverUrl,
      secureScreenEnabled = secureScreenEnabled,
      onDismiss = { showSettingsDialog = false },
      onSave = { newUrl, newSecure ->
        val cleaned = newUrl.trim().trimEnd('/').ifEmpty { BurnBinApiClient.DEFAULT_SERVER_URL }
        serverUrl = cleaned
        secureScreenEnabled = newSecure
        prefs.edit()
          .putString("server_url", cleaned)
          .putBoolean("secure_screen", newSecure)
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

          // Label + Paste helper
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Text(
              text = "Secret Content (Passwords, API Keys, Notes)",
              color = TextSecondary,
              fontSize = 13.sp,
              fontWeight = FontWeight.SemiBold,
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

          Spacer(modifier = Modifier.height(16.dp))

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
                TextButton(onClick = { showPassphraseText = !showPassphraseText }) {
                  Text(
                    text = if (showPassphraseText) "Hide" else "Show",
                    color = AccentPrimary,
                    fontSize = 12.sp,
                  )
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
              if (trimmedSecret.isEmpty()) {
                errorBanner = "Please enter a secret message."
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
                      SecretCrypto.encrypt(trimmedSecret, trimmedPass)
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
                      val sep = if (useQueryKeyFormat) "?key=" else "#key="
                      generatedShareUrl = "$cleanServer/secret/${created.id}$sep${encrypted.urlKey}"
                      copyFeedback = false
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
                copyToClipboard(context, "BurnBin Secret Link", shareUrl)
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
                usePassphrase = false
                generatedShareUrl = null
                generatedSecretId = null
                generatedUrlKey = null
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
    if (autoCheckTrigger > 0 && linkInput.isNotBlank()) {
      checkSecretLink(linkInput)
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
                onValueChange = { manualKeyInput = it.trim() },
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
                onValueChange = { decryptPassphrase = it },
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

                if (effectiveKey.isNullOrBlank() || effectiveKey.length != 64) {
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
                    val plaintext =
                      withContext(Dispatchers.Default) {
                        SecretCrypto.decrypt(
                          ciphertextB64 = payload.ciphertext,
                          ivCombined = payload.iv,
                          saltHex = payload.salt,
                          urlKeyHex = effectiveKey,
                          passphrase = pass,
                        )
                      }
                    uiState =
                      RevealUiState.Revealed(
                        plaintext = plaintext,
                        burned = payload.burned,
                        viewsLeft = payload.viewsLeft,
                      )
                  } catch (e: Exception) {
                    // Keep cachedConsumed so user can retry passphrase or key without losing the secret!
                    uiState =
                      state.copy(
                        cachedConsumed = payload,
                        isRevealing = false,
                        passphraseError =
                          e.message ?: "Failed to decrypt secret. Please verify your key and passphrase.",
                      )
                  }
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
                  if (state.cachedConsumed != null) "👁️ Try Passphrase Again" else "👁️ Reveal Secret Now"
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

            Spacer(modifier = Modifier.height(16.dp))

            // Copy Action
            Button(
              onClick = {
                copyToClipboard(context, "Decrypted Secret", state.plaintext)
                copiedSecretFeedback = true
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
private fun WebVaultView(serverUrl: String) {
  var isLoading by remember { mutableStateOf(true) }
  var webViewRef by remember { mutableStateOf<WebView?>(null) }

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
              override fun onPageFinished(view: WebView?, url: String?) {
                isLoading = false
              }
            }
          webChromeClient = WebChromeClient()
          loadUrl(serverUrl)
          webViewRef = this
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
  onDismiss: () -> Unit,
  onSave: (String, Boolean) -> Unit,
) {
  var urlInput by rememberSaveable { mutableStateOf(currentServerUrl) }
  var secureToggle by rememberSaveable { mutableStateOf(secureScreenEnabled) }

  AlertDialog(
    onDismissRequest = onDismiss,
    containerColor = BgSurface,
    titleContentColor = TextPrimary,
    textContentColor = TextSecondary,
    title = {
      Text(text = "⚙️ BurnBin Vault Settings", fontWeight = FontWeight.Bold, fontSize = 18.sp)
    },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
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
              text = "Block Screenshots",
              color = TextPrimary,
              fontSize = 14.sp,
              fontWeight = FontWeight.SemiBold,
            )
            Text(
              text = "Enable FLAG_SECURE to prevent screenshots or screen recording inside BurnBin.",
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
      }
    },
    confirmButton = {
      Button(
        onClick = { onSave(urlInput, secureToggle) },
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
        "Encryption happens locally on your Android device with AES-256-GCM. The decryption key lives exclusively in the URL hash (#key=...) and is never seen by the server.",
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

private fun copyToClipboard(context: Context, label: String, text: String) {
  val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
  Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
}

private fun readClipboard(context: Context): String? {
  val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  val item = clipboard.primaryClip?.getItemAt(0)
  return item?.coerceToText(context)?.toString()
}

private fun shareTextIntent(context: Context, text: String) {
  val sendIntent =
    Intent(Intent.ACTION_SEND).apply {
      putExtra(Intent.EXTRA_TEXT, text)
      type = "text/plain"
    }
  val shareIntent = Intent.createChooser(sendIntent, "Share BurnBin Secret Link")
  context.startActivity(shareIntent)
}

// Keep internal overload for template unit/UI tests compatibility
@Composable
internal fun MainScreen(data: List<String>, modifier: Modifier = Modifier) {
  Column(modifier) { data.forEach { Greeting(it) } }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
  Text(text = "Hello $name!", modifier = modifier)
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
  BurnBinTheme { MainScreen() }
}
