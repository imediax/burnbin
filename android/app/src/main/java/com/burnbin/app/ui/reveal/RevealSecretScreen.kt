package com.burnbin.app.ui.reveal

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.burnbin.app.crypto.SecretCrypto
import com.burnbin.app.security.formatAbsoluteExpiry
import com.burnbin.app.security.formatByteSize
import com.burnbin.app.security.readClipboard
import com.burnbin.app.theme.AccentDarkText
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BgSurfaceElevated
import com.burnbin.app.theme.BorderColor
import com.burnbin.app.theme.DangerPrimary
import com.burnbin.app.theme.DangerTextLight
import com.burnbin.app.theme.SecretGreenText
import com.burnbin.app.theme.TextMuted
import com.burnbin.app.theme.TextPrimary
import com.burnbin.app.theme.TextSecondary
import com.burnbin.app.theme.WarningPrimary
import com.burnbin.app.theme.WarningTextLight
import com.burnbin.app.ui.components.AlertBox
import com.burnbin.app.ui.components.AlertType
import com.burnbin.app.ui.components.burnBinTextFieldColors
import com.burnbin.app.ui.main.BurnBinUiState
import com.burnbin.app.ui.main.RevealUiState
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun RevealSecretScreen(
  state: BurnBinUiState,
  onLinkInputChange: (String) -> Unit,
  onCheckSecretLink: (String) -> Unit,
  onManualKeyChange: (String) -> Unit,
  onDecryptPassphraseChange: (String) -> Unit,
  onToggleShowDecryptPassphrase: () -> Unit,
  onRevealSecretClick: () -> Unit,
  onCopySecretClick: (String) -> Unit,
  onClearClipboardNow: () -> Unit,
  onClearReveal: (Boolean) -> Unit,
  onCreateNewClick: () -> Unit,
  onBeforeExternalActivity: () -> Unit = {},
) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val scrollState = rememberScrollState()

  val qrScanLauncher =
    rememberLauncherForActivityResult(ScanContract()) { scanResult ->
      val scanned = scanResult.contents?.trim()
      if (!scanned.isNullOrBlank()) {
        onLinkInputChange(scanned)
        onCheckSecretLink(scanned)
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
                    onBeforeExternalActivity()
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
                      onCheckSecretLink(clip)
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
          value = state.revealLinkInput,
          onValueChange = onLinkInputChange,
          placeholder = {
            Text(
              text = "${state.serverUrl}/secret/...#key=...",
              color = TextMuted,
              fontFamily = FontFamily.Monospace,
              fontSize = 13.sp,
            )
          },
          trailingIcon = {
            if (state.revealLinkInput.isNotEmpty()) {
              TextButton(
                onClick = { onClearReveal(false) },
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
          onClick = { onCheckSecretLink(state.revealLinkInput) },
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

    when (val revealState = state.revealUiState) {
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
            AlertBox(type = AlertType.DANGER, title = null, message = revealState.message)
            Spacer(modifier = Modifier.height(12.dp))
            Text(
              text = "BurnBin deletes active encrypted records once read or expired. Once burned, they can no longer be retrieved via BurnBin.",
              color = TextSecondary,
              fontSize = 13.sp,
            )
            Spacer(modifier = Modifier.height(14.dp))
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
              Button(
                onClick = { onClearReveal(false) },
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

            val expiryLabel = formatAbsoluteExpiry(revealState.meta.expiresAt)
            if (expiryLabel.isNotBlank()) {
              Spacer(modifier = Modifier.height(4.dp))
              Text(text = "Expires $expiryLabel", color = TextMuted, fontSize = 12.sp)
            }

            Spacer(modifier = Modifier.height(14.dp))

            val destructMsg =
              if (revealState.meta.viewsLeft == 1) {
                "This is a single-use secret. The active encrypted record will be deleted from BurnBin immediately when revealed."
              } else {
                "This secret has ${revealState.meta.viewsLeft} view(s) remaining before being deleted from BurnBin."
              }

            AlertBox(
              type = AlertType.WARNING,
              title = "Self-Destruct Notice:",
              message = destructMsg,
            )

            if (revealState.parsedLink.fromQueryKey) {
              Spacer(modifier = Modifier.height(10.dp))
              AlertBox(
                type = AlertType.WARNING,
                title = "Transit Exposure Warning:",
                message =
                  "This legacy link included the decryption key in the URL query string (?key=), which may have been logged in transit before reaching BurnBin. The parameter has been stripped from the link input. Treat this secret as potentially exposed.",
              )
            }

            if (revealState.parsedLink.urlKey.isNullOrBlank()) {
              Spacer(modifier = Modifier.height(14.dp))
              AlertBox(
                type = AlertType.WARNING,
                title = "🔑 Key Missing in Link:",
                message = "The link opened without an encryption key (chat apps often cut links at #). Paste the 64-character hex key below to decrypt.",
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
                            SecretCrypto.parseSecretLink(clip, state.serverUrl).getOrNull()?.urlKey
                              ?: clip.trim()
                          onManualKeyChange(extracted)
                        } else {
                          Toast.makeText(context, "Clipboard is empty", Toast.LENGTH_SHORT).show()
                        }
                      }
                      .padding(horizontal = 6.dp, vertical = 2.dp),
                )
              }
              Spacer(modifier = Modifier.height(6.dp))
              OutlinedTextField(
                value = state.manualKeyInput,
                onValueChange = onManualKeyChange,
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

            if (revealState.meta.requiresPassphrase) {
              Spacer(modifier = Modifier.height(14.dp))
              Text(
                text = "Enter Secret Passphrase:",
                color = TextSecondary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
              )
              Spacer(modifier = Modifier.height(6.dp))
              OutlinedTextField(
                value = state.decryptPassphrase,
                onValueChange = onDecryptPassphraseChange,
                placeholder = { Text("Required by the sender", color = TextMuted, fontSize = 14.sp) },
                singleLine = true,
                visualTransformation =
                  if (state.showDecryptPassphrase) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                  TextButton(onClick = onToggleShowDecryptPassphrase) {
                    Text(
                      text = if (state.showDecryptPassphrase) "Hide" else "Show",
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

            if (!revealState.passphraseError.isNullOrBlank()) {
              Spacer(modifier = Modifier.height(10.dp))
              AlertBox(type = AlertType.DANGER, title = "Error:", message = revealState.passphraseError)
            }

            Spacer(modifier = Modifier.height(18.dp))

            Button(
              onClick = onRevealSecretClick,
              enabled = !revealState.isRevealing,
              shape = RoundedCornerShape(10.dp),
              colors =
                ButtonDefaults.buttonColors(
                  containerColor = DangerPrimary,
                  contentColor = Color.White,
                ),
              contentPadding = PaddingValues(vertical = 14.dp),
              modifier = Modifier.fillMaxWidth(),
            ) {
              if (revealState.isRevealing) {
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
                    revealState.cachedConsumed == null -> "👁️ Reveal Secret Now"
                    revealState.meta.requiresPassphrase && !revealState.parsedLink.urlKey.isNullOrBlank() -> "👁️ Try Passphrase Again"
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

              val stampColor = if (revealState.burned) DangerPrimary else WarningPrimary
              val stampLabel = if (revealState.burned) "🔥 DESTROYED" else "👁️ ${revealState.viewsLeft} LEFT"
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
              if (revealState.burned) {
                "This secret has been burned. The active encrypted record has been deleted and is no longer retrievable via BurnBin."
              } else {
                "This secret can still be viewed ${revealState.viewsLeft} more time(s) before being deleted from BurnBin."
              }

            AlertBox(type = AlertType.INFO, title = null, message = bannerMsg)

            Spacer(modifier = Modifier.height(14.dp))

            if (revealState.plaintext.isNotBlank()) {
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
                    text = revealState.plaintext,
                    color = SecretGreenText,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp,
                    lineHeight = 20.sp,
                  )
                }
              }

              Spacer(modifier = Modifier.height(14.dp))
            }

            revealState.attachment?.let { attachment ->
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
                Row(
                  modifier = Modifier.fillMaxWidth().padding(14.dp),
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
                    onClick = {
                      onBeforeExternalActivity()
                      saveFileLauncher.launch(attachment.name)
                    },
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

              Spacer(modifier = Modifier.height(14.dp))
            }

            if (revealState.plaintext.isNotBlank()) {
              Button(
                onClick = { onCopySecretClick(revealState.plaintext) },
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
                  text = if (state.copiedSecretFeedback) "✓ Copied!" else "📋 Copy Secret",
                  fontWeight = FontWeight.Bold,
                  fontSize = 14.sp,
                )
              }
            }

            if (state.clipboardCountdownSeconds > 0 || state.clipboardClearedBanner) {
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
                      if (state.clipboardCountdownSeconds > 0) {
                        "🔒 Auto-clearing clipboard in ${state.clipboardCountdownSeconds}s"
                      } else {
                        "✓ Clipboard wiped"
                      },
                    color = if (state.clipboardCountdownSeconds > 0) WarningTextLight else AccentPrimary,
                    fontSize = 12.sp,
                    modifier = Modifier.weight(1f),
                  )
                  if (state.clipboardCountdownSeconds > 0) {
                    Text(
                      text = "Clear Now",
                      color = AccentPrimary,
                      fontSize = 12.sp,
                      fontWeight = FontWeight.Bold,
                      modifier =
                        Modifier
                          .clip(RoundedCornerShape(6.dp))
                          .clickable { onClearClipboardNow() }
                          .padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                  }
                }
              }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
              Button(
                onClick = { onClearReveal(false) },
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
                Text(text = "🔓 Reveal Another", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
              }

              Button(
                onClick = {
                  onClearReveal(true)
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
                Text(text = "✕ Clear", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
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
