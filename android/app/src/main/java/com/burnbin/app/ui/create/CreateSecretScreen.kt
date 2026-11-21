package com.burnbin.app.ui.create

import android.net.Uri
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.burnbin.app.crypto.SecretCrypto
import com.burnbin.app.data.TrackedSecretItem
import com.burnbin.app.data.TrackedSecretsStore
import com.burnbin.app.security.formatByteSize
import com.burnbin.app.security.generateQrBitmap
import com.burnbin.app.security.readClipboard
import com.burnbin.app.theme.AccentDarkText
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BgSurfaceElevated
import com.burnbin.app.theme.BorderColor
import com.burnbin.app.theme.DangerPrimary
import com.burnbin.app.theme.DangerTextLight
import com.burnbin.app.theme.InfoPrimary
import com.burnbin.app.theme.TextMuted
import com.burnbin.app.theme.TextPrimary
import com.burnbin.app.theme.TextSecondary
import com.burnbin.app.theme.WarningPrimary
import com.burnbin.app.ui.components.AlertBox
import com.burnbin.app.ui.components.AlertType
import com.burnbin.app.ui.components.SecurityHighlightsSection
import com.burnbin.app.ui.components.SelectableChip
import com.burnbin.app.ui.components.burnBinTextFieldColors
import com.burnbin.app.ui.components.shareTextIntent
import com.burnbin.app.ui.main.BurnBinUiState

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun CreateSecretScreen(
  state: BurnBinUiState,
  onSecretTextChange: (String) -> Unit,
  onPasswordOptionsChange: (Int, Boolean) -> Unit,
  onGenerateStrongPassword: () -> Unit,
  onAttachFileUri: (Uri) -> Unit,
  onRemoveAttachment: () -> Unit,
  onSelectTtl: (Int) -> Unit,
  onSelectMaxViews: (Int) -> Unit,
  onToggleUsePassphrase: (Boolean) -> Unit,
  onPassphraseChange: (String) -> Unit,
  onToggleShowPassphrase: () -> Unit,
  onGeneratePassphrase: () -> Unit,
  onLocalLabelChange: (String) -> Unit,
  onSubmitSecret: () -> Unit,
  onSelectShareFormat: (Boolean) -> Unit,
  onCopyGeneratedLink: () -> Unit,
  onOpenGeneratedInReveal: () -> Unit,
  onResetCreateForm: () -> Unit,
  onCheckTrackedStatus: (TrackedSecretItem) -> Unit,
  onBurnTrackedSecret: (TrackedSecretItem) -> Unit,
  onDismissTrackedSecret: (String) -> Unit,
) {
  val context = LocalContext.current
  val scrollState = rememberScrollState()
  var showQrCard by rememberSaveable { mutableStateOf(false) }

  val attachmentPickerLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
      if (uri != null) onAttachFileUri(uri)
    }

  val ttlOptions =
    listOf(
      300 to "5 mins",
      600 to "10 mins",
      3600 to "1 hour",
      86400 to "24 hours",
      604800 to "7 days",
      2592000 to "30 days",
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
    if (state.generatedShareUrl == null) {
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

          Spacer(modifier = Modifier.height(16.dp))

          // Label + Generator & Paste helpers
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
                    .clickable { onGenerateStrongPassword() }
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
                        onSecretTextChange(clip)
                      } else {
                        Toast.makeText(context, "Clipboard is empty", Toast.LENGTH_SHORT).show()
                      }
                    }
                    .padding(horizontal = 6.dp, vertical = 2.dp),
              )
            }
          }

          Spacer(modifier = Modifier.height(6.dp))

          FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
          ) {
            listOf(16, 24, 32).forEach { len ->
              SelectableChip(
                label = "${len}c",
                selected = state.pwLength == len,
                onClick = { onPasswordOptionsChange(len, state.pwIncludeSymbols) },
              )
            }
            SelectableChip(
              label = if (state.pwIncludeSymbols) "Symbols: ON" else "Symbols: OFF",
              selected = state.pwIncludeSymbols,
              onClick = { onPasswordOptionsChange(state.pwLength, !state.pwIncludeSymbols) },
            )
          }

          Spacer(modifier = Modifier.height(8.dp))

          OutlinedTextField(
            value = state.secretText,
            onValueChange = onSecretTextChange,
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
            if (state.secretText.isNotEmpty()) {
              Text(
                text = "Clear",
                color = TextMuted,
                fontSize = 12.sp,
                modifier = Modifier.clickable { onSecretTextChange("") },
              )
            } else {
              Spacer(modifier = Modifier.width(1.dp))
            }
            Text(
              text = "${state.secretText.length} characters",
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
                  text = state.selectedAttachment?.name ?: "Optional File Attachment (Max 1 MB)",
                  color = if (state.selectedAttachment != null) TextPrimary else TextSecondary,
                  fontSize = 13.sp,
                  fontWeight = FontWeight.SemiBold,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                )
                Text(
                  text =
                    state.selectedAttachment?.let {
                      "${it.mime} • ${formatByteSize(it.size)} • Encrypted locally"
                    } ?: "Attach a key, config, or doc before encrypting",
                  color = TextMuted,
                  fontSize = 11.sp,
                )
              }
              Spacer(modifier = Modifier.width(8.dp))
              if (state.selectedAttachment != null) {
                TextButton(
                  onClick = onRemoveAttachment,
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
                    selected = state.selectedTtlSeconds == seconds,
                    onClick = { onSelectTtl(seconds) },
                  )
                }
              }
            }

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
                    selected = state.selectedMaxViews == views,
                    onClick = { onSelectMaxViews(views) },
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
                .clickable { onToggleUsePassphrase(!state.usePassphrase) }
                .padding(vertical = 4.dp),
          ) {
            Checkbox(
              checked = state.usePassphrase,
              onCheckedChange = onToggleUsePassphrase,
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

          if (state.usePassphrase) {
            Spacer(modifier = Modifier.height(6.dp))
            OutlinedTextField(
              value = state.passphrase,
              onValueChange = onPassphraseChange,
              placeholder = { Text("Enter a secret passphrase", color = TextMuted, fontSize = 14.sp) },
              singleLine = true,
              visualTransformation =
                if (state.showPassphraseText) VisualTransformation.None else PasswordVisualTransformation(),
              trailingIcon = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                  TextButton(
                    onClick = onGeneratePassphrase,
                    contentPadding = PaddingValues(horizontal = 6.dp),
                  ) {
                    Text(text = "🎲 Gen", color = AccentPrimary, fontSize = 12.sp)
                  }
                  TextButton(
                    onClick = onToggleShowPassphrase,
                    contentPadding = PaddingValues(horizontal = 6.dp),
                  ) {
                    Text(
                      text = if (state.showPassphraseText) "Hide" else "Show",
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

            val strength = remember(state.passphrase) { SecretCrypto.evaluatePassphraseStrength(state.passphrase) }
            if (strength.score > 0) {
              Spacer(modifier = Modifier.height(6.dp))
              val barColor =
                when (strength.score) {
                  1 -> DangerPrimary
                  2 -> WarningPrimary
                  3 -> InfoPrimary
                  else -> AccentPrimary
                }
              Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
              ) {
                LinearProgressIndicator(
                  progress = { strength.score / 4f },
                  color = barColor,
                  trackColor = BgPrimary,
                  modifier = Modifier.weight(1f).height(6.dp).clip(RoundedCornerShape(999.dp)),
                )
                Text(
                  text = strength.label,
                  color = TextSecondary,
                  fontSize = 11.sp,
                  fontWeight = FontWeight.SemiBold,
                )
              }
            }

            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = "The recipient will be required to enter this passphrase to decrypt the content.",
              color = TextMuted,
              fontSize = 12.sp,
            )
          }

          Spacer(modifier = Modifier.height(12.dp))

          OutlinedTextField(
            value = state.localLabel,
            onValueChange = onLocalLabelChange,
            label = { Text("Local Tracker Label (optional — stays on this device)", fontSize = 12.sp) },
            placeholder = { Text("e.g. Staging API key for Alex", color = TextMuted, fontSize = 13.sp) },
            singleLine = true,
            shape = RoundedCornerShape(8.dp),
            colors = burnBinTextFieldColors(),
            modifier = Modifier.fillMaxWidth(),
          )

          if (state.createErrorBanner != null) {
            Spacer(modifier = Modifier.height(12.dp))
            AlertBox(
              type = AlertType.DANGER,
              title = "Error:",
              message = state.createErrorBanner,
            )
          }

          Spacer(modifier = Modifier.height(18.dp))

          Button(
            onClick = onSubmitSecret,
            enabled = !state.isSubmitting,
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
            if (state.isSubmitting) {
              CircularProgressIndicator(
                color = AccentDarkText,
                strokeWidth = 2.dp,
                modifier = Modifier.size(18.dp),
              )
              Spacer(modifier = Modifier.width(10.dp))
              Text(
                text = state.submitStatusLabel,
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
      val shareUrl = state.generatedShareUrl
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

          val expiryLabel = TrackedSecretsStore.formatAbsoluteExpiry(state.generatedExpiresAtSec)
          if (expiryLabel.isNotBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = "Expires $expiryLabel",
              color = TextMuted,
              fontSize = 12.sp,
            )
          }

          Spacer(modifier = Modifier.height(14.dp))

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
              selected = state.useQueryKeyFormat,
              onClick = { onSelectShareFormat(true) },
            )
            SelectableChip(
              label = "🔒 Hash (#key=)",
              selected = !state.useQueryKeyFormat,
              onClick = { onSelectShareFormat(false) },
            )
          }

          Spacer(modifier = Modifier.height(6.dp))

          Text(
            text = "Chat-Safe (?key=): Best for WhatsApp/SMS so links aren't cut off. Hash (#key=): Key never leaves browser URL fragments.",
            color = TextMuted,
            fontSize = 11.sp,
            lineHeight = 15.sp,
          )

          Spacer(modifier = Modifier.height(10.dp))

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

          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
          ) {
            Button(
              onClick = onCopyGeneratedLink,
              shape = RoundedCornerShape(10.dp),
              colors =
                ButtonDefaults.buttonColors(
                  containerColor = if (state.copyLinkFeedback) AccentPrimary else BgSurfaceElevated,
                  contentColor = if (state.copyLinkFeedback) AccentDarkText else TextPrimary,
                ),
              border = BorderStroke(1.dp, if (state.copyLinkFeedback) AccentPrimary else BorderColor),
              contentPadding = PaddingValues(vertical = 12.dp),
              modifier = Modifier.weight(1f),
            ) {
              Text(
                text = if (state.copyLinkFeedback) "✓ Copied!" else "📋 Copy Link",
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp,
              )
            }

            Button(
              onClick = { shareTextIntent(context, shareUrl) },
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

          OutlinedButton(
            onClick = {
              val viewsNote =
                if (state.selectedMaxViews == 1) "This secret self-destructs after 1 view."
                else "This secret self-destructs after ${state.selectedMaxViews} views."
              val passNote =
                if (state.lastUsedPassphrase) "\nA separate passphrase is required to unlock it."
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
              onClick = onOpenGeneratedInReveal,
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
                showQrCard = false
                onResetCreateForm()
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

    SentSecretsSection(
      trackedSecrets = state.trackedSecrets,
      trackerError = state.trackerError,
      onCheckStatus = onCheckTrackedStatus,
      onBurnNow = onBurnTrackedSecret,
      onDismiss = onDismissTrackedSecret,
    )

    SecurityHighlightsSection()

    Text(
      text = "Zero-Knowledge BurnBin • AES-256-GCM + PBKDF2 • No cookies or trackers",
      color = TextMuted,
      fontSize = 12.sp,
      textAlign = TextAlign.Center,
      modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
    )
  }
}
