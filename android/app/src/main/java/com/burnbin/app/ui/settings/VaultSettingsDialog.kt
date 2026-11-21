package com.burnbin.app.ui.settings

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.burnbin.app.data.BurnBinApiClient
import com.burnbin.app.security.canAuthenticateDeviceOrBiometric
import com.burnbin.app.theme.AccentDarkText
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BorderColor
import com.burnbin.app.theme.TextMuted
import com.burnbin.app.theme.TextPrimary
import com.burnbin.app.theme.TextSecondary
import com.burnbin.app.ui.components.burnBinTextFieldColors

@Composable
fun VaultSettingsDialog(
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
