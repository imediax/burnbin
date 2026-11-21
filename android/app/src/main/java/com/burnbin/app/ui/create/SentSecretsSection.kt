package com.burnbin.app.ui.create

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.burnbin.app.data.TrackedSecretItem
import com.burnbin.app.data.TrackedSecretsStore
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BgSurfaceElevated
import com.burnbin.app.theme.BorderColor
import com.burnbin.app.theme.DangerPrimary
import com.burnbin.app.theme.DangerTextLight
import com.burnbin.app.theme.TextMuted
import com.burnbin.app.theme.TextPrimary
import com.burnbin.app.theme.TextSecondary
import com.burnbin.app.ui.components.AlertBox
import com.burnbin.app.ui.components.AlertType

@Composable
fun SentSecretsSection(
  trackedSecrets: List<TrackedSecretItem>,
  trackerError: String?,
  onCheckStatus: (TrackedSecretItem) -> Unit,
  onBurnNow: (TrackedSecretItem) -> Unit,
  onDismiss: (String) -> Unit,
) {
  var trackedExpanded by rememberSaveable { mutableStateOf(false) }

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

        if (!trackerError.isNullOrBlank()) {
          AlertBox(type = AlertType.DANGER, title = null, message = trackerError)
          Spacer(modifier = Modifier.height(8.dp))
        }

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
                        append(TrackedSecretsStore.formatExpiryCountdown(item.expiresAtMs))
                        if (item.hasAttachment) append(" • 📎 File")
                      },
                    color = TextMuted,
                    fontSize = 11.sp,
                  )

                  Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                      onClick = { onCheckStatus(item) },
                      shape = RoundedCornerShape(8.dp),
                      border = BorderStroke(1.dp, BorderColor),
                      contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    ) {
                      Text(text = "🔄 Status", color = TextPrimary, fontSize = 11.sp)
                    }

                    if (effectiveStatus == "active" && item.deleteToken.isNotBlank()) {
                      OutlinedButton(
                        onClick = { onBurnNow(item) },
                        shape = RoundedCornerShape(8.dp),
                        border = BorderStroke(1.dp, DangerPrimary.copy(alpha = 0.5f)),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                      ) {
                        Text(text = "🔥 Burn Now", color = DangerTextLight, fontSize = 11.sp)
                      }
                    }

                    TextButton(
                      onClick = { onDismiss(item.id) },
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
}
