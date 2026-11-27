package com.burnbin.app.ui.components

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.burnbin.app.theme.AccentDarkText
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BgSurfaceElevated
import com.burnbin.app.theme.BorderColor
import com.burnbin.app.theme.DangerPrimary
import com.burnbin.app.theme.DangerTextLight
import com.burnbin.app.theme.InfoPrimary
import com.burnbin.app.theme.InfoTextLight
import com.burnbin.app.theme.TextMuted
import com.burnbin.app.theme.TextPrimary
import com.burnbin.app.theme.TextSecondary
import com.burnbin.app.theme.WarningPrimary
import com.burnbin.app.theme.WarningTextLight

enum class BurnBinTab {
  CREATE,
  REVEAL,
}

enum class AlertType {
  WARNING,
  DANGER,
  INFO,
}

private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

@Composable
fun BurnBinHeader(
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
fun BurnBinTabBar(
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

@Composable
fun SelectableChip(
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

@Composable
fun AlertBox(
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

@Composable
fun SecurityHighlightsSection() {
  Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
    SecurityHighlightCard(
      title = "🔒 End-to-End Encrypted",
      description =
        "Encryption happens locally on your Android device with AES-256-GCM. Generated links keep the decryption key inside the #key= URL fragment.",
    )
    SecurityHighlightCard(
      title = "🔥 True Burn-on-Read",
      description =
        "Data is stored atomically per view. Once the view limit is reached, the active encrypted record is deleted and is no longer retrievable via BurnBin.",
    )
    SecurityHighlightCard(
      title = "⏱️ Automatic TTL Purge",
      description =
        "Unopened secrets expire automatically and are deleted after their TTL.",
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
fun burnBinTextFieldColors() =
  OutlinedTextFieldDefaults.colors(
    focusedContainerColor = BgPrimary,
    unfocusedContainerColor = BgPrimary,
    focusedBorderColor = AccentPrimary,
    unfocusedBorderColor = BorderColor,
    cursorColor = AccentPrimary,
    focusedTextColor = TextPrimary,
    unfocusedTextColor = TextPrimary,
  )

fun shareTextIntent(context: Context, text: String) {
  val sendIntent =
    Intent(Intent.ACTION_SEND).apply {
      putExtra(Intent.EXTRA_TEXT, text)
      type = "text/plain"
    }
  val shareIntent = Intent.createChooser(sendIntent, "Share BurnBin Secret Link")
  context.startActivity(shareIntent)
}
