package com.burnbin.app.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.burnbin.app.theme.AccentDarkText
import com.burnbin.app.theme.AccentPrimary
import com.burnbin.app.theme.BgPrimary
import com.burnbin.app.theme.BgSurface
import com.burnbin.app.theme.BorderColor
import com.burnbin.app.theme.TextPrimary
import com.burnbin.app.theme.TextSecondary

@Composable
fun AppLockScreen(
  modifier: Modifier = Modifier,
  errorMessage: String?,
  deviceLockAvailable: Boolean,
  onUnlockClick: () -> Unit,
  onDisableLockWhenUnavailable: () -> Unit,
) {
  Box(
    modifier = modifier.fillMaxSize().background(BgPrimary).padding(24.dp),
    contentAlignment = Alignment.Center,
  ) {
    Surface(
      color = BgSurface,
      shape = RoundedCornerShape(16.dp),
      border = BorderStroke(1.dp, BorderColor),
      modifier = Modifier.fillMaxWidth(),
    ) {
      Column(
        modifier = Modifier.padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        Text(
          text = "🔒 BurnBin Locked",
          color = TextPrimary,
          fontSize = 22.sp,
          fontWeight = FontWeight.Bold,
          textAlign = TextAlign.Center,
        )
        Text(
          text = "Unlock with biometrics or your device PIN, pattern, or password to access BurnBin.",
          color = TextSecondary,
          fontSize = 14.sp,
          lineHeight = 20.sp,
          textAlign = TextAlign.Center,
        )

        if (errorMessage != null) {
          AlertBox(type = AlertType.DANGER, title = null, message = errorMessage)
        }

        Spacer(modifier = Modifier.height(4.dp))

        Button(
          onClick = onUnlockClick,
          shape = RoundedCornerShape(10.dp),
          colors = ButtonDefaults.buttonColors(containerColor = AccentPrimary, contentColor = AccentDarkText),
          contentPadding = PaddingValues(vertical = 14.dp),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Text(
            text = "🔓 Unlock BurnBin",
            fontWeight = FontWeight.Bold,
            fontSize = 15.sp,
          )
        }

        if (!deviceLockAvailable) {
          OutlinedButton(
            onClick = onDisableLockWhenUnavailable,
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, BorderColor),
            contentPadding = PaddingValues(vertical = 12.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "Disable App Lock & Continue",
              color = TextSecondary,
              fontWeight = FontWeight.SemiBold,
              fontSize = 13.sp,
            )
          }
        }
      }
    }
  }
}
