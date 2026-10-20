package com.burnbin.app.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val BurnBinDarkColorScheme =
  darkColorScheme(
    primary = AccentPrimary,
    onPrimary = AccentDarkText,
    secondary = BgSurfaceElevated,
    onSecondary = TextPrimary,
    tertiary = InfoPrimary,
    background = BgPrimary,
    onBackground = TextPrimary,
    surface = BgSurface,
    onSurface = TextPrimary,
    surfaceVariant = BgSurfaceElevated,
    onSurfaceVariant = TextSecondary,
    error = DangerPrimary,
    onError = Color.White,
    outline = BorderColor,
  )

@Composable
fun BurnBinTheme(
  darkTheme: Boolean = true,
  dynamicColor: Boolean = false,
  content: @Composable () -> Unit,
) {
  MaterialTheme(
    colorScheme = BurnBinDarkColorScheme,
    typography = Typography,
    content = content,
  )
}
