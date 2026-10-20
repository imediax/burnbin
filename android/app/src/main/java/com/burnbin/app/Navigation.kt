package com.burnbin.app

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import com.burnbin.app.ui.main.MainScreen

@Composable
fun MainNavigation(
  initialSharedText: String? = null,
  initialDeepLinkUrl: String? = null,
  deepLinkTrigger: Long = 0L,
  onToggleSecureScreen: (Boolean) -> Unit = {},
) {
  val backStack = rememberNavBackStack(Main)

  NavDisplay(
    backStack = backStack,
    onBack = { backStack.removeLastOrNull() },
    entryProvider =
      entryProvider {
        entry<Main> {
          MainScreen(
            onItemClick = { navKey -> backStack.add(navKey) },
            modifier = Modifier.fillMaxSize().safeDrawingPadding(),
            initialSharedText = initialSharedText,
            initialDeepLinkUrl = initialDeepLinkUrl,
            deepLinkTrigger = deepLinkTrigger,
            onToggleSecureScreen = onToggleSecureScreen,
          )
        }
      },
  )
}
