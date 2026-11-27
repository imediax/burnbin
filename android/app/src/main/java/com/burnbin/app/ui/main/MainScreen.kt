package com.burnbin.app.ui.main

import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.burnbin.app.theme.BgPrimary
import com.burnbin.app.theme.BurnBinTheme
import com.burnbin.app.ui.components.BurnBinHeader
import com.burnbin.app.ui.components.BurnBinTab
import com.burnbin.app.ui.components.BurnBinTabBar
import com.burnbin.app.ui.create.CreateSecretScreen
import com.burnbin.app.ui.reveal.RevealSecretScreen
import com.burnbin.app.ui.settings.VaultSettingsDialog

@Composable
fun MainScreen(
  modifier: Modifier = Modifier,
  initialSharedText: String? = null,
  sharedTextTrigger: Long = 0L,
  initialSharedFileUri: Uri? = null,
  sharedFileTrigger: Long = 0L,
  initialDeepLinkUrl: String? = null,
  deepLinkTrigger: Long = 0L,
  viewModel: BurnBinViewModel = viewModel(),
) {
  val context = LocalContext.current
  val state by viewModel.uiState.collectAsStateWithLifecycle()
  var showSettingsDialog by rememberSaveable { mutableStateOf(false) }

  LaunchedEffect(initialDeepLinkUrl, deepLinkTrigger) {
    viewModel.handleDeepLink(initialDeepLinkUrl, deepLinkTrigger)
  }

  LaunchedEffect(initialSharedText, sharedTextTrigger) {
    viewModel.handleSharedText(initialSharedText, sharedTextTrigger)
  }

  LaunchedEffect(initialSharedFileUri, sharedFileTrigger) {
    viewModel.handleSharedFile(initialSharedFileUri, sharedFileTrigger)
  }

  Column(
    modifier = modifier.fillMaxSize().background(BgPrimary),
  ) {
    BurnBinHeader(
      onLogoClick = { viewModel.selectTab(BurnBinTab.CREATE) },
      onSettingsClick = { showSettingsDialog = true },
    )

    BurnBinTabBar(
      activeTab = state.activeTab,
      onTabSelected = viewModel::selectTab,
    )

    Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
      when (state.activeTab) {
        BurnBinTab.CREATE -> {
          CreateSecretScreen(
            state = state,
            onSecretTextChange = viewModel::updateSecretText,
            onPasswordOptionsChange = viewModel::updatePasswordOptions,
            onGenerateStrongPassword = viewModel::generateStrongPassword,
            onAttachFileUri = viewModel::attachFileFromUri,
            onRemoveAttachment = viewModel::removeAttachment,
            onSelectTtl = viewModel::selectTtl,
            onSelectMaxViews = viewModel::selectMaxViews,
            onToggleUsePassphrase = viewModel::toggleUsePassphrase,
            onPassphraseChange = viewModel::updatePassphrase,
            onToggleShowPassphrase = viewModel::toggleShowPassphraseText,
            onGeneratePassphrase = viewModel::generateShareablePassphrase,
            onSubmitSecret = viewModel::submitSecret,
            onCopyGeneratedLink = viewModel::copyGeneratedLink,
            onOpenGeneratedInReveal = viewModel::openGeneratedInReveal,
            onResetCreateForm = viewModel::resetCreateForm,
          )
        }
        BurnBinTab.REVEAL -> {
          RevealSecretScreen(
            state = state,
            onLinkInputChange = viewModel::updateRevealLinkInput,
            onCheckSecretLink = viewModel::checkSecretLink,
            onManualKeyChange = viewModel::updateManualKeyInput,
            onDecryptPassphraseChange = viewModel::updateDecryptPassphrase,
            onToggleShowDecryptPassphrase = viewModel::toggleShowDecryptPassphrase,
            onRevealSecretClick = { viewModel.revealCurrentSecret(context) },
            onCopySecretClick = viewModel::copyRevealedSecret,
            onClearClipboardNow = viewModel::clearClipboardNow,
            onClearReveal = viewModel::clearRevealState,
            onCreateNewClick = viewModel::switchToCreateFromReveal,
          )
        }
      }
    }
  }

  if (showSettingsDialog) {
    VaultSettingsDialog(
      currentServerUrl = state.serverUrl,
      autoClearClipboardEnabled = state.autoClearClipboardEnabled,
      biometricRevealEnabled = state.biometricRevealEnabled,
      onDismiss = { showSettingsDialog = false },
      onSave = { newUrl, newAutoClear, newBiometric ->
        viewModel.saveSettings(newUrl, newAutoClear, newBiometric)
        showSettingsDialog = false
        Toast.makeText(context, "Settings saved", Toast.LENGTH_SHORT).show()
      },
    )
  }
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
  BurnBinTheme { MainScreen() }
}
