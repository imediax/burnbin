package com.burnbin.app.ui.main

import android.app.Application
import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.burnbin.app.crypto.DecodedAttachment
import com.burnbin.app.crypto.InvalidKeyException
import com.burnbin.app.crypto.InvalidPassphraseException
import com.burnbin.app.crypto.ParsedSecretLink
import com.burnbin.app.crypto.SecretCrypto
import com.burnbin.app.data.ApiException
import com.burnbin.app.data.BurnBinApiClient
import com.burnbin.app.data.ConsumedSecretResponse
import com.burnbin.app.data.SecretMetaResponse
import com.burnbin.app.data.TrackedSecretItem
import com.burnbin.app.data.TrackedSecretsStore
import com.burnbin.app.security.authenticateForReveal
import com.burnbin.app.security.clearClipboard
import com.burnbin.app.security.copyToClipboard
import com.burnbin.app.security.readAttachmentFromUri
import com.burnbin.app.ui.components.BurnBinTab
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface RevealUiState {
  data object Idle : RevealUiState
  data object CheckingVault : RevealUiState
  data class Error(val message: String) : RevealUiState
  data class PreReveal(
    val parsedLink: ParsedSecretLink,
    val meta: SecretMetaResponse,
    val cachedConsumed: ConsumedSecretResponse? = null,
    val passphraseError: String? = null,
    val isRevealing: Boolean = false,
    val failedPassphraseAttempts: Int = 0,
  ) : RevealUiState

  data class Revealed(
    val plaintext: String,
    val attachment: DecodedAttachment? = null,
    val burned: Boolean,
    val viewsLeft: Int,
  ) : RevealUiState
}

data class BurnBinUiState(
  val serverUrl: String = BurnBinApiClient.DEFAULT_SERVER_URL,
  val secureScreenEnabled: Boolean = false,
  val autoClearClipboardEnabled: Boolean = true,
  val biometricRevealEnabled: Boolean = false,
  val activeTab: BurnBinTab = BurnBinTab.CREATE,
  // Create state
  val secretText: String = "",
  val pwLength: Int = 24,
  val pwIncludeSymbols: Boolean = true,
  val selectedTtlSeconds: Int = 3600,
  val selectedMaxViews: Int = 1,
  val usePassphrase: Boolean = false,
  val passphrase: String = "",
  val showPassphraseText: Boolean = false,
  val localLabel: String = "",
  val selectedAttachment: DecodedAttachment? = null,
  val isSubmitting: Boolean = false,
  val submitStatusLabel: String = "",
  val createErrorBanner: String? = null,
  val generatedSecretId: String? = null,
  val generatedUrlKey: String? = null,
  val generatedShareUrl: String? = null,
  val generatedExpiresAtSec: Long = 0L,
  val useQueryKeyFormat: Boolean = false,
  val lastUsedPassphrase: Boolean = false,
  val copyLinkFeedback: Boolean = false,
  val trackedSecrets: List<TrackedSecretItem> = emptyList(),
  val trackerError: String? = null,
  // Reveal state
  val revealLinkInput: String = "",
  val revealUiState: RevealUiState = RevealUiState.Idle,
  val decryptPassphrase: String = "",
  val manualKeyInput: String = "",
  val showDecryptPassphrase: Boolean = false,
  val copiedSecretFeedback: Boolean = false,
  // Persistent clipboard auto-clear timer (survives tab switches)
  val clipboardCountdownSeconds: Int = 0,
  val clipboardClearedBanner: Boolean = false,
)

class BurnBinViewModel(application: Application) : AndroidViewModel(application) {
  companion object {
    const val MAX_PASSPHRASE_ATTEMPTS = 5
    const val CLIPBOARD_CLEAR_SECONDS = 45
  }

  private val prefs = application.getSharedPreferences("burnbin_prefs", Context.MODE_PRIVATE)
  private val _uiState = MutableStateFlow(
    BurnBinUiState(
      serverUrl = prefs.getString("server_url", BurnBinApiClient.DEFAULT_SERVER_URL)
        ?: BurnBinApiClient.DEFAULT_SERVER_URL,
      secureScreenEnabled = prefs.getBoolean("secure_screen", false),
      autoClearClipboardEnabled = prefs.getBoolean("auto_clear_clipboard", true),
      biometricRevealEnabled = prefs.getBoolean("biometric_reveal", false),
      trackedSecrets = TrackedSecretsStore.load(prefs),
    )
  )
  val uiState: StateFlow<BurnBinUiState> = _uiState.asStateFlow()

  private var clipboardTimerJob: Job? = null
  private var lastHandledDeepLinkTrigger = -1L
  private var lastHandledSharedTextTrigger = -1L
  private var lastHandledSharedFileTrigger = -1L

  fun selectTab(tab: BurnBinTab) {
    _uiState.update { it.copy(activeTab = tab) }
  }

  fun saveSettings(
    newUrl: String,
    secureScreen: Boolean,
    autoClearClipboard: Boolean,
    biometricReveal: Boolean,
  ) {
    val cleaned = newUrl.trim().trimEnd('/').ifEmpty { BurnBinApiClient.DEFAULT_SERVER_URL }
    prefs.edit()
      .putString("server_url", cleaned)
      .putBoolean("secure_screen", secureScreen)
      .putBoolean("auto_clear_clipboard", autoClearClipboard)
      .putBoolean("biometric_reveal", biometricReveal)
      .apply()
    _uiState.update {
      it.copy(
        serverUrl = cleaned,
        secureScreenEnabled = secureScreen,
        autoClearClipboardEnabled = autoClearClipboard,
        biometricRevealEnabled = biometricReveal,
      )
    }
    if (!autoClearClipboard) {
      clipboardTimerJob?.cancel()
      _uiState.update { it.copy(clipboardCountdownSeconds = 0) }
    }
  }

  fun handleDeepLink(url: String?, trigger: Long) {
    if (url.isNullOrBlank() || trigger == lastHandledDeepLinkTrigger) return
    lastHandledDeepLinkTrigger = trigger
    _uiState.update { it.copy(revealLinkInput = url, activeTab = BurnBinTab.REVEAL) }
    checkSecretLink(url)
  }

  fun handleSharedText(text: String?, trigger: Long) {
    if (text.isNullOrBlank() || trigger == lastHandledSharedTextTrigger) return
    lastHandledSharedTextTrigger = trigger
    _uiState.update {
      it.copy(
        activeTab = BurnBinTab.CREATE,
        secretText = text,
        generatedShareUrl = null,
        generatedSecretId = null,
        generatedUrlKey = null,
        createErrorBanner = null,
        copyLinkFeedback = false,
      )
    }
  }

  fun handleSharedFile(uri: Uri?, trigger: Long) {
    if (uri == null || trigger == lastHandledSharedFileTrigger) return
    lastHandledSharedFileTrigger = trigger
    _uiState.update {
      it.copy(
        activeTab = BurnBinTab.CREATE,
        generatedShareUrl = null,
        generatedSecretId = null,
        generatedUrlKey = null,
        createErrorBanner = null,
        copyLinkFeedback = false,
      )
    }
    attachFileFromUri(uri)
  }

  // Create form actions
  fun updateSecretText(value: String) {
    _uiState.update { it.copy(secretText = value, createErrorBanner = null) }
  }

  fun updatePasswordOptions(length: Int, includeSymbols: Boolean) {
    _uiState.update { it.copy(pwLength = length, pwIncludeSymbols = includeSymbols) }
  }

  fun generateStrongPassword() {
    val s = _uiState.value
    val pw = SecretCrypto.generateStrongPassword(s.pwLength, s.pwIncludeSymbols)
    _uiState.update { it.copy(secretText = pw, createErrorBanner = null) }
  }

  fun selectTtl(seconds: Int) {
    _uiState.update { it.copy(selectedTtlSeconds = seconds) }
  }

  fun selectMaxViews(views: Int) {
    _uiState.update { it.copy(selectedMaxViews = views) }
  }

  fun toggleUsePassphrase(enabled: Boolean) {
    _uiState.update {
      it.copy(
        usePassphrase = enabled,
        passphrase = if (enabled) it.passphrase else "",
        createErrorBanner = null,
      )
    }
  }

  fun updatePassphrase(value: String) {
    _uiState.update { it.copy(passphrase = value, createErrorBanner = null) }
  }

  fun toggleShowPassphraseText() {
    _uiState.update { it.copy(showPassphraseText = !it.showPassphraseText) }
  }

  fun generateShareablePassphrase() {
    val phrase = SecretCrypto.generateShareablePassphrase()
    _uiState.update { it.copy(passphrase = phrase, showPassphraseText = true, createErrorBanner = null) }
  }

  fun updateLocalLabel(label: String) {
    if (label.length <= 80) {
      _uiState.update { it.copy(localLabel = label) }
    }
  }

  fun attachFileFromUri(uri: Uri) {
    val appCtx = getApplication<Application>()
    viewModelScope.launch {
      val fileRes = withContext(Dispatchers.IO) { readAttachmentFromUri(appCtx, uri) }
      fileRes
        .onSuccess { attachment ->
          _uiState.update { it.copy(selectedAttachment = attachment, createErrorBanner = null) }
        }
        .onFailure { err ->
          _uiState.update { it.copy(createErrorBanner = err.message ?: "Could not attach selected file.") }
        }
    }
  }

  fun removeAttachment() {
    _uiState.update { it.copy(selectedAttachment = null) }
  }

  fun selectShareFormat(useQuery: Boolean) {
    _uiState.update { s ->
      val id = s.generatedSecretId
      val key = s.generatedUrlKey
      val cleanServer = s.serverUrl.trim().trimEnd('/')
      val updatedUrl =
        if (id != null && key != null) {
          val sep = if (useQuery) "?key=" else "#key="
          "$cleanServer/secret/$id$sep$key"
        } else {
          s.generatedShareUrl
        }
      s.copy(
        useQueryKeyFormat = useQuery,
        generatedShareUrl = updatedUrl,
        copyLinkFeedback = false,
      )
    }
  }

  fun copyGeneratedLink() {
    val shareUrl = _uiState.value.generatedShareUrl ?: return
    copyToClipboard(getApplication(), "BurnBin Secret Link", shareUrl, sensitive = true)
    _uiState.update { it.copy(copyLinkFeedback = true) }
  }

  fun resetCreateForm() {
    _uiState.update {
      it.copy(
        secretText = "",
        passphrase = "",
        usePassphrase = false,
        showPassphraseText = false,
        localLabel = "",
        selectedAttachment = null,
        generatedShareUrl = null,
        generatedSecretId = null,
        generatedUrlKey = null,
        generatedExpiresAtSec = 0L,
        copyLinkFeedback = false,
        createErrorBanner = null,
      )
    }
  }

  fun submitSecret() {
    val s = _uiState.value
    val trimmedSecret = s.secretText.trim()
    val attachmentToSend = s.selectedAttachment
    if (trimmedSecret.isEmpty() && attachmentToSend == null) {
      _uiState.update { it.copy(createErrorBanner = "Please enter a secret message or attach an encrypted file.") }
      return
    }
    val trimmedPass = if (s.usePassphrase) s.passphrase.trim() else null
    if (s.usePassphrase && trimmedPass.isNullOrEmpty()) {
      _uiState.update { it.copy(createErrorBanner = "Please enter a passphrase or uncheck passphrase protection.") }
      return
    }

    _uiState.update { it.copy(createErrorBanner = null, isSubmitting = true, submitStatusLabel = "Encrypting locally...") }

    viewModelScope.launch {
      try {
        val encrypted =
          withContext(Dispatchers.Default) {
            val payloadBytes = SecretCrypto.encodePayload(trimmedSecret, attachmentToSend)
            SecretCrypto.encryptBytes(payloadBytes, trimmedPass)
          }

        _uiState.update { it.copy(submitStatusLabel = "Saving to vault...") }

        val apiResult =
          BurnBinApiClient.createSecret(
            baseUrl = s.serverUrl,
            ciphertext = encrypted.ciphertext,
            iv = encrypted.iv,
            salt = encrypted.salt,
            maxViews = s.selectedMaxViews,
            ttlSeconds = s.selectedTtlSeconds,
          )

        apiResult
          .onSuccess { created ->
            val cleanServer = s.serverUrl.trim().trimEnd('/')
            val sep = if (s.useQueryKeyFormat) "?key=" else "#key="
            val shareUrl = "$cleanServer/secret/${created.id}$sep${encrypted.urlKey}"
            val expiresAtSec =
              if (created.expiresAt > 0L) created.expiresAt
              else (System.currentTimeMillis() / 1000L) + s.selectedTtlSeconds

            val trackedEntry =
              TrackedSecretItem(
                id = created.id,
                baseUrl = cleanServer,
                label = s.localLabel.trim(),
                createdAtMs = System.currentTimeMillis(),
                expiresAtMs = expiresAtSec * 1000L,
                maxViews = created.maxViews,
                viewsLeft = created.maxViews,
                deleteToken = created.deleteToken ?: "",
                hasAttachment = attachmentToSend != null,
                status = "active",
              )
            val updatedList = listOf(trackedEntry) + _uiState.value.trackedSecrets.filterNot { it.id == created.id }
            TrackedSecretsStore.save(prefs, updatedList)

            _uiState.update {
              it.copy(
                generatedSecretId = created.id,
                generatedUrlKey = encrypted.urlKey,
                generatedShareUrl = shareUrl,
                generatedExpiresAtSec = expiresAtSec,
                lastUsedPassphrase = trimmedPass != null,
                copyLinkFeedback = false,
                trackedSecrets = updatedList,
                selectedAttachment = null,
              )
            }
          }
          .onFailure { err ->
            _uiState.update { it.copy(createErrorBanner = err.message ?: "Failed to save secret to vault.") }
          }
      } catch (e: Exception) {
        _uiState.update { it.copy(createErrorBanner = "Encryption error: ${e.message}") }
      } finally {
        _uiState.update { it.copy(isSubmitting = false) }
      }
    }
  }

  // Sent secrets tracker actions
  fun checkTrackedSecretStatus(item: TrackedSecretItem) {
    _uiState.update { it.copy(trackerError = null) }
    viewModelScope.launch {
      val metaRes = BurnBinApiClient.getSecretMeta(item.baseUrl, item.id)
      metaRes
        .onSuccess { meta ->
          val updatedItem =
            item.copy(
              status = "active",
              viewsLeft = meta.viewsLeft,
              expiresAtMs = if (meta.expiresAt > 0L) meta.expiresAt * 1000L else item.expiresAtMs,
            )
          val updatedList = _uiState.value.trackedSecrets.map { if (it.id == item.id) updatedItem else it }
          TrackedSecretsStore.save(prefs, updatedList)
          _uiState.update { it.copy(trackedSecrets = updatedList) }
        }
        .onFailure { err ->
          if (err is ApiException.NotFound) {
            val updatedList =
              _uiState.value.trackedSecrets.map {
                if (it.id == item.id) it.copy(status = "burned", viewsLeft = 0) else it
              }
            TrackedSecretsStore.save(prefs, updatedList)
            _uiState.update { it.copy(trackedSecrets = updatedList) }
          } else {
            _uiState.update {
              it.copy(trackerError = err.message ?: "Could not check secret status (check network).")
            }
          }
        }
    }
  }

  fun revokeTrackedSecret(item: TrackedSecretItem) {
    _uiState.update { it.copy(trackerError = null) }
    viewModelScope.launch {
      val revokeRes =
        BurnBinApiClient.revokeSecret(
          baseUrl = item.baseUrl,
          secretId = item.id,
          deleteToken = item.deleteToken,
        )
      revokeRes
        .onSuccess {
          val updatedList =
            _uiState.value.trackedSecrets.map {
              if (it.id == item.id) it.copy(status = "burned", viewsLeft = 0) else it
            }
          TrackedSecretsStore.save(prefs, updatedList)
          _uiState.update { it.copy(trackedSecrets = updatedList) }
          Toast.makeText(getApplication(), "Secret burned on server", Toast.LENGTH_SHORT).show()
        }
        .onFailure { err ->
          _uiState.update { it.copy(trackerError = err.message ?: "Failed to burn secret.") }
        }
    }
  }

  fun dismissTrackedSecret(id: String) {
    val updatedList = _uiState.value.trackedSecrets.filterNot { it.id == id }
    TrackedSecretsStore.save(prefs, updatedList)
    _uiState.update { it.copy(trackedSecrets = updatedList) }
  }

  // Reveal actions
  fun openGeneratedInReveal() {
    val shareUrl = _uiState.value.generatedShareUrl ?: return
    _uiState.update { it.copy(revealLinkInput = shareUrl, activeTab = BurnBinTab.REVEAL) }
    checkSecretLink(shareUrl)
  }

  fun openWebLinkInReveal(secretUrl: String) {
    _uiState.update { it.copy(revealLinkInput = secretUrl, activeTab = BurnBinTab.REVEAL) }
    checkSecretLink(secretUrl)
  }

  fun switchToCreateFromReveal() {
    _uiState.update {
      it.copy(
        revealLinkInput = "",
        revealUiState = RevealUiState.Idle,
        decryptPassphrase = "",
        manualKeyInput = "",
        activeTab = BurnBinTab.CREATE,
      )
    }
  }

  fun updateRevealLinkInput(url: String) {
    _uiState.update {
      it.copy(
        revealLinkInput = url,
        revealUiState = if (it.revealUiState !is RevealUiState.Idle) RevealUiState.Idle else it.revealUiState,
      )
    }
  }

  fun updateManualKeyInput(value: String) {
    _uiState.update { s ->
      val nextReveal =
        if (s.revealUiState is RevealUiState.PreReveal && !s.revealUiState.passphraseError.isNullOrBlank()) {
          s.revealUiState.copy(passphraseError = null)
        } else {
          s.revealUiState
        }
      s.copy(manualKeyInput = value.trim(), revealUiState = nextReveal)
    }
  }

  fun updateDecryptPassphrase(value: String) {
    _uiState.update { s ->
      val nextReveal =
        if (s.revealUiState is RevealUiState.PreReveal && !s.revealUiState.passphraseError.isNullOrBlank()) {
          s.revealUiState.copy(passphraseError = null)
        } else {
          s.revealUiState
        }
      s.copy(decryptPassphrase = value, revealUiState = nextReveal)
    }
  }

  fun toggleShowDecryptPassphrase() {
    _uiState.update { it.copy(showDecryptPassphrase = !it.showDecryptPassphrase) }
  }

  fun clearRevealState(wipeActiveTimerClipboard: Boolean = false) {
    if (wipeActiveTimerClipboard && _uiState.value.clipboardCountdownSeconds > 0) {
      clearClipboard(getApplication())
    }
    clipboardTimerJob?.cancel()
    _uiState.update {
      it.copy(
        revealLinkInput = "",
        decryptPassphrase = "",
        manualKeyInput = "",
        revealUiState = RevealUiState.Idle,
        copiedSecretFeedback = false,
        clipboardCountdownSeconds = 0,
        clipboardClearedBanner = false,
      )
    }
  }

  fun checkSecretLink(rawUrl: String) {
    val parsedRes = SecretCrypto.parseSecretLink(rawUrl, _uiState.value.serverUrl)
    parsedRes
      .onFailure { err ->
        _uiState.update { it.copy(revealUiState = RevealUiState.Error(err.message ?: "Invalid BurnBin link.")) }
      }
      .onSuccess { parsed ->
        _uiState.update {
          it.copy(
            revealUiState = RevealUiState.CheckingVault,
            decryptPassphrase = "",
            manualKeyInput = parsed.urlKey ?: "",
            copiedSecretFeedback = false,
          )
        }
        viewModelScope.launch {
          val metaRes = BurnBinApiClient.getSecretMeta(parsed.baseUrl, parsed.secretId)
          metaRes
            .onSuccess { meta ->
              _uiState.update {
                it.copy(revealUiState = RevealUiState.PreReveal(parsedLink = parsed, meta = meta))
              }
            }
            .onFailure { err ->
              _uiState.update {
                it.copy(
                  revealUiState = RevealUiState.Error(
                    err.message ?: "This secret does not exist, has expired, or has already been burned."
                  )
                )
              }
            }
        }
      }
  }

  fun revealCurrentSecret(uiContext: Context) {
    val state = _uiState.value.revealUiState as? RevealUiState.PreReveal ?: return
    val effectiveKey =
      if (!state.parsedLink.urlKey.isNullOrBlank()) state.parsedLink.urlKey else _uiState.value.manualKeyInput.trim()

    if (effectiveKey.isBlank() || !effectiveKey.matches(Regex("^[a-fA-F0-9]{64}$"))) {
      _uiState.update {
        it.copy(
          revealUiState = state.copy(
            passphraseError = "Missing or invalid decryption key. Please enter a valid 64-character hexadecimal key."
          )
        )
      }
      return
    }

    val pass = if (state.meta.requiresPassphrase) _uiState.value.decryptPassphrase.trim() else null
    if (state.meta.requiresPassphrase && pass.isNullOrEmpty()) {
      _uiState.update {
        it.copy(revealUiState = state.copy(passphraseError = "Please enter the passphrase to unlock this secret."))
      }
      return
    }

    val executeConsumeAndDecrypt: () -> Unit = {
      val currentPre = _uiState.value.revealUiState as? RevealUiState.PreReveal ?: state
      _uiState.update { it.copy(revealUiState = currentPre.copy(isRevealing = true, passphraseError = null)) }
      viewModelScope.launch {
        val payload =
          if (currentPre.cachedConsumed != null) {
            currentPre.cachedConsumed
          } else {
            val res =
              BurnBinApiClient.consumeSecret(
                baseUrl = currentPre.parsedLink.baseUrl,
                secretId = currentPre.parsedLink.secretId,
              )
            val consumed = res.getOrNull()
            if (consumed == null) {
              _uiState.update {
                it.copy(
                  revealUiState = RevealUiState.Error(
                    res.exceptionOrNull()?.message
                      ?: "This secret could not be retrieved. It may have just been burned or expired."
                  )
                )
              }
              return@launch
            }
            consumed
          }

        try {
          val decoded =
            withContext(Dispatchers.Default) {
              val plainBytes =
                SecretCrypto.decryptBytes(
                  ciphertextB64 = payload.ciphertext,
                  ivCombined = payload.iv,
                  saltHex = payload.salt,
                  urlKeyHex = effectiveKey,
                  passphrase = pass,
                )
              SecretCrypto.decodePayload(plainBytes)
            }
          _uiState.update {
            it.copy(
              revealUiState = RevealUiState.Revealed(
                plaintext = decoded.text,
                attachment = decoded.attachment,
                burned = payload.burned,
                viewsLeft = payload.viewsLeft,
              )
            )
          }
        } catch (e: InvalidPassphraseException) {
          val nextAttempts = currentPre.failedPassphraseAttempts + 1
          if (nextAttempts >= MAX_PASSPHRASE_ATTEMPTS) {
            _uiState.update {
              it.copy(
                decryptPassphrase = "",
                revealUiState = RevealUiState.Error(
                  "Too many incorrect passphrase attempts ($MAX_PASSPHRASE_ATTEMPTS). Encrypted payload has been wiped from device memory."
                ),
              )
            }
          } else {
            _uiState.update {
              it.copy(
                revealUiState = currentPre.copy(
                  cachedConsumed = payload,
                  isRevealing = false,
                  failedPassphraseAttempts = nextAttempts,
                  passphraseError = "Incorrect passphrase (attempt $nextAttempts of $MAX_PASSPHRASE_ATTEMPTS).",
                )
              )
            }
          }
        } catch (e: InvalidKeyException) {
          _uiState.update {
            it.copy(
              manualKeyInput = effectiveKey,
              revealUiState = currentPre.copy(
                parsedLink = currentPre.parsedLink.copy(urlKey = null),
                cachedConsumed = payload,
                isRevealing = false,
                passphraseError = e.message ?: "Decryption failed: Invalid or corrupted key in link.",
              ),
            )
          }
        } catch (e: Exception) {
          _uiState.update {
            it.copy(
              revealUiState = currentPre.copy(
                cachedConsumed = payload,
                isRevealing = false,
                passphraseError = e.message ?: "Failed to decrypt secret.",
              )
            )
          }
        }
      }
    }

    if (_uiState.value.biometricRevealEnabled && state.cachedConsumed == null) {
      authenticateForReveal(
        context = uiContext,
        onSuccess = executeConsumeAndDecrypt,
        onErrorOrCancel = { errMsg ->
          _uiState.update { it.copy(revealUiState = state.copy(passphraseError = errMsg)) }
        },
      )
    } else {
      executeConsumeAndDecrypt()
    }
  }

  // Persistent ViewModel-scoped clipboard countdown (survives switching tabs)
  fun copyRevealedSecret(plaintext: String) {
    val appCtx = getApplication<Application>()
    copyToClipboard(appCtx, "Decrypted Secret", plaintext, sensitive = true)
    _uiState.update { it.copy(copiedSecretFeedback = true, clipboardClearedBanner = false) }
    clipboardTimerJob?.cancel()
    if (_uiState.value.autoClearClipboardEnabled) {
      clipboardTimerJob =
        viewModelScope.launch {
          for (sec in CLIPBOARD_CLEAR_SECONDS downTo 1) {
            _uiState.update { it.copy(clipboardCountdownSeconds = sec) }
            delay(1_000L)
          }
          clearClipboard(appCtx)
          _uiState.update {
            it.copy(
              clipboardCountdownSeconds = 0,
              copiedSecretFeedback = false,
              clipboardClearedBanner = true,
            )
          }
        }
    }
  }

  fun clearClipboardNow() {
    clipboardTimerJob?.cancel()
    clearClipboard(getApplication())
    _uiState.update {
      it.copy(
        clipboardCountdownSeconds = 0,
        copiedSecretFeedback = false,
        clipboardClearedBanner = true,
      )
    }
  }
}
