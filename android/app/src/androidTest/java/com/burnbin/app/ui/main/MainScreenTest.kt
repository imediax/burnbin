package com.burnbin.app.ui.main

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/** UI tests for [com.burnbin.app.ui.main.MainScreen]. */
class MainScreenTest {

  @get:Rule val composeTestRule = createAndroidComposeRule<ComponentActivity>()

  @Before
  fun setup() {
    composeTestRule.setContent { MainScreen() }
  }

  @Test
  fun burnBinHeaderAndTabs_exist() {
    composeTestRule.onNodeWithText("BurnBin").assertExists()
    composeTestRule.onNodeWithText("🔒 Create Secret").assertExists()
    composeTestRule.onNodeWithText("🔓 Reveal Secret").assertExists()
  }
}
