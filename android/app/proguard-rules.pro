# Keep kotlinx.serialization runtime & generated serializers intact
-keepattributes *Annotation*, InnerClasses, Signature
-keep,includedescriptorclasses class com.burnbin.app.**$$serializer { *; }
-keepclassmembers class com.burnbin.app.** {
    *** Companion;
}
-keepclasseswithmembers class com.burnbin.app.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-dontwarn kotlinx.serialization.**

# ZXing & JourneyApps scanner views/activities
-keep class com.journeyapps.barcodescanner.** { *; }
-keep class com.google.zxing.** { *; }
-dontwarn com.google.zxing.**

# Biometric prompt callbacks
-keepclassmembers class * extends androidx.biometric.BiometricPrompt$AuthenticationCallback {
    *;
}
