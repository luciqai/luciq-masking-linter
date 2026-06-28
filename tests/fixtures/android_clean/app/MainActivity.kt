class MainActivity {
    fun onCreate() {
        Luciq.setAutoMaskScreenshotsTypes(MaskingType.TEXT_INPUTS, MaskingType.LABELS)
        if (userHasConsented) {
            SessionReplay.enabled = true
        }
    }

    @Composable
    fun Profile(user: User) {
        Text(user.email, modifier = Modifier.luciqPrivate(isPrivate = true))
        val passwordField = EditText(context)
    }
}
