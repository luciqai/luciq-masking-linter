class MainActivity {
    fun onCreate() {
        Luciq.Builder(application, token)
            .ignoreFlagSecure(true)
            .build()
        Luciq.setNetworkAutoMaskingState(Feature.State.DISABLED)
    }

    @Composable
    fun Profile(user: User) {
        Text(user.email)
        Text(user.fiscalCode)
        val passwordField = EditText(context)
    }
}
