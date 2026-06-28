class Pay {
    fun onCreate() {
        Luciq.setAutoMaskScreenshotsTypes(MaskingType.TEXT_INPUTS)
    }

    @Composable
    fun Card(user: User) {
        Text(user.cardNumber) // luciq-ignore: rendered already masked upstream
    }
}
