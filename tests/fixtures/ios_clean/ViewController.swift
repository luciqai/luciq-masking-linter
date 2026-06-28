import Luciq

class VC {
    func setup() {
        SessionReplay.autoMaskScreenshotOptions = [.textInputs, .labels]
        if userHasConsented {
            SessionReplay.enabled = true
        }
    }

    var body: some View {
        Text(user.email).luciqPrivate()
        SecureField("pwd", text: $pwd)
    }
}
