import Luciq

class VC {
    func setup() {
        NetworkLogger.autoMaskingEnabled = false
    }

    var body: some View {
        Text(user.email)
        SecureField("pwd", text: $pwd)
    }
}
