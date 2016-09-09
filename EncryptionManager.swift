import Security
import Foundation

class EncryptionManager {
    let publicKey: SecKey
    let privateKey: SecKey

    private let blockSize: Int

    init() {
        var publicKey, privateKey: SecKey?

        SecKeyGeneratePair(NSDictionary(dictionary: [kSecAttrKeyType :  kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits : 1024]), &publicKey, &privateKey)

        if let publicKey = publicKey, let privateKey = privateKey {
            self.publicKey = publicKey
            self.privateKey = privateKey
        }

        blockSize = SecKeyGetBlockSize(self.publicKey)
    }
}
