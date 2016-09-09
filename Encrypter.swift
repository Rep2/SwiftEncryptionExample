import Security
import Foundation

enum EncryptionError: ErrorType {
    case EncryptionFailed(code: OSStatus)
    case DecryptionFailed(code: OSStatus)
    case TextDecodingFailed
}

class Encrypter {

    static let instance = Encrypter()

    private let publicKey: SecKey
    private let privateKey: SecKey

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

    func ecnrypt(message: String) throws -> NSData {
        let plainTextData = [UInt8](message.utf8)
        let plainTextDataLength = Int(plainTextData.count)

        var encryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var encryptedDataLength = blockSize

        let result = SecKeyEncrypt(publicKey, SecPadding(arrayLiteral: SecPadding.PKCS1), plainTextData, plainTextDataLength, &encryptedData, &encryptedDataLength)

        guard result == errSecSuccess else {
            throw EncryptionError.EncryptionFailed(code: result)
        }

        return NSData(bytes: encryptedData, length: encryptedDataLength)
    }

    func decrypt(encryptedData: [UInt8], encoding: NSStringEncoding = NSUTF8StringEncoding) throws -> String {
        var decryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var decryptedDataLength = blockSize

        let result = SecKeyDecrypt(privateKey, SecPadding(arrayLiteral: SecPadding.PKCS1), encryptedData, decryptedDataLength, &decryptedData, &decryptedDataLength)

        guard result == errSecSuccess else {
            throw EncryptionError.DecryptionFailed(code: result)
        }

        if let decryptedText = String(bytes: decryptedData, encoding: encoding) {
            return decryptedText
        } else {
            throw EncryptionError.TextDecodingFailed
        }
    }

}
