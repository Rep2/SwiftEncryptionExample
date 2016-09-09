import Security
import Foundation

enum EncryptionError: ErrorType {
    case EncryptionFailed(code: OSStatus)
    case DecryptionFailed(code: OSStatus)
    case TextDecodingFailed
}

class Encrypter {

    func ecnrypt(message: String, publicKey: SecKey) throws -> NSData {
        let blockSize = SecKeyGetBlockSize(publicKey)

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

}
