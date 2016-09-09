import Security
import Foundation

class Decrypter {

    static func decrypt(encryptedData: [UInt8], privateKey: SecKey, encoding: NSStringEncoding = NSUTF8StringEncoding) throws -> String {
        let blockSize = SecKeyGetBlockSize(privateKey)

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
