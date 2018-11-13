import Foundation
import Security

// Methods are based on https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html#//apple_ref/doc/uid/TP40011172
public struct RSA {
    
    /**
     
     Many encryption algorithms rely on cryptographically strong pseudorandom numbers.
     - returns:
     Generate random data
     - Reference:
     [SecRandomCopyBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes)
     
     */
    public static func generateSecureRandomData() -> Data? {
        
        var bts = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bts.count, &bts)
        if status == errSecSuccess {
            print(bts)
            let dt = Data(bytes: bts)
            return dt
        }
        return nil
    }
    
    
    /**
     
     Create an external representation of a key for transmission.
     
     - parameters:
     - key: Public or Private key
     - returns:
     Base64 representaion of the given key
     - Reference:
     [Storing Keys as Data](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_as_data)
     */
    private static func convertKeyToBase64String(key: SecKey) -> String? {
        
        var error: Unmanaged<CFError>?
        if let cfData = SecKeyCopyExternalRepresentation(key, &error) {
            let data: Data = cfData as Data
            let b64Key = data.base64EncodedString()
            return b64Key
        }
        
        return nil
    }
    
    /**
     Create an assimetric ley pair, but does not store the private one in the keychain.
     
     - returns:
     Generated Private Key
     - Reference:
     [Generate Keys](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys#2863927)
     */
    public static func createAssimetricKeyPair() -> SecKey? {
        
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA as String,
                                         kSecAttrKeySizeInBits as String: 2048,
                                         kSecPrivateKeyAttrs as String:
                                            [kSecAttrIsPermanent as String: false,
                                             kSecAttrCanEncrypt as String: true,
                                             kSecAttrCanDecrypt as String: true,
                                             kSecAttrCanSign as String: true
            ]];
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let err = error!.takeRetainedValue() as Error
            debugPrint(err)
            return nil
        }
        
        return privateKey
    }
    
    /**
     
     Restores a key from an external representation of that key.
     
     - parameters:
     - base64String: Base64 encoded representation of a private key
     - returns:
     Private key
     - Reference:
     [SecKeyCreateWithData](https://developer.apple.com/documentation/security/1643701-seckeycreatewithdata)
     */
    public static func createPrivateKeyFromBase64(_ base64String: String) -> SecKey? {
        
        let attributes: [String: Any] = [
            kSecAttrType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ];
        
        if let cfData = Data(base64Encoded: base64String.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)) {
            var error: Unmanaged<CFError>?
            guard let generatedKey = SecKeyCreateWithData(cfData as CFData, attributes as CFDictionary, &error) else {
                let err = error!.takeRetainedValue() as Error
                debugPrint(err)
                return nil
            }
            return generatedKey
        } else {
            debugPrint("Could not convert base64 encodedString to Data")
        }
        
        return nil
    }
    
    
    
    /**
     
     Encrypts a block of plaintext.
     
     - parameters:
     - data: Raw data to be encrypted
     - publicKey: Public key encrypt the data
     - returns:
     Encrypt data
     - Reference:
     [SecKeyEncrypt](https://developer.apple.com/documentation/security/1617956-seckeyencrypt)
     */
    public static func secKeyEncrypt(_ data: String, publicKey: SecKey) -> Data {
        
        var cipherLen = SecKeyGetBlockSize(publicKey)
        var cipherText = [UInt8](repeating: 0, count: cipherLen)
        let plainText = [UInt8](data.utf8)
        let plainTextDataLength = Int(plainText.count)
        
        let status = SecKeyEncrypt(publicKey, SecPadding.init(rawValue: 0), plainText, plainTextDataLength, &cipherText, &cipherLen)
        
        if status != errSecSuccess {
            debugPrint("Failed encrypting data \(status)")
        }
        
        return Data(bytes: cipherText)
    }
    
    /**
     
     Decrypts a block of ciphertext
     
     - parameters:
     - data: Raw data to be decrypted
     - privateKey: Private key decrypt the data
     - returns:
     Plain text     
     - Reference:
     [SecKeyDecrypt](https://developer.apple.com/documentation/security/1617894-seckeydecrypt)
     */
    public static func secKeyDecrypt(_ data: Data, privateKey: SecKey) -> String? {
        
        var plainTextLen = SecKeyGetBlockSize(privateKey)
        var plainText = [UInt8](repeating: 0, count: plainTextLen)
        let dataBytes = [UInt8](data)
        
        let status = SecKeyDecrypt(privateKey, SecPadding.init(rawValue: 0), dataBytes, dataBytes.count, &plainText, &plainTextLen)
        
        if status == errSecSuccess {
            print(plainText)
            return String(bytes: plainText, encoding: String.Encoding.utf8)
        } else {
            debugPrint("Failed decrypting data \(status)")
            return nil
        }
    }
    /**
     
     Encrypt data with a given key.
     - parameters:
     - data: Raw data to be encrypted
     - with: Public key encrypt the data
     - returns:
     Encrypted data
     - Reference:
     [SecKeyCreateEncryptedData](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_as_data)
     */
    public static func encrypt(data toBeEncrypted: String, with publicKey: SecKey) -> Data? {
        
        let size = SecKeyGetBlockSize(publicKey)
        debugPrint(size)
        
        let algorithm = SecKeyAlgorithm.rsaEncryptionPKCS1
        
        guard SecKeyIsAlgorithmSupported(publicKey, SecKeyOperationType.encrypt, algorithm) else {
            debugPrint("Algorithm not supported")
            return nil
        }
        
        guard let dt = toBeEncrypted.data(using: .utf8) else {
            debugPrint("Could not create data")
            return nil
        }
        
        var error: Unmanaged<CFError>?
        //This function first create a symmetric key using AES, then encrypt the data using this key, then encrypt the key using RSA public key provided, and, at last, and assemble a block of data composed by (RSA encrypted session key (AES) + the AES encrypted data + 16-byte AES-GCM tag)
        guard let result = SecKeyCreateEncryptedData(publicKey, algorithm, dt as CFData, &error) else {
            let err = error!.takeRetainedValue() as Error
            debugPrint(err)
            return nil
        }
        
        let encryptedData = result as Data
        return encryptedData
    }
    
    /**
     
     Decrypt data with a given key.
     - parameters:
     - data: Encrypted data generated from SecKeyCreateEncryptedData
     - with: Private key to decrypt the data
     - returns:
     Decrypted data
     - Reference:
     [SecKeyCreateDecryptedData](https://developer.apple.com/documentation/security/1644043-seckeycreatedecrypteddata)
     */
    public static func decrypt(data encryptedData: Data, with privateKey: SecKey) -> Data? {
        
        let algorithm = SecKeyAlgorithm.rsaEncryptionPKCS1
        
        guard SecKeyIsAlgorithmSupported(privateKey, SecKeyOperationType.decrypt, algorithm) else {
            debugPrint("Algorithm not supported")
            return nil
        }
        
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateDecryptedData(privateKey, algorithm, encryptedData as CFData, &error) else {
            let err = error!.takeRetainedValue() as Error
            debugPrint(err)
            return nil
        }
        
        let dt = result as Data
        return dt
    }
    
    /**
     
     Creates the cryptographic signature for a block of data using a private key and specified algorithm.
     - parameters:
     - data: Block of data to be signed
     - with: Private key to sign the block
     - returns:
     Base 64 encoded string of the signature.
     - Reference:
     [SecKeyCreateSignature](https://developer.apple.com/documentation/security/1643916-seckeycreatesignature)
     */
    public static func signData(_ data: Data, with privateKey: SecKey) -> String? {
        
        let algorithm = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA1
        
        guard SecKeyIsAlgorithmSupported(privateKey, SecKeyOperationType.sign, algorithm) else {
            debugPrint("Algorithm not supported")
            return nil
        }
        
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
            let err = error!.takeRetainedValue() as Error
            debugPrint(err)
            return nil
        }
        
        let dt = result as Data
        return dt.base64EncodedString()
    }
    
    
    /**
     
     Creates the cryptographic signature for a block of data using a private key. This method does not apply any hashing to the data before signing-it
     - parameters:
     - data: Block of data to be signed
     - with: Private key to sign the block
     - returns:
     Signature data
     - Reference:
     [SecKeyRawSign](https://developer.apple.com/documentation/security/1618025-seckeyrawsign)
     */
    public static func signRawData(_ data: Data, with privateKey: SecKey) -> Data? {
        
        var signature = [UInt8](repeating: 0, count: SecKeyGetBlockSize(privateKey))
        let dataToSign = [UInt8](data)
        var signatureLen = SecKeyGetBlockSize(privateKey)
        
        let status = SecKeyRawSign(privateKey, SecPadding.PKCS1SHA1, dataToSign, data.count, &signature, &signatureLen)
        if status == errSecSuccess {
            let dt = Data(bytes: dataToSign)
            return dt
        } else {
            print("failed signing")
        }
        return nil
    }
    
    /**
     
     Verifies a digital signature created with SecKeyRawSign
     - parameters:
     - data: Signed data
     - signature: Generated signature
     - with: Public key to sign the block
     - returns:
     Base 64 encoded string of the signature.
     - Reference:
     [SecKeyRawVerify](https://developer.apple.com/documentation/security/1617884-seckeyrawverify)
     */
    public static func verifyRawSignData(_ data: Data, signature: Data, with publicKey: SecKey) -> Data? {
        
        let signedData = [UInt8](data)
        let signatureData = [UInt8](signature)        
        let result = SecKeyRawVerify(publicKey, SecPadding.PKCS1SHA1, signedData, signedData.count, signatureData, signatureData.count)
        print("Verify result \(result)")
        
        return nil
    }
    
    /**
     
     Gets the public key associated with the given private key.
     - parameters:
     - from: Private key to calculate the public one
     - returns:
     The public key corresponding to the given private key.
     - Reference:
     [SecKeyCopyPublicKey](https://developer.apple.com/documentation/security/1643774-seckeycopypublickey)
     */
    public static func calculatePublicKey(from privateKey: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(privateKey)
    }
    
}
