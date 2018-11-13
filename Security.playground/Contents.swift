/**
 - Author:
 Rodrigo Morbach
 */

import UIKit

let b64StringKey = """
MIIEowIBAAKCAQEAo81+4NLKXyrWs9k853t+9kK0u0i8owHO7FRd1SJXCyFDRpcy823YHRydxn84NLkLVOASGiILJb5FpeZ3HzNhzohDy//MJcTwp00KQSiXPgOtMoZbEBzIu7RlSWyroxHTwIbyTAPaGaqV8j3EGYWahfubUlHL/lPMJk/eEHj3E/+1+oGaJ5IpIEG9HzrjcEyYjXAPyfc9jWFFMf4V37GaD8+krbp+pIcNCXgViaIXI4l9MuQjAp1OYbKA32h+UhTSXZsmp0ZWlGy/LhSK3VLt5cNUzXYHpPQyke1kb1vyLcZLAbKlqfrz4k84YOdZNJdp399x79B+S2o/Z6+1IjAwIwIDAQABAoIBAA29zTfBumqkad5f/ZBMl5726dMb6+Z5RHYmZIUr4p7gG5UEiMIyKolt33CJ0KaS1XgGOigi4TBTF32ugu5e1zgsmnkDjKLbtCkDOTaBJLr2ADKD+4fmmkWUGyElpcdCCIBKWD5EEajKJ9a3RsgYIX/wiejfss8zRKX8JXY+559jCs23Vyrtd0sTOhZ5FPX2N/SiMvUuNviDLOUGZ00xOdkz9gI5Aorlc7VFwR/Ef3Gz95Vw9ewLl5QuoGUZ0X3CCyj6tTOewzkpUYRtDAoLHmB2nJpEop9yK7FFb7U4CNOJuTXV/YyUIBR+BaPmV5skUvH/MFkRUPzak+eHaULXfmkCgYEA1yHQdA7l1mexjrqj9aMKnQBfyzmPV7mcLBftweh+S9RC10U/wOEaQMD5wXL6eJhvdK+Vcd2zvOeHDqtNbG2aSPeUZpGVPYisA0USg4rJgaWa5wdA1uWZAysBhD7rsr6QXGAtJGcoV4Z9TLK5UKMxWB2ezgnAlXXmW7I+SX/TVTkCgYEAwut1pqxEiF+0pYjGd+k0uaqRcHXPai1jVWRReS8Ob1emhfsbMMKjaWtCY0WQ8nbYnf/HNWlTuze7qH2Gqfbm8JKBS9yR1oGExonbjOTmppvxo7IGh6Kmd4DVHdmvPbevHFgN0vsfBK/7opbNHdH2PmOBCPwdvHhQ2n0qfuxD7DsCgYBRg354eyybEK82ZYG6kQx0cK/bUPP/SVTjYC22S2GPWd35s0N00dYgsv3vTqGZECkrDVySyG5SJWgHJuEvNFhBTY3tTzw9FIwYsRNSxEOV3CnVX+oxgs13ZdQtR6oHEC2i0s5H/M5MW6keZpnQ9AS+XnrNluRhvUqLc/4l20k4AQKBgH0kZtinaSiVKYnNkn6R/wPk+pNVT+E/WrMMQTKof4AEqikC2qYnkHqyHmFV3IWOv+xQtzkXcmaUlarLTJX6qrJxnQlzhz5M0U4WXBrNKzh0jmMmfQK/7lhzImCTzeq173snHVkDWRrNUaVFZFNs5ceQYtu94emK5X4hNhNe5QzZAoGBAJfQcjsgTQnUtNAc89xTpDmlMaafAy8QIZC0JDosmRYB1TQt3jUBK+Q9L2frO1bDmJ9wR2ssnrMQMTRSFp7UV+LGG4R5U2AkfBWOUceCPWaRjYgkOwzAOkHJ2Byg0JetmkCIFeri2o5rrfbMJWIpD+XjCN0ZI1vy9enMEPAoA0lp
"""

let privateKey = RSA.createPrivateKeyFromBase64(b64StringKey)


if let generatedKeyData = RSA.generateSecureRandomData() {
    print(generatedKeyData.base64EncodedString())
}

// RSA.createAssimetricKeyPair()

if let publicKey = RSA.calculatePublicKey(from: privateKey!) {
    if let encryptedData = RSA.encrypt(data: "Data to be encrypted", with: publicKey) {
        if let result = RSA.decrypt(data: encryptedData, with: privateKey!) {
            debugPrint(String(data: result, encoding: String.Encoding.utf8)!)
        }
    }
} else {
    debugPrint("Failed calculating the public key from private one")
}

if let publicKey = RSA.calculatePublicKey(from: privateKey!) {

    let encryptedBytes = RSA.secKeyEncrypt("Data to be encrypted", publicKey: publicKey)
    print("Encrypted String: \(encryptedBytes.base64EncodedString())")

    if let result = RSA.secKeyDecrypt(encryptedBytes, privateKey: privateKey!) {
        print(result)
    }
}

let dataToBeSigned = "Data to be signed".data(using: .utf8)
let key = RSA.generateSecureRandomData()
if let result = RSA.signData(key!, with: privateKey!) {
    print(result)
}

if let rawDataSignature = RSA.signRawData(dataToBeSigned!, with: privateKey!) {
    print(rawDataSignature.count)
}
