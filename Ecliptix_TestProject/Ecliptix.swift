//
//  Ecliptix.swift
//  Ecliptix_TestProject
//
//  Created by Oleksandr Melnechenko on 15.10.2025.
//

import Foundation

enum EcliptixClientSwiftError: Error, CustomStringConvertible {
    case nativeError(String)
    case invalidOutput(String)

    var description: String {
        switch self {
        case .nativeError(let message): return "Native error: \(message)"
        case .invalidOutput(let message): return "Invalid output: \(message)"
        }
    }
}

struct Ecliptix {
    @inline(__always)
    static func lastErrorString() -> String {
        guard let cString = ecliptix_client_get_error() else { return "unknown" }
        return String(cString: cString)
    }

    static func initialize() throws {
        let resultCode = ecliptix_client_init()
        guard resultCode == 0 else {
            throw EcliptixClientSwiftError.nativeError(lastErrorString())
        }
    }

    static func cleanup() {
        ecliptix_client_cleanup()
    }

    /// Дістає DER публічного ключа клієнта (зашитого з твого `CLIENT_PUBLIC_KEY_PEM`)
    /// Робить два проходи: якщо буфер замалий — перевиділяє за потрібною довжиною.
    static func getPublicKeyDER() throws -> Data {
        // Перший прохід із запасом
        var buffer = Data(count: 4096)
        var currentLength: size_t = size_t(buffer.count)

        var result = buffer.withUnsafeMutableBytes { outBuf -> Int32 in
            let outPtr = outBuf.bindMemory(to: UInt8.self).baseAddress
            return ecliptix_client_get_public_key(outPtr, &currentLength).rawValue
        }

        if result == 0 {
            // Успіх з першого разу
            return buffer.prefix(Int(currentLength))
        }

        // Якщо функція повернула "Buffer too small", ти у своїй імплементації
        // ставиш *public_key_len = der_len і повертаєш ECLIPTIX_ERROR_INVALID_PARAMS.
        // Обробимо це: беремо потрібну довжину і викликаємо ще раз.
        let neededLength = Int(currentLength)
        guard neededLength > 0 else {
            throw EcliptixClientSwiftError.nativeError(lastErrorString())
        }

        buffer = Data(count: neededLength)
        currentLength = size_t(neededLength)
        result = buffer.withUnsafeMutableBytes { outBuf -> Int32 in
            let outPtr = outBuf.bindMemory(to: UInt8.self).baseAddress
            return ecliptix_client_get_public_key(outPtr, &currentLength).rawValue
        }

        guard result == 0 else {
            throw EcliptixClientSwiftError.nativeError(lastErrorString())
        }
        return buffer.prefix(Int(currentLength))
    }

    /// RSA-OAEP: довжина шифртексту = розмір модуля (256B для RSA-2048, 512B для RSA-4096).
    /// Твоя функція очікує, що *ciphertext_len буде попередньо встановлено в capacity.
    static func encryptRSAOAEP(plaintext: Data, conservativeCapacity: Int = 1024) throws -> Data {
        var ciphertext = Data(count: conservativeCapacity) // запас під 4096-бітний ключ
        var ciphertextLength: size_t = size_t(ciphertext.count)

        let result = plaintext.withUnsafeBytes { inBuf -> Int32 in
            let inPtr = inBuf.bindMemory(to: UInt8.self).baseAddress
            return ciphertext.withUnsafeMutableBytes { outBuf -> Int32 in
                let outPtr = outBuf.bindMemory(to: UInt8.self).baseAddress
                return ecliptix_client_encrypt(inPtr, plaintext.count, outPtr, &ciphertextLength).rawValue
            }
        }

        guard result == 0 else {
            throw EcliptixClientSwiftError.nativeError(lastErrorString())
        }
        return ciphertext.prefix(Int(ciphertextLength))
    }

    /// Для RSA-OAEP розшифрований plaintext не довший за шифртекст → ставимо capacity = ciphertext.count.
    static func decryptRSAOAEP(ciphertext: Data) throws -> Data {
        var plaintext = Data(count: ciphertext.count)
        var plaintextLength: size_t = size_t(plaintext.count)

        let result = ciphertext.withUnsafeBytes { inBuf -> Int32 in
            let inPtr = inBuf.bindMemory(to: UInt8.self).baseAddress
            return plaintext.withUnsafeMutableBytes { outBuf -> Int32 in
                let outPtr = outBuf.bindMemory(to: UInt8.self).baseAddress
                return ecliptix_client_decrypt(inPtr, ciphertext.count, outPtr, &plaintextLength).rawValue
            }
        }

        guard result == 0 else {
            throw EcliptixClientSwiftError.nativeError(lastErrorString())
        }
        return plaintext.prefix(Int(plaintextLength))
    }
}
