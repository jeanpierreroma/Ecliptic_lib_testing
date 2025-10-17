//
//  Opaque_test.swift
//  Ecliptix_TestProject
//
//  Created by Oleksandr Melnechenko on 17.10.2025.
//

import SwiftUI

typealias OpaqueClientHandleRef = UnsafeMutableRawPointer
typealias OpaqueClientStateRef  = UnsafeMutableRawPointer

enum OpaqueClientSwiftError: Error, CustomStringConvertible {
    case nullPointer(String)
    case native(Int32, String)
    var description: String {
        switch self {
        case .nullPointer(let where_):        return "null pointer @ \(where_)"
        case .native(let code, let where_):   return "rc=\(code) @ \(where_)"
        }
    }
}

struct OpaqueSmoke {

    // 🔑 ВСТАВ СВІЙ 32-байтовий Ristretto255 pubkey у hex (без 0x, 64 hex-символи)
    // Якщо залишиш "", смоук пропустить кроки, що вимагають client_handle.
    private static let serverPublicKeyHex: String = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

    static func serverPublicKey() -> Data? {
        let s = serverPublicKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.count == 64 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard j <= s.endIndex, let b = UInt8(s[i..<j], radix: 16) else { return nil }
            bytes.append(b)
            i = j
        }
        return Data(bytes)
    }

    static func createClient(serverPublicKey: Data) throws -> OpaqueClientHandleRef {
        var handle: UnsafeMutableRawPointer?
        let rc: Int32 = serverPublicKey.withUnsafeBytes { keyBuf in
            opaque_client_create(
                keyBuf.bindMemory(to: UInt8.self).baseAddress, serverPublicKey.count, &handle
            )
        }
        guard rc == 0, let h = handle else { throw OpaqueClientSwiftError.native(rc, "opaque_client_create") }
        return h
    }

    static func createState() throws -> OpaqueClientStateRef {
        var handle: UnsafeMutableRawPointer?
        let rc: Int32 = opaque_client_state_create(&handle)
        guard rc == 0, let h = handle else { throw OpaqueClientSwiftError.native(rc, "opaque_client_state_create") }
        return h
    }

    static func destroy(_ handle: OpaqueClientHandleRef?) { if let h = handle { opaque_client_destroy(h) } }
    static func destroyState(_ state: OpaqueClientStateRef?) { if let s = state { opaque_client_state_destroy(s) } }

    // У твоєму C-API функції приймають просто capacity (не in/out довжину),
    // тож даємо “із запасом”, а логувати будемо префікс.
    static func createRegistrationRequest(clientHandle: OpaqueClientHandleRef,
                                          clientState: OpaqueClientStateRef,
                                          password: Data) throws -> Data {
        var out = Data(count: 256)                // >= REGISTRATION_REQUEST_LENGTH
        let capacity = out.count                  // <— зняли значення ДО мутації

        let rc: Int32 = out.withUnsafeMutableBytes { outBytes -> Int32 in
            guard let outPtr = outBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return password.withUnsafeBytes { pwBytes -> Int32 in
                let pwPtr = pwBytes.bindMemory(to: UInt8.self).baseAddress
                return opaque_client_create_registration_request(
                    clientHandle,
                    pwPtr, password.count,
                    clientState,
                    outPtr, capacity          // <— використовуємо локальний capacity
                )
            }
        }
        guard rc == 0 else { throw OpaqueClientSwiftError.native(rc, "create_registration_request") }
        return out
    }

    static func generateKE1(clientHandle: OpaqueClientHandleRef,
                            clientState: OpaqueClientStateRef,
                            password: Data) throws -> Data {
        var out = Data(count: 128)                // >= KE1_LENGTH (≈96)
        let capacity = out.count                  // <— зняли значення ДО мутації

        let rc: Int32 = out.withUnsafeMutableBytes { outBytes -> Int32 in
            guard let outPtr = outBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return password.withUnsafeBytes { pwBytes -> Int32 in
                let pwPtr = pwBytes.bindMemory(to: UInt8.self).baseAddress
                return opaque_client_generate_ke1(
                    clientHandle,
                    pwPtr, password.count,
                    clientState,
                    outPtr, capacity            // <— використовуємо локальний capacity
                )
            }
        }
        guard rc == 0 else { throw OpaqueClientSwiftError.native(rc, "generate_ke1") }
        return out
    }
}
