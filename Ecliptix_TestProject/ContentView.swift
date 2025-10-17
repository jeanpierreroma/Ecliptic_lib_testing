//
//  ContentView.swift
//  Ecliptix_TestProject
//
//  Created by Oleksandr Melnechenko on 15.10.2025.
//

import SwiftUI

struct ContentView: View {
    @State private var statusText: String = "Running…"
    @State private var statusLogText: String = "Running…"

    var body: some View {
        ScrollView {
            
            VStack(spacing: 50) {
                Text(statusText)
                    .font(.system(.body, design: .monospaced))
                    .padding()
                
                Text("-----------------------")
                
                Text(statusLogText)
                    .font(.system(.body, design: .monospaced))
                    .padding()
            }
            
        }
        .task {
            // 1) init
            do {
                try Ecliptix.initialize()
            } catch {
                statusText = "init failed → \(error)"
                return
            }

            // 2) публічний ключ
            var publicKeyBase64 = "n/a"
            do {
                let der = try Ecliptix.getPublicKeyDER()
                publicKeyBase64 = der.base64EncodedString()
            } catch {
                publicKeyBase64 = "error: \(error)"
            }

            // 3) encrypt
            let messageData = Data("hello from swift".utf8)
            var encryptInfo = "n/a"
            var ciphertext: Data?
            do {
                let ct = try Ecliptix.encryptRSAOAEP(plaintext: messageData)
                ciphertext = ct
                encryptInfo = "ciphertext length = \(ct.count) bytes"
            } catch {
                encryptInfo = "encrypt error: \(error)"
            }

            // 4) decrypt (може бути вимкнено у твоєму .a, якщо приватний ключ не вшитий)
            var decryptInfo = "skipped"
            if let ct = ciphertext {
                do {
                    let pt = try Ecliptix.decryptRSAOAEP(ciphertext: ct)
                    decryptInfo = (pt == messageData) ? "roundtrip OK" : "roundtrip FAIL"
                } catch {
                    decryptInfo = "decrypt error: \(error) (це очікувано, якщо приватного ключа немає)"
                }
            }

            // 5) cleanup
            Ecliptix.cleanup()

            statusText =
            """
            ✅ init OK
            • public key (DER, base64): \(publicKeyBase64.prefix(120))…
            • encrypt: \(encryptInfo)
            • decrypt: \(decryptInfo)
            """
        }
        .task { await runSmoke() }
    }
    
    @MainActor
    private func runSmoke() async {
        var lines: [String] = []
        func add(_ s: String) { lines.append(s); statusLogText = lines.joined(separator: "\n") }

        var clientHandle: OpaqueClientHandleRef?
        var clientState:  OpaqueClientStateRef?

        do {
            // state працює незалежно від ключа — перевіряємо базові ручки
            clientState = try OpaqueSmoke.createState();  add("✔︎ state created")

            if let serverKey = OpaqueSmoke.serverPublicKey() {
                clientHandle = try OpaqueSmoke.createClient(serverPublicKey: serverKey)
                add("✔︎ client created (server key OK)")

                let password = Data("pa$$w0rd".utf8)

                let regReq = try OpaqueSmoke.createRegistrationRequest(
                    clientHandle: clientHandle!, clientState: clientState!, password: password)
                add("• registration_request: capacity \(regReq.count) B; base64 \(regReq.prefix(96).base64EncodedString().prefix(120))…")

                let ke1 = try OpaqueSmoke.generateKE1(
                    clientHandle: clientHandle!, clientState: clientState!, password: password)
                add("• KE1: capacity \(ke1.count) B; base64 \(ke1.prefix(96).base64EncodedString().prefix(120))…")

                add("✅ OPAQUE smoke OK")
            } else {
                add("ℹ️ serverPublicKeyHex не заданий або має неправильну довжину (очікується 64 hex).")
                add("   Пропускаю кроки, що вимагають client_handle. State create/destroy перевірено.")
            }
        } catch {
            add("❌ \(error)")
        }

        OpaqueSmoke.destroyState(clientState)
        OpaqueSmoke.destroy(clientHandle)
    }
}

#Preview {
    ContentView()
}
