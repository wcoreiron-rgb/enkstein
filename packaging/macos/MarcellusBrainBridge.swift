import Foundation
import Network

private struct BridgeConfig {
    let port: NWEndpoint.Port
    let secret: String

    static func load() throws -> BridgeConfig {
        let arguments = CommandLine.arguments
        guard let portIndex = arguments.firstIndex(of: "--port"), portIndex + 1 < arguments.count,
              let rawPort = UInt16(arguments[portIndex + 1]),
              let port = NWEndpoint.Port(rawValue: rawPort),
              let secretIndex = arguments.firstIndex(of: "--secret-file"), secretIndex + 1 < arguments.count else {
            throw BridgeError.invalidConfiguration
        }
        let secretURL = URL(fileURLWithPath: arguments[secretIndex + 1])
        let secret = try String(contentsOf: secretURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard secret.count >= 32 else { throw BridgeError.invalidConfiguration }
        return BridgeConfig(port: port, secret: secret)
    }
}

private enum BridgeError: Error {
    case invalidConfiguration
    case invalidRequest
    case runtimeUnavailable(String)
    case invocationFailed(String)
}

private final class BrainBridge {
    private let config: BridgeConfig
    private let queue = DispatchQueue(label: "com.marcellus.brain-bridge", qos: .userInitiated, attributes: .concurrent)
    private var listener: NWListener?

    init(config: BridgeConfig) {
        self.config = config
    }

    func start() throws {
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        let listener = try NWListener(using: parameters, on: config.port)
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener.stateUpdateHandler = { state in
            if case .failed(let error) = state {
                FileHandle.standardError.write(Data("Brain Bridge failed: \(error)\n".utf8))
                exit(1)
            }
        }
        listener.start(queue: queue)
        self.listener = listener
        dispatchMain()
    }

    private func accept(_ connection: NWConnection) {
        guard isLocalPeer(connection.endpoint) else {
            send(connection, status: 403, body: ["detail": "Local access only"])
            return
        }
        connection.start(queue: queue)
        receive(connection, buffer: Data())
    }

    private func receive(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1_048_576) { [weak self] data, _, complete, error in
            guard let self else { return }
            var combined = buffer
            if let data { combined.append(data) }
            if let request = self.parseRequest(combined) {
                self.handle(connection, request: request)
            } else if error != nil || complete || combined.count > 1_048_576 {
                self.send(connection, status: 400, body: ["detail": "Invalid request"])
            } else {
                self.receive(connection, buffer: combined)
            }
        }
    }

    private func parseRequest(_ data: Data) -> (method: String, path: String, headers: [String: String], body: Data)? {
        let separator = Data("\r\n\r\n".utf8)
        guard let headerRange = data.range(of: separator),
              let headerText = String(data: data[..<headerRange.lowerBound], encoding: .utf8) else { return nil }
        let lines = headerText.components(separatedBy: "\r\n")
        let requestLine = lines.first?.split(separator: " ").map(String.init) ?? []
        guard requestLine.count >= 2 else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            let parts = line.split(separator: ":", maxSplits: 1).map(String.init)
            if parts.count == 2 {
                headers[parts[0].lowercased()] = parts[1].trimmingCharacters(in: .whitespaces)
            }
        }
        let length = Int(headers["content-length"] ?? "0") ?? 0
        guard length >= 0, length <= 1_048_576 else { return nil }
        let bodyStart = headerRange.upperBound
        guard bodyStart <= data.count, length <= data.count - bodyStart else { return nil }
        return (requestLine[0], requestLine[1], headers, data.subdata(in: bodyStart..<(bodyStart + length)))
    }

    private func handle(
        _ connection: NWConnection,
        request: (method: String, path: String, headers: [String: String], body: Data)
    ) {
        guard constantTimeEquals(request.headers["x-marcellus-bridge-token"] ?? "", config.secret) else {
            send(connection, status: 401, body: ["detail": "Unauthorized"])
            return
        }

        if request.method == "GET", request.path == "/v1/status" {
            queue.async { [weak self] in
                guard let self else { return }
                self.send(connection, status: 200, body: ["brains": self.status()])
            }
            return
        }

        if request.method == "POST", request.path == "/v1/invoke" {
            guard let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let brain = payload["brain"] as? String,
                  let prompt = payload["prompt"] as? String,
                  !prompt.isEmpty, prompt.count <= 24_000 else {
                send(connection, status: 400, body: ["detail": "Invalid invocation payload"])
                return
            }
            let model = payload["model"] as? String
            queue.async { [weak self] in
                guard let self else { return }
                do {
                    let result = try self.invoke(brain: brain, prompt: prompt, model: model)
                    self.send(connection, status: 200, body: result)
                } catch BridgeError.runtimeUnavailable(let detail) {
                    self.send(connection, status: 200, body: ["success": false, "detail": detail])
                } catch {
                    self.send(connection, status: 200, body: ["success": false, "detail": "Brain invocation failed"])
                }
            }
            return
        }

        send(connection, status: 404, body: ["detail": "Not found"])
    }

    private func status() -> [[String: Any]] {
        let codexPath = findExecutable("codex")
        let codexStatus = codexPath.flatMap { try? run($0, arguments: ["login", "status"], timeout: 12) }
        let codexAuthenticated = codexStatus?.output.contains("Logged in using ChatGPT") == true

        let claudePath = findExecutable("claude")
        let claudeStatus = claudePath.flatMap { try? run($0, arguments: ["auth", "status"], timeout: 12) }
        let claudeAuthenticated = claudeStatus.map { $0.code == 0 } ?? false

        return [
            [
                "brain": "codex_subscription",
                "kind": "subscription",
                "available": codexPath != nil,
                "authenticated": codexAuthenticated,
                "runtime": codexPath == nil ? NSNull() : "Codex CLI",
                "account_type": codexAuthenticated ? "ChatGPT subscription" : NSNull(),
                "detail": codexPath == nil ? "Install ChatGPT/Codex on this host." : (codexAuthenticated ? "Ready" : "Run codex login on this host."),
            ],
            [
                "brain": "claude_subscription",
                "kind": "subscription",
                "available": claudePath != nil,
                "authenticated": claudeAuthenticated,
                "runtime": claudePath == nil ? NSNull() : "Claude Agent SDK runtime",
                "account_type": claudeAuthenticated ? "Claude subscription" : NSNull(),
                "detail": claudePath == nil ? "Install Claude Code, then authenticate on this host." : (claudeAuthenticated ? "Ready" : "Run claude login on this host."),
            ],
        ]
    }

    private func invoke(brain: String, prompt: String, model: String?) throws -> [String: Any] {
        switch brain {
        case "codex_subscription":
            return try invokeCodex(prompt: prompt, model: model)
        case "claude_subscription":
            return try invokeClaude(prompt: prompt, model: model)
        default:
            throw BridgeError.invalidRequest
        }
    }

    private func invokeCodex(prompt: String, model: String?) throws -> [String: Any] {
        guard let executable = findExecutable("codex") else {
            throw BridgeError.runtimeUnavailable("Codex is not installed on this host.")
        }
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("marcellus-brain-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let output = work.appendingPathComponent("response.txt")
        var arguments = [
            "exec", "--ephemeral", "--skip-git-repo-check", "--ignore-user-config",
            "--sandbox", "read-only", "--color", "never", "-C", work.path,
            "-o", output.path,
        ]
        if let model, !model.isEmpty { arguments += ["--model", model] }
        arguments.append("-")
        let governedPrompt = """
        You are a reasoning-only Brain inside Marcellus. Do not call tools, inspect files, browse, or change any system. Do not claim actions were executed. Answer the supplied question concisely and identify uncertainty.

        QUESTION:
        \(prompt)
        """
        let started = Date()
        let result = try run(executable, arguments: arguments, input: governedPrompt, timeout: 180)
        guard result.code == 0,
              let response = try? String(contentsOf: output, encoding: .utf8),
              !response.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw BridgeError.invocationFailed("Codex did not return a response.")
        }
        return [
            "success": true,
            "provider": "openai_chatgpt_subscription",
            "model": model ?? "subscription-default",
            "response": response.trimmingCharacters(in: .whitespacesAndNewlines),
            "latency_ms": Int(Date().timeIntervalSince(started) * 1000),
        ]
    }

    private func invokeClaude(prompt: String, model: String?) throws -> [String: Any] {
        guard let executable = findExecutable("claude") else {
            throw BridgeError.runtimeUnavailable("Claude Agent SDK runtime is not installed on this host.")
        }
        var arguments = ["-p", "--output-format", "json", "--permission-mode", "dontAsk", "--tools", ""]
        if let model, !model.isEmpty { arguments += ["--model", model] }
        arguments.append(
            "You are a reasoning-only Brain inside Marcellus. Do not use tools or change systems. " +
            "Answer concisely and identify uncertainty.\n\nQUESTION:\n" + prompt
        )
        let started = Date()
        let result = try run(executable, arguments: arguments, timeout: 180)
        guard result.code == 0 else { throw BridgeError.invocationFailed("Claude invocation failed.") }
        let data = Data(result.output.utf8)
        let payload = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        let response = (payload?["result"] as? String) ?? result.output
        guard !response.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw BridgeError.invocationFailed("Claude returned no response.")
        }
        return [
            "success": true,
            "provider": "anthropic_claude_subscription",
            "model": model ?? "subscription-default",
            "response": response.trimmingCharacters(in: .whitespacesAndNewlines),
            "latency_ms": Int(Date().timeIntervalSince(started) * 1000),
        ]
    }

    private func run(
        _ executable: String,
        arguments: [String],
        input: String? = nil,
        timeout: TimeInterval
    ) throws -> (code: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = [
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "PATH": "/Applications/ChatGPT.app/Contents/Resources:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
        ]
        let captureURL = FileManager.default.temporaryDirectory.appendingPathComponent("marcellus-process-\(UUID().uuidString).log")
        FileManager.default.createFile(atPath: captureURL.path, contents: nil)
        guard let capture = try? FileHandle(forWritingTo: captureURL) else {
            throw BridgeError.invocationFailed("Could not prepare process output.")
        }
        defer {
            try? capture.close()
            try? FileManager.default.removeItem(at: captureURL)
        }
        let stdin = Pipe()
        process.standardOutput = capture
        process.standardError = capture
        if input != nil { process.standardInput = stdin }
        try process.run()
        if let input {
            stdin.fileHandleForWriting.write(Data(input.utf8))
            try? stdin.fileHandleForWriting.close()
        }
        let semaphore = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in semaphore.signal() }
        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            throw BridgeError.invocationFailed("Brain invocation timed out.")
        }
        try capture.synchronize()
        let data = (try? Data(contentsOf: captureURL)) ?? Data()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    private func findExecutable(_ name: String) -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let candidates: [String]
        if name == "codex" {
            candidates = [
                "/Applications/ChatGPT.app/Contents/Resources/codex",
                "/opt/homebrew/bin/codex", "/usr/local/bin/codex", "\(home)/.local/bin/codex",
            ]
        } else {
            candidates = ["/opt/homebrew/bin/claude", "/usr/local/bin/claude", "\(home)/.local/bin/claude"]
        }
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private func send(_ connection: NWConnection, status: Int, body: [String: Any]) {
        let data = (try? JSONSerialization.data(withJSONObject: body)) ?? Data("{}".utf8)
        let reason = status == 200 ? "OK" : status == 400 ? "Bad Request" : status == 401 ? "Unauthorized" : status == 403 ? "Forbidden" : "Not Found"
        let header = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(data.count)\r\nConnection: close\r\n\r\n"
        var response = Data(header.utf8)
        response.append(data)
        connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
    }

    private func isLocalPeer(_ endpoint: NWEndpoint) -> Bool {
        guard case .hostPort(let host, _) = endpoint else { return false }
        let value = "\(host)".lowercased()
        if value == "127.0.0.1" || value == "::1" || value.hasPrefix("10.") || value.hasPrefix("192.168.") {
            return true
        }
        let octets = value.split(separator: ".").compactMap { Int($0) }
        return octets.count == 4 && octets[0] == 172 && (16...31).contains(octets[1])
    }

    private func constantTimeEquals(_ left: String, _ right: String) -> Bool {
        let a = Array(left.utf8)
        let b = Array(right.utf8)
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }
}

private var activeBridge: BrainBridge?

do {
    activeBridge = BrainBridge(config: try BridgeConfig.load())
    try activeBridge?.start()
} catch {
    FileHandle.standardError.write(Data("Invalid Marcellus Brain Bridge configuration.\n".utf8))
    exit(2)
}
