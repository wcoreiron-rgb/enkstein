import Foundation
import Network
import AppKit
import ApplicationServices

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

private final class BrowserSessionBroker {
    private let condition = NSCondition()
    private var pairingCodes: [String: Date] = [:]
    private var queuedTasks: [[String: Any]] = []
    private var pendingTaskIDs: Set<String> = []
    private var completedTasks: [String: [String: Any]] = [:]
    private var providers: Set<String> = []
    private var lastSeen: Date?
    private var token: String
    private let tokenURL: URL

    init() {
        let directory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Marcellus", isDirectory: true)
        tokenURL = directory.appendingPathComponent("browser-bridge.token")
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if let existing = try? String(contentsOf: tokenURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), existing.count >= 48 {
            token = existing
        } else {
            token = Self.newToken()
            persistToken()
        }
    }

    func createPairingCode() -> String {
        condition.lock()
        defer { condition.unlock() }
        let now = Date()
        pairingCodes = pairingCodes.filter { $0.value > now }
        let code = UUID().uuidString.lowercased()
        pairingCodes[code] = now.addingTimeInterval(300)
        return code
    }

    func exchange(code: String) -> String? {
        condition.lock()
        defer { condition.unlock() }
        guard let expiry = pairingCodes.removeValue(forKey: code), expiry > Date() else { return nil }
        token = Self.newToken()
        persistToken()
        return token
    }

    func validate(candidate: String) -> Bool {
        let left = Array(candidate.utf8)
        let right = Array(token.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }

    func poll(availableProviders: [String]) -> [String: Any]? {
        condition.lock()
        defer { condition.unlock() }
        providers = Set(availableProviders.filter { ["chatgpt", "claude", "gemini"].contains($0) })
        lastSeen = Date()
        guard let index = queuedTasks.firstIndex(where: { task in
            guard let brain = task["brain"] as? String else { return false }
            return providers.contains(Self.provider(for: brain))
        }) else { return nil }
        return queuedTasks.remove(at: index)
    }

    func complete(taskID: String, success: Bool, response: String?, detail: String?) {
        condition.lock()
        defer { condition.unlock() }
        guard pendingTaskIDs.contains(taskID) else { return }
        completedTasks[taskID] = [
            "success": success,
            "response": response?.prefix(120_000).description ?? "",
            "detail": detail?.prefix(500).description ?? "",
        ]
        condition.broadcast()
    }

    func invoke(brain: String, prompt: String, sessionID: String?, timeout: TimeInterval) throws -> [String: Any] {
        let provider = Self.provider(for: brain)
        condition.lock()
        let live = lastSeen.map { Date().timeIntervalSince($0) < 15 && providers.contains(provider) } ?? false
        guard live else {
            condition.unlock()
            throw BridgeError.runtimeUnavailable(
                "The Enkstein browser companion is not connected to a signed-in \(provider.capitalized) tab."
            )
        }
        let taskID = UUID().uuidString.lowercased()
        pendingTaskIDs.insert(taskID)
        var task: [String: Any] = [
            "task_id": taskID,
            "brain": brain,
            "provider": provider,
            "prompt": prompt,
        ]
        if let sessionID { task["session_id"] = sessionID }
        queuedTasks.append(task)
        condition.broadcast()
        let deadline = Date().addingTimeInterval(timeout)
        while completedTasks[taskID] == nil && condition.wait(until: deadline) && Date() < deadline {}
        let result = completedTasks.removeValue(forKey: taskID)
        pendingTaskIDs.remove(taskID)
        queuedTasks.removeAll { ($0["task_id"] as? String) == taskID }
        condition.unlock()
        guard let result else { throw BridgeError.invocationFailed("Browser session invocation timed out.") }
        return result
    }

    func status(brain: String, label: String) -> [String: Any] {
        condition.lock()
        defer { condition.unlock() }
        let provider = Self.provider(for: brain)
        let connected = lastSeen.map { Date().timeIntervalSince($0) < 15 && providers.contains(provider) } ?? false
        return [
            "brain": brain,
            "kind": "browser_session",
            "available": connected,
            "authenticated": connected,
            "runtime": connected ? "Enkstein browser companion" : NSNull(),
            "account_type": connected ? "User-managed browser session" : NSNull(),
            "models": [],
            "supports_custom_model": false,
            "detail": connected
                ? "Ready through a visible signed-in \(label) browser tab."
                : "Install and pair the Enkstein browser companion, then sign in to \(label).",
        ]
    }

    private static func provider(for brain: String) -> String {
        if brain.hasPrefix("chatgpt_") { return "chatgpt" }
        if brain.hasPrefix("claude_") { return "claude" }
        return "gemini"
    }

    private static func newToken() -> String {
        UUID().uuidString.replacingOccurrences(of: "-", with: "")
            + UUID().uuidString.replacingOccurrences(of: "-", with: "")
    }

    private func persistToken() {
        try? Data(token.utf8).write(to: tokenURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenURL.path)
    }
}

private final class BrainBridge {
    private let config: BridgeConfig
    private let queue = DispatchQueue(label: "com.marcellus.brain-bridge", qos: .userInitiated, attributes: .concurrent)
    private let desktopInvocationLock = NSLock()
    private let browserBroker = BrowserSessionBroker()
    private var listener: NWListener?
    private let allowedExtensions = Set([
        "bash", "c", "cfg", "conf", "cpp", "cs", "css", "csv", "go", "h", "hpp", "html", "ini",
        "java", "js", "json", "jsx", "kt", "kts", "log", "md", "mjs", "ps1", "py", "rb", "rs",
        "sh", "sql", "tf", "tfvars", "toml", "ts", "tsx", "txt", "xml", "yaml", "yml",
    ])

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
        if request.method == "GET", request.path.hasPrefix("/v1/browser/setup") {
            let html = """
            <!doctype html><html><head><meta charset="utf-8"><title>Enkstein Browser Pairing</title></head>
            <body style="font:16px system-ui;padding:40px;max-width:640px;margin:auto">
            <h1>Pairing Enkstein</h1><p id="status">Waiting for the Enkstein browser companion…</p>
            </body></html>
            """
            sendHTML(connection, status: 200, html: html)
            return
        }

        if request.method == "POST", request.path == "/v1/browser/exchange" {
            guard let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let code = payload["code"] as? String,
                  let token = browserBroker.exchange(code: code) else {
                send(connection, status: 401, body: ["detail": "Pairing code is invalid or expired"])
                return
            }
            send(connection, status: 200, body: ["token": token])
            return
        }

        if request.method == "POST", request.path == "/v1/browser/poll" {
            guard browserBroker.validate(candidate: request.headers["x-marcellus-browser-token"] ?? ""),
                  let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any] else {
                send(connection, status: 401, body: ["detail": "Browser companion is not paired"])
                return
            }
            let providers = payload["providers"] as? [String] ?? []
            send(connection, status: 200, body: ["task": browserBroker.poll(availableProviders: providers) ?? NSNull()])
            return
        }

        if request.method == "POST", request.path == "/v1/browser/complete" {
            guard browserBroker.validate(candidate: request.headers["x-marcellus-browser-token"] ?? ""),
                  let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let taskID = payload["task_id"] as? String else {
                send(connection, status: 401, body: ["detail": "Browser companion is not paired"])
                return
            }
            browserBroker.complete(
                taskID: taskID,
                success: payload["success"] as? Bool ?? false,
                response: payload["response"] as? String,
                detail: payload["detail"] as? String
            )
            send(connection, status: 200, body: ["accepted": true])
            return
        }

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
                  !prompt.isEmpty, prompt.count <= 128_000 else {
                send(connection, status: 400, body: ["detail": "Invalid invocation payload"])
                return
            }
            let model = payload["model"] as? String
            let sessionID = payload["session_id"] as? String
            if let sessionID,
               sessionID.range(of: "^[a-f0-9]{64}$", options: .regularExpression) == nil {
                send(connection, status: 400, body: ["detail": "Invalid session identifier"])
                return
            }
            queue.async { [weak self] in
                guard let self else { return }
                do {
                    let result = try self.invoke(brain: brain, prompt: prompt, model: model, sessionID: sessionID)
                    self.send(connection, status: 200, body: result)
                } catch BridgeError.runtimeUnavailable(let detail) {
                    self.send(connection, status: 200, body: ["success": false, "detail": detail])
                } catch BridgeError.invocationFailed(let detail) {
                    self.send(connection, status: 200, body: ["success": false, "detail": detail])
                } catch {
                    self.send(connection, status: 200, body: ["success": false, "detail": "Brain invocation failed"])
                }
            }
            return
        }

        if request.method == "POST", request.path == "/v1/accessibility/request" {
            queue.async { [weak self] in
                guard let self else { return }
                let granted = self.accessibilityTrusted(prompt: true)
                self.send(connection, status: 200, body: [
                    "granted": granted,
                    "detail": granted
                        ? "Desktop Brain access is ready."
                        : "Allow Enkstein in System Settings > Privacy & Security > Accessibility, then refresh.",
                ])
            }
            return
        }

        if request.method == "POST", request.path == "/v1/browser/pair" {
            let code = browserBroker.createPairingCode()
            let setupURL = "http://127.0.0.1:\(config.port.rawValue)/v1/browser/setup?code=\(code)"
            let opened = (try? run("/usr/bin/open", arguments: [setupURL], timeout: 15).code) == 0
            send(connection, status: 200, body: [
                "setup_url": setupURL,
                "opened": opened,
                "expires_in_seconds": 300,
            ])
            return
        }

        if request.method == "POST", request.path == "/v1/browser/open-extension" {
            let extensionURL = URL(fileURLWithPath: CommandLine.arguments[0])
                .deletingLastPathComponent()
                .appendingPathComponent("browser-extension", isDirectory: true)
            guard FileManager.default.fileExists(atPath: extensionURL.path) else {
                send(connection, status: 400, body: ["opened": false, "detail": "Browser companion files are missing"])
                return
            }
            do {
                let result = try run("/usr/bin/open", arguments: [extensionURL.path], timeout: 15)
                send(connection, status: result.code == 0 ? 200 : 400, body: ["opened": result.code == 0])
            } catch {
                send(connection, status: 400, body: ["opened": false, "detail": "Browser companion folder could not be opened"])
            }
            return
        }

        if request.method == "POST", request.path.hasPrefix("/v1/workspace/") {
            guard let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let token = payload["token"] as? String else {
                send(connection, status: 400, body: ["detail": "Invalid workspace payload"])
                return
            }
            queue.async { [weak self] in
                guard let self else { return }
                do {
                    let body: [String: Any]
                    switch request.path {
                    case "/v1/workspace/list":
                        body = try self.listWorkspace(token: token)
                    case "/v1/workspace/write":
                        guard let path = payload["path"] as? String,
                              let content = payload["content"] as? String else { throw BridgeError.invalidRequest }
                        body = try self.writeWorkspace(token: token, path: path, content: content)
                    case "/v1/workspace/trash":
                        guard let path = payload["path"] as? String else { throw BridgeError.invalidRequest }
                        body = try self.trashWorkspace(token: token, path: path)
                    default:
                        self.send(connection, status: 404, body: ["detail": "Not found"])
                        return
                    }
                    self.send(connection, status: 200, body: body)
                } catch {
                    self.send(connection, status: 400, body: ["detail": "Workspace operation rejected"])
                }
            }
            return
        }

        send(connection, status: 404, body: ["detail": "Not found"])
    }

    private func workspaceRegistry() throws -> [String: [String: String]] {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Marcellus/workspace-roots.json")
        let data = try Data(contentsOf: url)
        guard let roots = try JSONSerialization.jsonObject(with: data) as? [String: [String: String]] else {
            throw BridgeError.invalidRequest
        }
        return roots
    }

    private func workspaceRoot(token: String) throws -> URL {
        guard token.range(of: "^[a-f0-9-]{36}$", options: .regularExpression) != nil,
              let path = try workspaceRegistry()[token]?["path"] else { throw BridgeError.invalidRequest }
        let root = URL(fileURLWithPath: path, isDirectory: true).resolvingSymlinksInPath().standardizedFileURL
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw BridgeError.invalidRequest
        }
        return root
    }

    private func safeWorkspaceURL(root: URL, relativePath: String, allowMissingLeaf: Bool = false) throws -> URL {
        let normalized = relativePath.replacingOccurrences(of: "\\", with: "/")
        let parts = normalized.split(separator: "/").map(String.init)
        let blocked = Set([".git", ".secrets", "node_modules", ".marcellus-trash"])
        guard !parts.isEmpty, !parts.contains(".."), !parts.contains("."), parts.allSatisfy({ !blocked.contains($0) }) else {
            throw BridgeError.invalidRequest
        }
        let candidate = parts.reduce(root) { $0.appendingPathComponent($1) }.standardizedFileURL
        guard candidate.path.hasPrefix(root.path + "/") else { throw BridgeError.invalidRequest }
        var cursor = root
        for part in parts {
            cursor.appendPathComponent(part)
            if allowMissingLeaf && !FileManager.default.fileExists(atPath: cursor.path) { break }
            let values = try cursor.resourceValues(forKeys: [.isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { throw BridgeError.invalidRequest }
        }
        return candidate
    }

    private func listWorkspace(token: String) throws -> [String: Any] {
        let root = try workspaceRoot(token: token)
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]
        guard let enumerator = FileManager.default.enumerator(
            at: root, includingPropertiesForKeys: Array(keys),
            options: [.skipsHiddenFiles, .skipsPackageDescendants],
            errorHandler: { _, _ in true }
        ) else { throw BridgeError.invalidRequest }
        var files: [[String: Any]] = []
        var totalBytes = 0
        for case let url as URL in enumerator {
            let relative = String(url.path.dropFirst(root.path.count + 1))
            let parts = relative.split(separator: "/").map(String.init)
            if parts.contains(where: { [".git", ".secrets", "node_modules", ".marcellus-trash"].contains($0) }) {
                enumerator.skipDescendants()
                continue
            }
            let values = try url.resourceValues(forKeys: keys)
            guard values.isRegularFile == true, values.isSymbolicLink != true,
                  allowedExtensions.contains(url.pathExtension.lowercased()) else { continue }
            let size = values.fileSize ?? 0
            guard size <= 1_000_000, files.count < 100, totalBytes + size <= 5_000_000 else { continue }
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            guard let content = String(data: data, encoding: .utf8) else { continue }
            files.append(["path": relative, "content": content, "mime_type": "text/plain"])
            totalBytes += size
        }
        return ["files": files, "file_count": files.count, "total_bytes": totalBytes]
    }

    private func writeWorkspace(token: String, path: String, content: String) throws -> [String: Any] {
        guard content.utf8.count <= 1_000_000 else { throw BridgeError.invalidRequest }
        let root = try workspaceRoot(token: token)
        let target = try safeWorkspaceURL(root: root, relativePath: path, allowMissingLeaf: true)
        guard allowedExtensions.contains(target.pathExtension.lowercased()) else { throw BridgeError.invalidRequest }
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(content.utf8).write(to: target, options: .atomic)
        return ["success": true, "path": path, "size_bytes": content.utf8.count]
    }

    private func trashWorkspace(token: String, path: String) throws -> [String: Any] {
        let root = try workspaceRoot(token: token)
        let source = try safeWorkspaceURL(root: root, relativePath: path)
        guard FileManager.default.fileExists(atPath: source.path) else { throw BridgeError.invalidRequest }
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let trashRoot = root.appendingPathComponent(".marcellus-trash/\(stamp)", isDirectory: true)
        let destination = trashRoot.appendingPathComponent(path)
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.moveItem(at: source, to: destination)
        return ["success": true, "path": path, "recoverable": true]
    }

    private func status() -> [[String: Any]] {
        let codexPath = findExecutable("codex")
        let codexStatus = codexPath.flatMap { try? run($0, arguments: ["login", "status"], timeout: 12) }
        let codexAuthenticated = codexStatus?.output.contains("Logged in using ChatGPT") == true

        let claudePath = findExecutable("claude")
        let claudeStatus = claudePath.flatMap { try? run($0, arguments: ["auth", "status"], timeout: 12) }
        let claudeAuthenticated = claudeStatus.map { $0.code == 0 } ?? false

        let desktopTrusted = accessibilityTrusted(prompt: false)
        return [
            [
                "brain": "codex_subscription",
                "kind": "subscription",
                "available": codexPath != nil,
                "authenticated": codexAuthenticated,
                "runtime": codexPath == nil ? NSNull() : "Codex CLI",
                "account_type": codexAuthenticated ? "ChatGPT subscription" : NSNull(),
                "models": codexModels(),
                "supports_custom_model": false,
                "detail": codexPath == nil ? "Install ChatGPT/Codex on this host." : (codexAuthenticated ? "Ready" : "Run codex login on this host."),
            ],
            [
                "brain": "claude_subscription",
                "kind": "subscription",
                "available": claudePath != nil,
                "authenticated": claudeAuthenticated,
                "runtime": claudePath == nil ? NSNull() : "Claude Agent SDK runtime",
                "account_type": claudeAuthenticated ? "Claude subscription" : NSNull(),
                "models": claudeModels(),
                "supports_custom_model": false,
                "detail": claudePath == nil ? "Install Claude Code, then authenticate on this host." : (claudeAuthenticated ? "Ready" : "Run claude login on this host."),
            ],
            desktopStatus(
                brain: "chatgpt_desktop",
                appName: "ChatGPT",
                bundleIdentifiers: ["com.openai.chat", "com.openai.chatgpt"],
                trusted: desktopTrusted
            ),
            browserBroker.status(brain: "chatgpt_browser", label: "ChatGPT"),
            browserBroker.status(brain: "claude_browser", label: "Claude"),
            browserBroker.status(brain: "gemini_browser", label: "Gemini"),
            desktopStatus(
                brain: "claude_desktop",
                appName: "Claude",
                bundleIdentifiers: ["com.anthropic.claudefordesktop", "com.anthropic.claude"],
                trusted: desktopTrusted
            ),
        ]
    }

    private func desktopStatus(
        brain: String,
        appName: String,
        bundleIdentifiers: [String],
        trusted: Bool
    ) -> [String: Any] {
        let installed = desktopApplicationURL(appName: appName, bundleIdentifiers: bundleIdentifiers) != nil
        let running = runningApplication(bundleIdentifiers: bundleIdentifiers)
        let compatible: Bool? = running.map { application in
            let element = AXUIElementCreateApplication(application.processIdentifier)
            prepareAccessibilityTree(element)
            return editableTextElement(in: element) != nil
        }
        let ready = installed && trusted && compatible != false
        let detail: String
        if !installed {
            detail = "Install the \(appName) desktop app and sign in with your subscription."
        } else if !trusted {
            detail = "Grant Enkstein Accessibility access to use the visible \(appName) app session."
        } else if compatible == false {
            detail = "Installed, but this \(appName) version does not expose a compatible message field to macOS Accessibility."
        } else if running == nil {
            detail = "Installed. Open and sign in to \(appName); compatibility will be verified on first use."
        } else {
            detail = "Ready. The signed-in \(appName) app will open visibly for each request."
        }
        return [
            "brain": brain,
            "kind": "desktop_session",
            "available": installed,
            "authenticated": ready,
            "runtime": installed ? "\(appName) desktop app" : NSNull(),
            "account_type": installed ? "User-managed desktop session" : NSNull(),
            "models": [],
            "supports_custom_model": false,
            "detail": detail,
        ]
    }

    private func codexModels() -> [String] {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".codex/models_cache.json")
        guard let data = try? Data(contentsOf: url),
              let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rows = payload["models"] as? [[String: Any]] else { return [] }
        return rows.compactMap { $0["slug"] as? String }.filter { !$0.isEmpty }
    }

    private func claudeModels() -> [String] {
        return ["sonnet", "opus", "haiku"]
    }

    private func invoke(brain: String, prompt: String, model: String?, sessionID: String?) throws -> [String: Any] {
        switch brain {
        case "codex_subscription":
            return try invokeCodex(prompt: prompt, model: model)
        case "claude_subscription":
            return try invokeClaude(prompt: prompt, model: model)
        case "chatgpt_desktop":
            return try invokeDesktop(
                prompt: prompt,
                model: model,
                appName: "ChatGPT",
                bundleIdentifiers: ["com.openai.chat", "com.openai.chatgpt"],
                provider: "openai_chatgpt_desktop"
            )
        case "claude_desktop":
            return try invokeDesktop(
                prompt: prompt,
                model: model,
                appName: "Claude",
                bundleIdentifiers: ["com.anthropic.claudefordesktop", "com.anthropic.claude"],
                provider: "anthropic_claude_desktop"
            )
        case "chatgpt_browser", "claude_browser", "gemini_browser":
            return try invokeBrowser(brain: brain, prompt: prompt, model: model, sessionID: sessionID)
        default:
            throw BridgeError.invalidRequest
        }
    }

    private func invokeBrowser(brain: String, prompt: String, model: String?, sessionID: String?) throws -> [String: Any] {
        guard model == nil || model?.isEmpty == true else { throw BridgeError.invalidRequest }
        let started = Date()
        let governedPrompt = """
        You are a reasoning-only Brain inside Enkstein. Do not claim tools or systems were changed. Answer concisely and identify uncertainty.

        QUESTION:
        \(prompt)
        """
        let result = try browserBroker.invoke(
            brain: brain,
            prompt: governedPrompt,
            sessionID: sessionID,
            timeout: 180
        )
        guard result["success"] as? Bool == true,
              let response = result["response"] as? String,
              !response.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw BridgeError.invocationFailed(
                (result["detail"] as? String) ?? "The browser session returned no response."
            )
        }
        let provider = brain.hasPrefix("chatgpt_") ? "openai_chatgpt_browser"
            : brain.hasPrefix("claude_") ? "anthropic_claude_browser" : "google_gemini_browser"
        return [
            "success": true,
            "provider": provider,
            "model": "browser-selected",
            "response": response.trimmingCharacters(in: .whitespacesAndNewlines),
            "latency_ms": Int(Date().timeIntervalSince(started) * 1000),
        ]
    }

    private func accessibilityTrusted(prompt: Bool) -> Bool {
        if !prompt { return AXIsProcessTrusted() }
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        return AXIsProcessTrustedWithOptions(options)
    }

    private func desktopApplicationURL(appName: String, bundleIdentifiers: [String]) -> URL? {
        for identifier in bundleIdentifiers {
            if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier),
               FileManager.default.fileExists(atPath: url.path),
               let actualIdentifier = Bundle(url: url)?.bundleIdentifier,
               bundleIdentifiers.contains(actualIdentifier) {
                return url
            }
        }
        return nil
    }

    private func runningApplication(bundleIdentifiers: [String]) -> NSRunningApplication? {
        for identifier in bundleIdentifiers {
            if let app = NSRunningApplication.runningApplications(withBundleIdentifier: identifier).first { return app }
        }
        return nil
    }

    private func invokeDesktop(
        prompt: String,
        model: String?,
        appName: String,
        bundleIdentifiers: [String],
        provider: String
    ) throws -> [String: Any] {
        desktopInvocationLock.lock()
        defer { desktopInvocationLock.unlock() }
        guard model == nil || model?.isEmpty == true else {
            throw BridgeError.invalidRequest
        }
        guard accessibilityTrusted(prompt: true) else {
            throw BridgeError.runtimeUnavailable(
                "Allow Enkstein in System Settings > Privacy & Security > Accessibility, then retry."
            )
        }
        guard let applicationURL = desktopApplicationURL(appName: appName, bundleIdentifiers: bundleIdentifiers) else {
            throw BridgeError.runtimeUnavailable("\(appName) desktop app is not installed on this Mac.")
        }

        if runningApplication(bundleIdentifiers: bundleIdentifiers) == nil {
            let launch = try run("/usr/bin/open", arguments: [applicationURL.path], timeout: 20)
            guard launch.code == 0 else { throw BridgeError.runtimeUnavailable("\(appName) could not be opened.") }
            Thread.sleep(forTimeInterval: 2.0)
        }
        guard let application = runningApplication(bundleIdentifiers: bundleIdentifiers) else {
            throw BridgeError.runtimeUnavailable("\(appName) is not running.")
        }
        application.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
        Thread.sleep(forTimeInterval: 0.8)

        let appElement = AXUIElementCreateApplication(application.processIdentifier)
        prepareAccessibilityTree(appElement)
        sendShortcut(keyCode: 45, flags: .maskCommand) // New conversation (Command-N).
        Thread.sleep(forTimeInterval: 0.8)
        prepareAccessibilityTree(appElement)
        let baseline = Set(accessibleStaticText(in: appElement))
        guard let input = editableTextElement(in: appElement) else {
            throw BridgeError.invocationFailed(
                "Enkstein could not find the \(appName) message field. Make sure the app is signed in and showing a chat."
            )
        }

        let governedPrompt = """
        You are a reasoning-only Brain inside Enkstein. Do not claim tools or systems were changed. Answer concisely and identify uncertainty.

        QUESTION:
        \(prompt)
        """
        guard NSWorkspace.shared.frontmostApplication?.processIdentifier == application.processIdentifier else {
            throw BridgeError.invocationFailed("\(appName) lost focus before the governed prompt could be submitted.")
        }
        AXUIElementSetAttributeValue(input, kAXFocusedAttribute as CFString, kCFBooleanTrue)
        let setResult = AXUIElementSetAttributeValue(input, kAXValueAttribute as CFString, governedPrompt as CFTypeRef)
        guard setResult == .success else {
            throw BridgeError.invocationFailed("Enkstein could not write to the \(appName) message field.")
        }

        let started = Date()
        sendKey(keyCode: 36) // Return.
        let response = try waitForDesktopResponse(
            appElement: appElement,
            baseline: baseline,
            submittedPrompt: governedPrompt,
            appName: appName,
            timeout: 180
        )
        return [
            "success": true,
            "provider": provider,
            "model": "desktop-selected",
            "response": response,
            "latency_ms": Int(Date().timeIntervalSince(started) * 1000),
        ]
    }

    private func editableTextElement(in root: AXUIElement) -> AXUIElement? {
        var matches: [AXUIElement] = []
        walkAccessibility(root, depth: 0, maxDepth: 12) { element, role in
            guard role == (kAXTextAreaRole as String) || role == (kAXTextFieldRole as String) else { return }
            var enabledValue: CFTypeRef?
            let enabled = AXUIElementCopyAttributeValue(element, kAXEnabledAttribute as CFString, &enabledValue) == .success
                && (enabledValue as? Bool ?? true)
            if enabled { matches.append(element) }
        }
        return matches.last
    }

    private func prepareAccessibilityTree(_ root: AXUIElement) {
        AXUIElementSetAttributeValue(root, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        AXUIElementSetAttributeValue(root, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
    }

    private func accessibleStaticText(in root: AXUIElement) -> [String] {
        var values: [String] = []
        walkAccessibility(root, depth: 0, maxDepth: 14) { element, role in
            guard role == (kAXStaticTextRole as String) else { return }
            var value: CFTypeRef?
            if AXUIElementCopyAttributeValue(element, kAXValueAttribute as CFString, &value) == .success,
               let text = value as? String {
                let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { values.append(trimmed) }
            }
        }
        return values
    }

    private func walkAccessibility(
        _ element: AXUIElement,
        depth: Int,
        maxDepth: Int,
        visit: (AXUIElement, String) -> Void
    ) {
        guard depth <= maxDepth else { return }
        var roleValue: CFTypeRef?
        let role = AXUIElementCopyAttributeValue(element, kAXRoleAttribute as CFString, &roleValue) == .success
            ? (roleValue as? String ?? "") : ""
        visit(element, role)
        var childrenValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &childrenValue) == .success,
              let children = childrenValue as? [AXUIElement] else { return }
        for child in children.prefix(500) {
            walkAccessibility(child, depth: depth + 1, maxDepth: maxDepth, visit: visit)
        }
    }

    private func waitForDesktopResponse(
        appElement: AXUIElement,
        baseline: Set<String>,
        submittedPrompt: String,
        appName: String,
        timeout: TimeInterval
    ) throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        var lastCandidate = ""
        var stablePolls = 0
        Thread.sleep(forTimeInterval: 2.0)
        while Date() < deadline {
            let newValues = accessibleStaticText(in: appElement).filter { value in
                guard !baseline.contains(value), value != submittedPrompt, !submittedPrompt.contains(value) else { return false }
                let normalized = value.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
                return value.count >= 12
                    && !["thinking...", "working...", "searching...", "generating..."].contains(normalized)
            }
            var seen = Set<String>()
            let candidate = newValues.filter { seen.insert($0).inserted }.joined(separator: "\n\n")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if candidate.count >= 20 {
                if candidate == lastCandidate { stablePolls += 1 } else { stablePolls = 0; lastCandidate = candidate }
                if stablePolls >= 4 { return candidate }
            }
            Thread.sleep(forTimeInterval: 1.0)
        }
        throw BridgeError.invocationFailed(
            "\(appName) did not expose a completed response before the desktop bridge timed out."
        )
    }

    private func sendShortcut(keyCode: CGKeyCode, flags: CGEventFlags) {
        guard let down = CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: true),
              let up = CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: false) else { return }
        down.flags = flags
        up.flags = flags
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
    }

    private func sendKey(keyCode: CGKeyCode) {
        sendShortcut(keyCode: keyCode, flags: [])
    }

    private func invokeCodex(prompt: String, model: String?) throws -> [String: Any] {
        guard let executable = findExecutable("codex") else {
            throw BridgeError.runtimeUnavailable("Codex is not installed on this host.")
        }
        if let model, !model.isEmpty, !codexModels().contains(model) {
            throw BridgeError.invalidRequest
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
        You are a reasoning-only Brain inside Enkstein. Do not call tools, inspect files, browse, or change any system. Do not claim actions were executed. Answer the supplied question concisely and identify uncertainty.

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
        if let model, !model.isEmpty, !claudeModels().contains(model) {
            throw BridgeError.invalidRequest
        }
        var arguments = ["-p", "--output-format", "json", "--permission-mode", "dontAsk", "--tools", ""]
        if let model, !model.isEmpty { arguments += ["--model", model] }
        arguments.append(
            "You are a reasoning-only Brain inside Enkstein. Do not use tools or change systems. " +
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

    private func sendHTML(_ connection: NWConnection, status: Int, html: String) {
        let data = Data(html.utf8)
        let header = "HTTP/1.1 \(status) OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(data.count)\r\nConnection: close\r\n\r\n"
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
    FileHandle.standardError.write(Data("Invalid Enkstein Brain Bridge configuration.\n".utf8))
    exit(2)
}
