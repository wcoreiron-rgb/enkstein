import Foundation
import Network
import AppKit
import ApplicationServices
import CryptoKit

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

// Native protocol version advertised by /v1/browser/capabilities. Lets the extension detect
// lease/ack/progress/cancel support and fall back to the legacy poll/complete-only flow otherwise.
private enum BrowserTaskState: String {
    case queued, leased, submitted, streaming, completed, failed, cancelled, expired

    static let terminal: Set<BrowserTaskState> = [.completed, .failed, .cancelled, .expired]
}

// Durable journal record: metadata and digests only. Never add prompt/response/credentials/
// token/cookie/raw-data fields here — the journal file survives broker restarts on disk.
private struct BrowserTaskRecord {
    let taskID: String
    let brain: String
    let provider: String
    let sessionID: String?
    let sequence: Int
    let promptDigest: String
    var state: BrowserTaskState
    var createdAt: Date
    var leasedAt: Date?
    var leaseExpiresAt: Date?
    var attempts: Int
    var progressAt: Date?
    var detail: String

    // Volatile only: never written to the journal file.
    var prompt: String
    var response: String?
    var success: Bool?

    private var safeJournalDetail: String {
        guard !detail.isEmpty else { return "" }
        let safeDetails = [
            "Task lease exceeded the maximum retry attempts.",
            "Task cancelled.",
            "Browser session invocation timed out before the extension completed the task.",
            "Task payload is unavailable after a Brain Bridge restart; ask the extension to resubmit.",
        ]
        return safeDetails.contains(detail)
            ? detail
            : "Task has an operator-visible detail that was not persisted."
    }

    var journalDictionary: [String: Any] {
        var dict: [String: Any] = [
            "task_id": taskID,
            "brain": brain,
            "provider": provider,
            "sequence": sequence,
            "prompt_digest": promptDigest,
            "state": state.rawValue,
            "attempts": attempts,
            "created_at": createdAt.timeIntervalSince1970,
            "detail": safeJournalDetail,
        ]
        if let sessionID { dict["session_id"] = sessionID }
        if let leasedAt { dict["leased_at"] = leasedAt.timeIntervalSince1970 }
        if let leaseExpiresAt { dict["lease_expires_at"] = leaseExpiresAt.timeIntervalSince1970 }
        if let progressAt { dict["progress_at"] = progressAt.timeIntervalSince1970 }
        return dict
    }
}

private final class BrowserSessionBroker {
    // Advertised on /v1/browser/capabilities so the extension can detect the lease/ack/progress/
    // cancel protocol and fall back to legacy poll+complete-only behavior when absent.
    static let capabilities: [String: Any] = [
        "protocol": 2,
        "features": ["lease", "submit_ack", "progress", "complete", "cancel"],
        "endpoints": [
            "poll": "/v1/browser/poll",
            "ack": "/v1/browser/ack",
            "progress": "/v1/browser/progress",
            "complete": "/v1/browser/complete",
            "cancel": "/v1/browser/cancel",
        ],
    ]

    private static let leaseDuration: TimeInterval = 20
    private static let maxAttempts = 2
    private static let maxTerminalHistory = 200
    // The extension keeps this fresh primarily through chrome.alarms, since
    // Chrome suspends the MV3 background service worker (stopping any plain
    // setInterval) and throttles content-script timers heavily once their
    // tab is backgrounded. Chrome enforces a 30-second floor on alarm
    // periods, so this must comfortably exceed that floor plus scheduling
    // jitter/service-worker cold-start time, or a perfectly healthy,
    // still-open tab gets reported as disconnected between alarm ticks.
    private static let connectionStalenessSeconds: TimeInterval = 50
    // When a browser turn arrives but the companion has not checked in within
    // connectionStalenessSeconds, wait up to this long for it to reconnect
    // (service worker waking, tab finishing a refresh) before giving up. This
    // turns a transient readiness miss -- the common "Ready in status, but the
    // turn failed at ~130ms" case -- into a brief pause and a successful run,
    // instead of an instant failure that also burns a fallback attempt. A tab
    // that is genuinely closed/signed-out still fails within this bounded
    // window rather than hanging for the full invoke timeout.
    private static let readinessGraceSeconds: TimeInterval = 15

    private let condition = NSCondition()
    private var pairingCodes: [String: Date] = [:]
    private var tasks: [String: BrowserTaskRecord] = [:]
    private var queue: [String] = []
    private var sessionSequences: [String: Int] = [:]
    private var pendingCancelSignals: [String] = []
    private var providers: Set<String> = []
    private var lastSeen: Date?
    private var token: String
    private let tokenURL: URL
    private let journalURL: URL

    init() {
        let directory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Marcellus", isDirectory: true)
        tokenURL = directory.appendingPathComponent("browser-bridge.token")
        journalURL = directory.appendingPathComponent("browser-broker-journal.json")
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if let existing = try? String(contentsOf: tokenURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), existing.count >= 48 {
            token = existing
        } else {
            token = Self.newToken()
            persistToken()
        }
        loadJournalAtStartup()
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

    // poll re-leases an explicit task_id (service-worker restart recovery) when provided, otherwise
    // leases the next queued task matching the extension's currently available providers. Returns a
    // cancel_task_id when an invoke timeout/cancel needs to be signalled back to the extension.
    func poll(availableProviders: [String], requestedTaskID: String?) -> (task: [String: Any]?, cancelTaskID: String?) {
        condition.lock()
        defer { condition.unlock() }
        providers = Set(availableProviders.filter { ["chatgpt", "claude", "gemini"].contains($0) })
        lastSeen = Date()

        let cancelSignal = pendingCancelSignals.isEmpty ? nil : pendingCancelSignals.removeFirst()

        if let requestedTaskID {
            guard var record = tasks[requestedTaskID] else { return (nil, cancelSignal) }
            if BrowserTaskState.terminal.contains(record.state) { return (nil, requestedTaskID) }
            let leaseExpired = record.leaseExpiresAt.map { $0 < Date() } ?? true
            if leaseExpired, record.attempts >= Self.maxAttempts {
                record.state = .expired
                record.detail = "Task lease exceeded the maximum retry attempts."
                record.progressAt = Date()
                record.prompt = ""
                tasks[requestedTaskID] = record
                persistJournal()
                return (nil, requestedTaskID)
            }
            if record.state == .queued || leaseExpired { record.attempts += 1 }
            record.state = .leased
            record.leasedAt = Date()
            record.leaseExpiresAt = Date().addingTimeInterval(Self.leaseDuration)
            tasks[requestedTaskID] = record
            persistJournal()
            return (payload(for: record), cancelSignal)
        }

        guard let index = queue.firstIndex(where: { id in
            guard let task = tasks[id], task.state == .queued else { return false }
            return providers.contains(task.provider)
        }) else { return (nil, cancelSignal) }

        let taskID = queue.remove(at: index)
        guard var record = tasks[taskID] else { return (nil, cancelSignal) }
        record.state = .leased
        record.attempts += 1
        record.leasedAt = Date()
        record.leaseExpiresAt = Date().addingTimeInterval(Self.leaseDuration)
        tasks[taskID] = record
        persistJournal()
        return (payload(for: record), cancelSignal)
    }

    // ACK transitions leased -> submitted once the extension has written the prompt into the page.
    func ack(taskID: String) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard var record = tasks[taskID], record.state == .leased else { return false }
        record.state = .submitted
        record.progressAt = Date()
        record.leaseExpiresAt = Date().addingTimeInterval(Self.leaseDuration)
        tasks[taskID] = record
        persistJournal()
        return true
    }

    // progress only accepts submitted/streaming states with bounded detail text, and extends the lease.
    func progress(taskID: String, state: String, detail: String?) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard var record = tasks[taskID],
              record.state == .submitted || record.state == .streaming,
              let newState = BrowserTaskState(rawValue: state),
              newState == .submitted || newState == .streaming else { return false }
        record.state = newState
        record.progressAt = Date()
        record.leaseExpiresAt = Date().addingTimeInterval(Self.leaseDuration)
        if let detail { record.detail = String(detail.prefix(500)) }
        tasks[taskID] = record
        persistJournal()
        return true
    }

    func complete(taskID: String, success: Bool, response: String?, detail: String?) {
        condition.lock()
        defer { condition.unlock() }
        guard var record = tasks[taskID],
              [.leased, .submitted, .streaming].contains(record.state) else { return }
        record.state = success ? .completed : .failed
        record.response = response?.prefix(120_000).description ?? ""
        record.detail = detail?.prefix(500).description ?? ""
        record.success = success
        record.progressAt = Date()
        record.prompt = ""
        tasks[taskID] = record
        queue.removeAll { $0 == taskID }
        persistJournal()
        condition.broadcast()
    }

    // Idempotent: cancelling an already-terminal task is a no-op. Never persists response content.
    func cancel(taskID: String) {
        condition.lock()
        defer { condition.unlock() }
        guard var record = tasks[taskID], !BrowserTaskState.terminal.contains(record.state) else { return }
        record.state = .cancelled
        record.progressAt = Date()
        record.detail = "Task cancelled."
        record.prompt = ""
        record.response = nil
        tasks[taskID] = record
        queue.removeAll { $0 == taskID }
        persistJournal()
        condition.broadcast()
    }

    func invoke(brain: String, prompt: String, sessionID: String?, timeout: TimeInterval) throws -> [String: Any] {
        let provider = Self.provider(for: brain)
        condition.lock()
        // Wait a bounded grace period for the companion to (re)connect rather
        // than failing instantly on a transient miss. poll() refreshes
        // lastSeen/providers on the extension's regular check-in; re-checking
        // after each bounded wait lets a briefly-asleep worker or a
        // mid-refresh tab recover without burning the turn.
        let readinessDeadline = Date().addingTimeInterval(Self.readinessGraceSeconds)
        while !(lastSeen.map { Date().timeIntervalSince($0) < Self.connectionStalenessSeconds && providers.contains(provider) } ?? false) {
            if Date() >= readinessDeadline {
                condition.unlock()
                throw BridgeError.runtimeUnavailable(
                    "Enkstein could not reach a signed-in \(provider.capitalized) tab. Open \(Self.providerHost(for: provider)) in your browser, sign in, keep the tab open, then try again."
                )
            }
            _ = condition.wait(until: min(readinessDeadline, Date().addingTimeInterval(1)))
        }
        let generated = nextTaskID(provider: provider, sessionID: sessionID, prompt: prompt)
        let record = BrowserTaskRecord(
            taskID: generated.id, brain: brain, provider: provider, sessionID: sessionID,
            sequence: generated.sequence, promptDigest: generated.digest, state: .queued,
            createdAt: Date(), leasedAt: nil, leaseExpiresAt: nil, attempts: 0,
            progressAt: nil, detail: "", prompt: prompt, response: nil, success: nil
        )
        tasks[record.taskID] = record
        queue.append(record.taskID)
        persistJournal()
        condition.broadcast()

        let deadline = Date().addingTimeInterval(timeout)
        while true {
            guard let current = tasks[record.taskID] else { break }
            if BrowserTaskState.terminal.contains(current.state) { break }
            if !condition.wait(until: deadline) || Date() >= deadline { break }
        }

        var result: [String: Any]?
        if let final = tasks[record.taskID], final.state == .completed || final.state == .failed {
            result = ["success": final.success ?? false, "response": final.response ?? "", "detail": final.detail]
            var retained = final
            retained.prompt = ""
            retained.response = nil
            retained.success = nil
            tasks[record.taskID] = retained
        } else if var timedOut = tasks[record.taskID] {
            timedOut.state = timedOut.attempts > 0 ? .cancelled : .expired
            timedOut.detail = "Browser session invocation timed out before the extension completed the task."
            timedOut.progressAt = Date()
            timedOut.prompt = ""
            timedOut.response = nil
            tasks[record.taskID] = timedOut
            pendingCancelSignals.append(record.taskID)
            queue.removeAll { $0 == record.taskID }
        }
        persistJournal()
        condition.unlock()
        guard let result else {
            throw BridgeError.invocationFailed(
                "Browser session invocation timed out. The Enkstein browser companion was signalled to cancel the task."
            )
        }
        return result
    }

    func status(brain: String, label: String) -> [String: Any] {
        condition.lock()
        defer { condition.unlock() }
        let provider = Self.provider(for: brain)
        let connected = lastSeen.map { Date().timeIntervalSince($0) < Self.connectionStalenessSeconds && providers.contains(provider) } ?? false
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

    private func payload(for record: BrowserTaskRecord) -> [String: Any] {
        var dict: [String: Any] = [
            "task_id": record.taskID,
            "brain": record.brain,
            "provider": record.provider,
            "prompt": record.prompt,
        ]
        if let sessionID = record.sessionID { dict["session_id"] = sessionID }
        return dict
    }

    // Stable scoped SHA-256 task IDs: provider + opaque session ID + per-session monotonic sequence +
    // prompt digest. Only the sequence and digest are persisted; the prompt itself never is.
    private func nextTaskID(provider: String, sessionID: String?, prompt: String) -> (id: String, sequence: Int, digest: String) {
        let sessionKey = "\(provider)|\(sessionID ?? "-")"
        let sequence = (sessionSequences[sessionKey] ?? 0) + 1
        sessionSequences[sessionKey] = sequence
        let digest = SHA256.hash(data: Data(prompt.utf8)).map { String(format: "%02x", $0) }.joined()
        let scope = "\(sessionKey)|\(sequence)|\(digest)"
        let id = SHA256.hash(data: Data(scope.utf8)).map { String(format: "%02x", $0) }.joined()
        return (id, sequence, digest)
    }

    // Runs once at broker startup: any journaled task that was not already terminal had its volatile
    // prompt lost when the process exited, so it is converted to expired with an actionable detail
    // instead of being left stuck or silently re-leased with a payload that no longer exists.
    private func loadJournalAtStartup() {
        guard let data = try? Data(contentsOf: journalURL),
              let records = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return }
        for record in records {
            guard let taskID = record["task_id"] as? String,
                  let brain = record["brain"] as? String,
                  let provider = record["provider"] as? String,
                  let sequence = record["sequence"] as? Int,
                  let promptDigest = record["prompt_digest"] as? String,
                  let stateRaw = record["state"] as? String else { continue }
            let sessionID = record["session_id"] as? String
            let createdAt = (record["created_at"] as? Double).map { Date(timeIntervalSince1970: $0) } ?? Date()
            var loaded = BrowserTaskRecord(
                taskID: taskID, brain: brain, provider: provider, sessionID: sessionID,
                sequence: sequence, promptDigest: promptDigest, state: .expired,
                createdAt: createdAt, leasedAt: nil, leaseExpiresAt: nil,
                attempts: record["attempts"] as? Int ?? 0, progressAt: Date(),
                detail: "", prompt: "", response: nil, success: nil
            )
            if let resolved = BrowserTaskState(rawValue: stateRaw), BrowserTaskState.terminal.contains(resolved) {
                loaded.state = resolved
                loaded.detail = (record["detail"] as? String).map { String($0.prefix(500)) } ?? ""
            } else {
                loaded.state = .expired
                loaded.detail = "Task payload is unavailable after a Brain Bridge restart; ask the extension to resubmit."
            }
            tasks[taskID] = loaded
            if let sessionID {
                let key = "\(provider)|\(sessionID)"
                sessionSequences[key] = max(sessionSequences[key] ?? 0, sequence)
            }
        }
        persistJournal()
    }

    // Bounds the journal to the most recent terminal tasks so the file and in-memory map cannot grow
    // without limit across a long-running broker process.
    private func pruneTerminalHistory() {
        let terminalIDs = tasks.values
            .filter { BrowserTaskState.terminal.contains($0.state) }
            .sorted { ($0.progressAt ?? $0.createdAt) < ($1.progressAt ?? $1.createdAt) }
            .map { $0.taskID }
        guard terminalIDs.count > Self.maxTerminalHistory else { return }
        for id in terminalIDs.prefix(terminalIDs.count - Self.maxTerminalHistory) {
            tasks.removeValue(forKey: id)
        }
    }

    // Atomic, owner-only (0600) write. journalDictionary only ever carries metadata/digests — see its
    // definition above for the allowlist of fields; prompt/response/credentials/token/cookie are excluded.
    private func persistJournal() {
        pruneTerminalHistory()
        let records = tasks.values.map { $0.journalDictionary }
        guard let data = try? JSONSerialization.data(withJSONObject: records) else { return }
        try? data.write(to: journalURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journalURL.path)
    }

    private static func provider(for brain: String) -> String {
        if brain.hasPrefix("chatgpt_") { return "chatgpt" }
        if brain.hasPrefix("claude_") { return "claude" }
        return "gemini"
    }

    private static func providerHost(for provider: String) -> String {
        switch provider {
        case "chatgpt": return "chatgpt.com"
        case "claude": return "claude.ai"
        default: return "gemini.google.com"
        }
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
        // Apple/Swift app scaffolds and other common source/config types that
        // a "create this project" turn routinely produces.
        "swift", "m", "mm", "metal", "plist", "entitlements", "storyboard", "xib",
        "pbxproj", "xcconfig", "xcscheme", "modulemap", "resolved",
        "dart", "php", "vue", "svelte", "scss", "sass", "less", "svg", "gradle",
        "properties", "bat", "env", "gitignore", "gitattributes", "dockerignore",
        "editorconfig", "keep", "gitkeep",
    ])
    // Files with no extension whose exact name is a common, safe project
    // marker/config. `.keep`/`.gitkeep` and similar dotfiles report an empty
    // pathExtension in Foundation, so they must be matched by full name; the
    // same applies to conventional extensionless files like Dockerfile.
    private let allowedFilenames = Set([
        ".keep", ".gitkeep", ".gitignore", ".gitattributes", ".dockerignore",
        ".editorconfig", "dockerfile", "makefile", "procfile", "podfile",
        "gemfile", "rakefile", "license", "readme", "changelog", "notice",
    ])

    // A workspace file is allowed when its extension is allowlisted or its full
    // (lowercased) name is a recognized extensionless project file. Backend
    // path validation independently blocks secret leaves (.env, .pypirc, etc.)
    // and protected directories before any write reaches here.
    private func isAllowedWorkspaceFile(_ url: URL) -> Bool {
        if allowedExtensions.contains(url.pathExtension.lowercased()) { return true }
        return allowedFilenames.contains(url.lastPathComponent.lowercased())
    }

    private lazy var codexSessions = CodexAppServerSessionManager(
        findExecutable: { [weak self] name in self?.findExecutable(name) },
        workspaceRoot: { [weak self] token in
            guard let self else { throw BridgeError.invalidRequest }
            return try self.workspaceRoot(token: token)
        }
    )

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

        if request.method == "POST", request.path == "/v1/browser/capabilities" {
            guard browserBroker.validate(candidate: request.headers["x-marcellus-browser-token"] ?? "") else {
                send(connection, status: 401, body: ["detail": "Browser companion is not paired"])
                return
            }
            send(connection, status: 200, body: BrowserSessionBroker.capabilities)
            return
        }

        if request.method == "POST", request.path == "/v1/browser/poll" {
            guard browserBroker.validate(candidate: request.headers["x-marcellus-browser-token"] ?? ""),
                  let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any] else {
                send(connection, status: 401, body: ["detail": "Browser companion is not paired"])
                return
            }
            let providers = payload["providers"] as? [String] ?? []
            let requestedTaskID = payload["task_id"] as? String
            let result = browserBroker.poll(availableProviders: providers, requestedTaskID: requestedTaskID)
            var body: [String: Any] = ["task": result.task ?? NSNull()]
            if let cancelTaskID = result.cancelTaskID { body["cancel_task_id"] = cancelTaskID }
            send(connection, status: 200, body: body)
            return
        }

        if request.method == "POST", request.path == "/v1/browser/ack" {
            guard browserBroker.validate(candidate: request.headers["x-marcellus-browser-token"] ?? ""),
                  let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let taskID = payload["task_id"] as? String else {
                send(connection, status: 401, body: ["detail": "Browser companion is not paired"])
                return
            }
            send(connection, status: 200, body: ["accepted": browserBroker.ack(taskID: taskID)])
            return
        }

        if request.method == "POST", request.path == "/v1/browser/progress" {
            guard browserBroker.validate(candidate: request.headers["x-marcellus-browser-token"] ?? ""),
                  let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let taskID = payload["task_id"] as? String,
                  let state = payload["state"] as? String else {
                send(connection, status: 401, body: ["detail": "Browser companion is not paired"])
                return
            }
            let detail = payload["detail"] as? String
            send(connection, status: 200, body: ["accepted": browserBroker.progress(taskID: taskID, state: state, detail: detail)])
            return
        }

        if request.method == "POST", request.path == "/v1/browser/cancel" {
            guard browserBroker.validate(candidate: request.headers["x-marcellus-browser-token"] ?? ""),
                  let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let taskID = payload["task_id"] as? String else {
                send(connection, status: 401, body: ["detail": "Browser companion is not paired"])
                return
            }
            browserBroker.cancel(taskID: taskID)
            send(connection, status: 200, body: ["accepted": true])
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

        // CLI subscription login (codex login / claude login) is an
        // interactive OAuth device-flow that needs a real terminal and a
        // browser tab -- it cannot be completed silently from a background
        // process. This is the closest thing to a "single button" for it:
        // open Terminal.app pre-populated with the exact resolved binary's
        // login command, so the user only has to press Return and finish
        // the OAuth prompt in their browser, without hand-typing anything
        // or hunting for the right install path themselves.
        if request.method == "POST", request.path == "/v1/cli/launch-login" {
            guard let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
                  let brain = payload["brain"] as? String else {
                send(connection, status: 400, body: ["error": "A brain is required."])
                return
            }
            let executableName = brain == "claude_subscription" ? "claude" : brain == "codex_subscription" ? "codex" : nil
            guard let executableName else {
                send(connection, status: 400, body: ["error": "Unsupported CLI brain."])
                return
            }
            guard let executablePath = findExecutable(executableName) else {
                send(connection, status: 200, body: [
                    "launched": false,
                    "detail": "\(executableName) is not installed on this host yet.",
                ])
                return
            }
            let loginArgs = executableName == "claude" ? "" : " login"
            // Build the shell command Terminal will run, then embed it in the
            // AppleScript command string using its own quoting/escaping rules
            // (AppleScript "quoted form of" is not applicable here since this
            // is a literal script string, not a shell argument) -- escape only
            // double quotes and backslashes, matching AppleScript string literal
            // escaping, not shell escaping.
            let shellCommand = "\"\(executablePath)\"\(loginArgs)"
            let escapedForAppleScript = shellCommand
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
            let script = "tell application \"Terminal\" to do script \"\(escapedForAppleScript)\""
            let launched = (try? run("/usr/bin/osascript", arguments: ["-e", script], timeout: 15).code) == 0
            send(connection, status: 200, body: [
                "launched": launched,
                "detail": launched
                    ? "Complete sign-in in the opened Terminal window, then return here and refresh."
                    : "Could not open Terminal to run \(executableName) login.",
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

        if request.method == "POST", request.path.hasPrefix("/v1/codex/") {
            guard let payload = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any] else {
                send(connection, status: 400, body: ["detail": "Invalid Codex payload"])
                return
            }
            queue.async { [weak self] in
                guard let self else { return }
                do {
                    let body: [String: Any]
                    switch request.path {
                    case "/v1/codex/start":
                        guard let scope = payload["scope_digest"] as? String,
                              let token = payload["token"] as? String,
                              let sandbox = payload["sandbox"] as? String else { throw BridgeError.invalidRequest }
                        body = try self.codexSessions.start(scopeDigest: scope, token: token, sandbox: sandbox)
                    case "/v1/codex/turn":
                        guard let scope = payload["scope_digest"] as? String,
                              let token = payload["token"] as? String,
                              let prompt = payload["prompt"] as? String else { throw BridgeError.invalidRequest }
                        body = try self.codexSessions.turn(scopeDigest: scope, token: token, prompt: prompt)
                    case "/v1/codex/status":
                        guard let scope = payload["scope_digest"] as? String,
                              let token = payload["token"] as? String else { throw BridgeError.invalidRequest }
                        let cursor = (payload["cursor"] as? NSNumber)?.intValue ?? 0
                        body = try self.codexSessions.status(scopeDigest: scope, token: token, cursor: cursor)
                    case "/v1/codex/approve":
                        guard let scope = payload["scope_digest"] as? String,
                              let token = payload["token"] as? String,
                              let approvalId = payload["approval_id"] as? String,
                              let decision = payload["decision"] as? String else { throw BridgeError.invalidRequest }
                        body = try self.codexSessions.approve(scopeDigest: scope, token: token, approvalId: approvalId, decision: decision)
                    case "/v1/codex/cancel":
                        guard let scope = payload["scope_digest"] as? String,
                              let token = payload["token"] as? String else { throw BridgeError.invalidRequest }
                        body = try self.codexSessions.cancel(scopeDigest: scope, token: token)
                    default:
                        self.send(connection, status: 404, body: ["detail": "Not found"])
                        return
                    }
                    self.send(connection, status: 200, body: body)
                } catch let CodexAppServerSessionManager.SessionError.invalid(detail) {
                    self.send(connection, status: 400, body: ["detail": detail])
                } catch {
                    self.send(connection, status: 400, body: ["detail": "Codex session request rejected"])
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
                  isAllowedWorkspaceFile(url) else { continue }
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
        guard isAllowedWorkspaceFile(target) else { throw BridgeError.invalidRequest }
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
        let governedPrompt = "You are a reasoning-only Brain inside Enkstein. Do not use tools or change systems. " +
            "Answer concisely and identify uncertainty.\n\nQUESTION:\n" + prompt
        let started = Date()
        let result = try run(executable, arguments: arguments, input: governedPrompt, timeout: 180)
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

/// A reusable, long-lived Codex `app-server` connection spoken over stdio using
/// newline-delimited JSON-RPC. The prompt (and every other free-text body) is
/// never passed on argv and is never retained inside this process: events are
/// sanitized down to routing/telemetry metadata the moment they are ingested.
private final class CodexAppServerProcess {
    struct SanitizedEvent {
        let cursor: Int
        let channel: String  // "notification" or "serverRequest"
        let fields: [String: Any]
        // Numeric JSON-RPC id retained ONLY for allowlisted approval server
        // requests so the session manager can respond exactly once. Every other
        // server request drops its id (and body) at the boundary.
        let approvalRequestId: Int?
        let approvalMethod: String?
        // Bounded, non-sensitive approval detail surfaced transiently to the
        // matching thread for an informed decision. Never persisted or logged.
        let approvalDetail: [String: Any]?

        /// A dictionary guaranteed to contain only JSON-serialisable values so it
        /// can be handed straight to callers over HTTP.
        var jsonSafe: [String: Any] {
            CodexAppServerProcess.jsonSafe(fields)
        }
    }

    /// Server-initiated requests we are willing to surface for an operator
    /// decision. Anything else is auto-declined with a bodiless response.
    static let approvalMethods: Set<String> = [
        "item/commandExecution/requestApproval",
        "item/fileChange/requestApproval",
        "item/permissions/requestApproval",
    ]

    static func jsonSafe(_ value: Any) -> [String: Any] {
        func coerce(_ any: Any) -> Any? {
            switch any {
            case let number as NSNumber: return number
            case let string as String: return string
            case let flag as Bool: return flag
            case let dict as [String: Any]:
                var out: [String: Any] = [:]
                for (key, inner) in dict { if let safe = coerce(inner) { out[key] = safe } }
                return out
            case let array as [Any]:
                return array.compactMap { coerce($0) }
            default:
                return nil
            }
        }
        return (coerce(value) as? [String: Any]) ?? [:]
    }

    private enum CodexProcessError: Error {
        case executableMissing
        case notRunning
        case writeFailed
        case timedOut
        case terminated
    }

    private let executableLocator: (String) -> String?
    private let clientInfo: [String: Any]

    private let writeLock = NSLock()
    private let stateLock = NSLock()
    private let waiterCondition = NSCondition()

    private var process: Process?
    private var stdinPipe: Pipe?
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?
    private var readerThread: Thread?
    private var stderrThread: Thread?

    private var nextID: Int = 0
    private var running = false

    // Response routing: id -> completed result or nil while pending.
    private var pendingResponses: [Int: Result<Any?, Error>] = [:]
    private var awaitedIDs: Set<Int> = []

    // Bounded ring of sanitized events surfaced to callers via drainEvents.
    private let maxEvents = 500
    // Hard cap on any single retained text field (transient delta / diff /
    // approval detail). Keeps the in-memory ring bounded and non-abusive.
    static let maxTextField = 32 * 1024
    private var events: [SanitizedEvent] = []
    private var eventCursor = 0
    private var readBuffer = Data()

    init(executableLocator: @escaping (String) -> String?) {
        self.executableLocator = executableLocator
        self.clientInfo = [
            "name": "EnksteinBrainBridge",
            "version": "1",
        ]
    }

    // MARK: Lifecycle

    var isRunning: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return running && (process?.isRunning ?? false)
    }

    func start() throws {
        stateLock.lock()
        if running {
            stateLock.unlock()
            return
        }
        stateLock.unlock()

        guard let executable = executableLocator("codex") else {
            throw CodexProcessError.executableMissing
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["app-server", "--listen", "stdio://"]
        process.environment = [
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "PATH": "/Applications/ChatGPT.app/Contents/Resources:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
        ]

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        process.terminationHandler = { [weak self] _ in
            self?.handleTermination()
        }

        try process.run()

        stateLock.lock()
        self.process = process
        self.stdinPipe = stdinPipe
        self.stdoutPipe = stdoutPipe
        self.stderrPipe = stderrPipe
        self.running = true
        stateLock.unlock()

        let reader = Thread { [weak self] in self?.readLoop() }
        reader.name = "codex-app-server-reader"
        reader.stackSize = 1 << 20
        stateLock.lock(); self.readerThread = reader; stateLock.unlock()
        reader.start()

        // Concurrently drain and discard stderr so the app-server can never
        // deadlock on a full stderr pipe. Diagnostics may be sensitive, so we
        // never retain, journal, or log them.
        let stderrReader = Thread { [weak self] in self?.stderrDrainLoop() }
        stderrReader.name = "codex-app-server-stderr"
        stderrReader.stackSize = 1 << 18
        stateLock.lock(); self.stderrThread = stderrReader; stateLock.unlock()
        stderrReader.start()

        do {
            try handshake()
        } catch {
            // A failed handshake must cleanly terminate the transport rather
            // than leave an orphaned process attached to live pipes.
            stop()
            throw error
        }
    }

    /// Reads stderr to EOF and discards every byte. Retaining stderr risks
    /// leaking prompt/response fragments, so nothing here is kept.
    private func stderrDrainLoop() {
        guard let handle = stderrPipe?.fileHandleForReading else { return }
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty { break }
            // Intentionally discarded.
        }
    }

    func stop() {
        stateLock.lock()
        let process = self.process
        running = false
        stateLock.unlock()
        process?.terminationHandler = nil
        if process?.isRunning ?? false {
            process?.terminate()
        }
        handleTermination()
    }

    private func handshake() throws {
        var params: [String: Any] = ["clientInfo": clientInfo]
        params["capabilities"] = ["experimentalApi": false]
        _ = try request(method: "initialize", params: params)
        try notify(method: "initialized", params: nil)
    }

    // MARK: Public JSON-RPC surface

    @discardableResult
    func request(method: String, params: [String: Any]?) throws -> Any? {
        stateLock.lock()
        guard running else { stateLock.unlock(); throw CodexProcessError.notRunning }
        nextID += 1
        let id = nextID
        stateLock.unlock()

        waiterCondition.lock()
        awaitedIDs.insert(id)
        waiterCondition.unlock()

        var message: [String: Any] = ["id": id, "method": method]
        if let params { message["params"] = params }
        do {
            try writeMessage(message)
        } catch {
            waiterCondition.lock()
            awaitedIDs.remove(id)
            pendingResponses.removeValue(forKey: id)
            waiterCondition.unlock()
            throw error
        }

        let deadline = Date().addingTimeInterval(30)
        waiterCondition.lock()
        defer { waiterCondition.unlock() }
        while pendingResponses[id] == nil {
            if !waiterCondition.wait(until: deadline) {
                awaitedIDs.remove(id)
                throw CodexProcessError.timedOut
            }
        }
        let result = pendingResponses.removeValue(forKey: id)
        awaitedIDs.remove(id)
        switch result {
        case .success(let value)?: return value
        case .failure(let error)?: throw error
        case nil: throw CodexProcessError.terminated
        }
    }

    func notify(method: String, params: [String: Any]?) throws {
        stateLock.lock()
        guard running else { stateLock.unlock(); throw CodexProcessError.notRunning }
        stateLock.unlock()
        var message: [String: Any] = ["method": method]
        if let params { message["params"] = params }
        try writeMessage(message)
    }

    func drainEvents(after cursor: Int) -> [SanitizedEvent] {
        stateLock.lock(); defer { stateLock.unlock() }
        return events.filter { $0.cursor > cursor }
    }

    // MARK: Writing

    private func writeMessage(_ message: [String: Any]) throws {
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            throw CodexProcessError.writeFailed
        }
        var line = data
        line.append(0x0A)  // newline-delimited framing
        writeLock.lock()
        defer { writeLock.unlock() }
        stateLock.lock()
        let handle = stdinPipe?.fileHandleForWriting
        stateLock.unlock()
        guard let handle else { throw CodexProcessError.notRunning }
        do {
            try handle.write(contentsOf: line)
        } catch {
            throw CodexProcessError.writeFailed
        }
    }

    // MARK: Reading

    private func readLoop() {
        guard let handle = stdoutPipe?.fileHandleForReading else { return }
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty { break }
            readBuffer.append(chunk)
            while let newlineIndex = readBuffer.firstIndex(of: 0x0A) {
                let lineData = readBuffer.subdata(in: readBuffer.startIndex..<newlineIndex)
                readBuffer.removeSubrange(readBuffer.startIndex...newlineIndex)
                if lineData.isEmpty { continue }
                handleLine(lineData)
            }
        }
        handleTermination()
    }

    private func handleLine(_ data: Data) {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let message = object as? [String: Any] else { return }

        let hasID = message["id"] != nil
        let hasMethod = message["method"] != nil

        if hasID && !hasMethod {
            // Response to one of our requests.
            guard let id = numericID(message["id"]) else { return }
            let result: Result<Any?, Error>
            if let errorObject = message["error"] as? [String: Any] {
                result = .failure(CodexRPCError(sanitizedError(errorObject)))
            } else {
                result = .success(message["result"])
            }
            waiterCondition.lock()
            if awaitedIDs.contains(id) {
                pendingResponses[id] = result
                waiterCondition.broadcast()
            }
            waiterCondition.unlock()
            return
        }

        // Server-initiated request (has id + method) or notification (method only).
        if hasID {
            let method = message["method"] as? String
            let requestId = numericID(message["id"])
            if let method, let requestId, CodexAppServerProcess.approvalMethods.contains(method) {
                let params = (message["params"] as? [String: Any]) ?? [:]
                ingest(channel: "serverRequest", message: message,
                       approvalRequestId: requestId, approvalMethod: method,
                       approvalDetail: approvalDetail(method: method, params: params))
            } else {
                // Auto-decline every unsupported server request without ever
                // exposing its body, and never retain a routable id for it.
                if let requestId {
                    respondError(id: requestId, code: -32601, message: "Unsupported request")
                }
                ingest(channel: "serverRequest",
                       message: ["method": method as Any].compactMapValues { $0 },
                       approvalRequestId: nil, approvalMethod: nil, approvalDetail: nil)
            }
            return
        }
        ingest(channel: "notification", message: message,
               approvalRequestId: nil, approvalMethod: nil, approvalDetail: nil)
    }

    /// Writes a JSON-RPC response for a server-initiated request. Used only to
    /// answer allowlisted approval requests (accept/decline) exactly once.
    func respond(id: Int, result: [String: Any]) {
        try? writeMessage(["id": id, "result": result])
    }

    func respondError(id: Int, code: Int, message: String) {
        try? writeMessage(["id": id, "error": ["code": code, "message": message]])
    }

    private func ingest(channel: String, message: [String: Any],
                        approvalRequestId: Int?, approvalMethod: String?,
                        approvalDetail: [String: Any]?) {
        let fields = sanitize(message)
        stateLock.lock()
        eventCursor += 1
        events.append(SanitizedEvent(cursor: eventCursor, channel: channel, fields: fields,
                                     approvalRequestId: approvalRequestId,
                                     approvalMethod: approvalMethod,
                                     approvalDetail: approvalDetail))
        if events.count > maxEvents {
            events.removeFirst(events.count - maxEvents)
        }
        stateLock.unlock()
    }

    // MARK: Termination

    private func handleTermination() {
        stateLock.lock()
        running = false
        stateLock.unlock()
        // Fail every pending and awaited request so callers unblock.
        waiterCondition.lock()
        for id in awaitedIDs where pendingResponses[id] == nil {
            pendingResponses[id] = .failure(CodexProcessError.terminated)
        }
        waiterCondition.broadcast()
        waiterCondition.unlock()
    }

    // MARK: Sanitization

    private func numericID(_ raw: Any?) -> Int? {
        if let value = raw as? Int { return value }
        if let value = raw as? NSNumber { return value.intValue }
        if let value = raw as? String { return Int(value) }
        return nil
    }

    /// Retains only routing/telemetry metadata. Every free-text body — prompts,
    /// text, deltas, commands, arguments, content, output, and raw patch bodies —
    /// is discarded at the boundary and never stored.
    private func sanitize(_ message: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        if let method = message["method"] as? String { out["method"] = method }

        let params = (message["params"] as? [String: Any]) ?? message
        if let threadId = params["threadId"] as? String { out["threadId"] = threadId }
        if let turnId = params["turnId"] as? String { out["turnId"] = turnId }

        // `turn/completed` carries the authoritative lifecycle inside a nested
        // Turn object. Retain only its opaque id and enum status; never retain
        // the turn body or any model content.
        if let turn = params["turn"] as? [String: Any] {
            if out["turnId"] == nil, let id = turn["id"] as? String { out["turnId"] = id }
            if let status = turn["status"] as? String { out["turnStatus"] = status }
        }

        if let item = params["item"] as? [String: Any] {
            var safeItem: [String: Any] = [:]
            if let type = (item["type"] ?? item["itemType"]) as? String { safeItem["type"] = type }
            if let status = item["status"] as? String { safeItem["status"] = status }
            if let id = (item["id"] ?? item["itemId"]) as? String { safeItem["id"] = id }
            if !safeItem.isEmpty { out["item"] = safeItem }
        } else {
            if let type = (params["type"] ?? params["itemType"]) as? String { out["type"] = type }
            if let status = params["status"] as? String { out["status"] = status }
        }

        if let usage = (params["usage"] ?? params["tokenUsage"]) as? [String: Any] {
            out["usage"] = numericFields(usage)
        }

        if let errorObject = message["error"] as? [String: Any] {
            out["error"] = sanitizedError(errorObject)
        }

        // Transiently surface bounded response/plan/diff content for the exact
        // allowlisted streaming methods only. Held in the in-memory ring and
        // routed to the matching thread via status; never persisted or logged.
        if let transient = transientContent(method: out["method"] as? String, params: params) {
            out["transient"] = transient
        }
        return out
    }

    private func numericFields(_ source: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        for (key, value) in source {
            if let number = value as? NSNumber {
                out[key] = number
            } else if let nested = value as? [String: Any] {
                let inner = numericFields(nested)
                if !inner.isEmpty { out[key] = inner }
            }
        }
        return out
    }

    private func sanitizedError(_ error: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        if let code = error["code"] as? NSNumber { out["code"] = code }
        return out
    }

    /// Truncates any free-text value to `maxTextField` UTF-8 bytes so no single
    /// retained field can grow unbounded. Returns nil for empty/non-string.
    private func boundedString(_ value: Any?) -> String? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        let bytes = Array(text.utf8)
        if bytes.count <= CodexAppServerProcess.maxTextField { return text }
        return String(decoding: bytes.prefix(CodexAppServerProcess.maxTextField), as: UTF8.self)
    }

    /// Bounded transient content for the exact allowlisted streaming methods.
    /// Every other method returns nil, so no other body is ever retained.
    private func transientContent(method: String?, params: [String: Any]) -> [String: Any]? {
        guard let method else { return nil }
        switch method {
        case "item/agentMessage/delta", "item/plan/delta":
            guard let text = boundedString(params["delta"] ?? params["text"] ?? params["content"]) else { return nil }
            return ["kind": method, "text": text]
        case "turn/diff/updated":
            guard let text = boundedString(params["diff"] ?? params["unifiedDiff"] ?? params["content"]) else { return nil }
            return ["kind": method, "diff": text]
        default:
            return nil
        }
    }

    /// Bounded, non-sensitive detail for an allowlisted approval request so a
    /// same-thread operator can decide. File approvals never expose grantRoot or
    /// absolute paths; permissions approvals carry no free text (deny-only).
    private func approvalDetail(method: String, params: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        if let itemId = (params["itemId"] ?? params["item_id"]) as? String { out["itemId"] = itemId }
        if let turnId = (params["turnId"] ?? params["turn_id"]) as? String { out["turnId"] = turnId }
        switch method {
        case "item/commandExecution/requestApproval":
            if let command = boundedString(params["command"]) {
                out["command"] = command
            } else if let parts = params["command"] as? [Any] {
                let joined = parts.compactMap { $0 as? String }.joined(separator: " ")
                if let command = boundedString(joined) { out["command"] = command }
            }
            if let reason = boundedString(params["reason"]) { out["reason"] = reason }
            // Only the working-directory basename — never the absolute path.
            if let cwd = params["cwd"] as? String, !cwd.isEmpty {
                out["cwd"] = URL(fileURLWithPath: cwd).lastPathComponent
            }
        case "item/fileChange/requestApproval":
            if let reason = boundedString(params["reason"]) { out["reason"] = reason }
        default:
            break
        }
        return out
    }
}

private struct CodexRPCError: Error {
    let fields: [String: Any]
    init(_ fields: [String: Any]) { self.fields = fields }
}

/// Governs Codex `app-server` sessions over a single shared transport. Every
/// scope maps to one persisted thread. No prompt, event body, or approval body
/// is ever journalled — only an opaque thread id, sandbox, and timestamps.
private final class CodexAppServerSessionManager {
    enum SessionError: Error {
        case invalid(String)
    }

    private struct Session {
        var scopeKey: String
        var threadId: String
        var sandbox: String
        var updatedAt: Double
        var currentTurnId: String?
        var interrupted: Bool
        // Turn lifecycle, tracked from exact notifications and distinct from the
        // transport/session state. "idle" | "running" | "completed" | "interrupted".
        var turnState: String
    }

    private struct PendingApproval {
        let approvalId: String
        let requestId: Int
        let method: String
        // Always the concrete thread this approval belongs to. Approvals without
        // a valid, known thread are auto-declined and never enqueued.
        let threadId: String
        let detail: [String: Any]
    }

    private static let scopeDigestPattern = "^[a-f0-9]{64}$"
    private static let maxPromptLength = 128_000
    // The most restrictive approval policy the generated schema supports so the
    // agent must ask before running anything (untrusted / on-request family).
    private static let approvalPolicy = "untrusted"

    private let process: CodexAppServerProcess
    private let workspaceRootResolver: (String) throws -> URL

    private let lock = NSLock()
    private var sessions: [String: Session] = [:]  // keyed by SHA256 scope key
    private var pendingApprovals: [PendingApproval] = []
    private var processedCursor = 0

    private let storeURL: URL

    init(findExecutable: @escaping (String) -> String?,
         workspaceRoot: @escaping (String) throws -> URL) {
        self.process = CodexAppServerProcess(executableLocator: findExecutable)
        self.workspaceRootResolver = workspaceRoot
        self.storeURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Marcellus/codex-app-server-sessions.json")
        loadPersistedSessions()
    }

    // MARK: Scope keying

    /// Combines the caller-provided scope digest and the internal workspace
    /// token, then hashes them so only an opaque key is ever persisted.
    private static func scopeKey(scopeDigest: String, token: String) -> String {
        let combined = "\(scopeDigest):\(token)"
        return SHA256.hash(data: Data(combined.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func requireScope(_ scopeDigest: String) throws {
        guard scopeDigest.range(of: Self.scopeDigestPattern, options: .regularExpression) != nil else {
            throw SessionError.invalid("scope_digest must be a 64-character lowercase hex digest")
        }
    }

    // MARK: start

    func start(scopeDigest: String, token: String, sandbox: String) throws -> [String: Any] {
        try requireScope(scopeDigest)
        guard sandbox == "read-only" || sandbox == "workspace-write" else {
            throw SessionError.invalid("sandbox must be read-only or workspace-write")
        }
        let root: URL
        do {
            root = try workspaceRootResolver(token)
        } catch {
            throw SessionError.invalid("Workspace token is not registered")
        }
        let key = Self.scopeKey(scopeDigest: scopeDigest, token: token)

        lock.lock(); defer { lock.unlock() }

        if !process.isRunning {
            do { try process.start() } catch {
                throw SessionError.invalid("Codex app-server is unavailable")
            }
        }

        var resumed = false
        var threadId = sessions[key]?.threadId

        if let existing = threadId {
            let params: [String: Any] = [
                "threadId": existing,
                "approvalPolicy": Self.approvalPolicy,
                "sandbox": sandbox,
            ]
            do {
                _ = try process.request(method: "thread/resume", params: params)
                resumed = true
            } catch {
                threadId = nil  // resume failed; start a fresh thread below
            }
        }

        if threadId == nil {
            let params: [String: Any] = [
                "cwd": root.path,
                "approvalPolicy": Self.approvalPolicy,
                "sandbox": sandbox,
            ]
            let result = try process.request(method: "thread/start", params: params)
            guard let started = extractId(result, keys: ["threadId", "thread_id"], container: "thread") else {
                throw SessionError.invalid("Codex did not return a thread")
            }
            threadId = started
        }

        let session = Session(
            scopeKey: key,
            threadId: threadId!,
            sandbox: sandbox,
            updatedAt: Date().timeIntervalSince1970,
            currentTurnId: nil,
            interrupted: false,
            turnState: "idle"
        )
        sessions[key] = session
        persistSessions()

        return [
            "status": "running",
            "sandbox": sandbox,
            "resumed": resumed,
            "threadId": threadId!,
        ]
    }

    // MARK: turn

    func turn(scopeDigest: String, token: String, prompt: String) throws -> [String: Any] {
        try requireScope(scopeDigest)
        guard !prompt.isEmpty, prompt.count <= Self.maxPromptLength else {
            throw SessionError.invalid("prompt must be between 1 and 128000 characters")
        }
        let key = Self.scopeKey(scopeDigest: scopeDigest, token: token)

        lock.lock(); defer { lock.unlock() }
        guard var session = sessions[key] else {
            throw SessionError.invalid("No active Codex session; call start first")
        }
        guard process.isRunning else {
            session.interrupted = true
            sessions[key] = session
            throw SessionError.invalid("Codex session is interrupted; call start to resume")
        }

        // The prompt is passed over JSON-RPC stdin only and never journalled.
        let params: [String: Any] = [
            "threadId": session.threadId,
            "input": [["type": "text", "text": prompt]],
        ]
        let result = try process.request(method: "turn/start", params: params)
        let turnId = extractId(result, keys: ["turnId", "turn_id"], container: "turn")
        session.currentTurnId = turnId
        session.turnState = "running"
        session.updatedAt = Date().timeIntervalSince1970
        sessions[key] = session

        var body: [String: Any] = [
            "status": "running",
            "threadId": session.threadId,
            "cursor": currentCursorLocked(),
        ]
        if let turnId { body["turnId"] = turnId }
        return body
    }

    // MARK: status

    func status(scopeDigest: String, token: String, cursor: Int) throws -> [String: Any] {
        try requireScope(scopeDigest)
        let key = Self.scopeKey(scopeDigest: scopeDigest, token: token)

        lock.lock(); defer { lock.unlock() }
        guard let session = sessions[key] else {
            throw SessionError.invalid("No active Codex session; call start first")
        }
        ingestEventsLocked()

        // reflect any turn completion/interruption picked up during ingest.
        let refreshed = sessions[key] ?? session
        let running = process.isRunning && !refreshed.interrupted
        let boundedCursor = max(0, cursor)
        // Only events explicitly scoped to this thread are ever returned. A
        // threadless notification is dropped, never fanned out to every session.
        let safeEvents = process.drainEvents(after: boundedCursor)
            .filter { $0.channel == "notification" || $0.approvalRequestId != nil }
            .filter { event in
                guard let threadId = event.fields["threadId"] as? String else { return false }
                return threadId == refreshed.threadId
            }
            .map { ["cursor": $0.cursor, "channel": $0.channel, "fields": $0.jsonSafe] as [String: Any] }

        // Approvals require an exact thread match; approval_id alone never routes.
        let pending = pendingApprovals
            .filter { $0.threadId == refreshed.threadId }
            .map { approval -> [String: Any] in
                var entry: [String: Any] = ["approval_id": approval.approvalId, "method": approval.method]
                if !approval.detail.isEmpty { entry["detail"] = CodexAppServerProcess.jsonSafe(approval.detail) }
                return entry
            }

        var body: [String: Any] = [
            // Preserve the coarse transport/session verdict for compatibility.
            "status": running ? "running" : "interrupted",
            // Distinguish transport, session, and turn lifecycle explicitly.
            "transport": process.isRunning ? "running" : "interrupted",
            "session": running ? "active" : "interrupted",
            "turn": refreshed.turnState,
            "threadId": refreshed.threadId,
            "cursor": currentCursorLocked(),
            "events": safeEvents,
            "pending_approvals": pending,
        ]
        if let turnId = refreshed.currentTurnId { body["turnId"] = turnId }
        return body
    }

    // MARK: approve

    func approve(scopeDigest: String, token: String, approvalId: String, decision: String) throws -> [String: Any] {
        try requireScope(scopeDigest)
        guard decision == "accept" || decision == "decline" else {
            throw SessionError.invalid("decision must be accept or decline")
        }
        let key = Self.scopeKey(scopeDigest: scopeDigest, token: token)

        lock.lock(); defer { lock.unlock() }
        guard let session = sessions[key] else {
            throw SessionError.invalid("No active Codex session; call start first")
        }
        ingestEventsLocked()
        // The approval must belong to this caller's current thread — approval_id
        // alone is never sufficient to route a decision.
        guard let index = pendingApprovals.firstIndex(where: {
            $0.approvalId == approvalId && $0.threadId == session.threadId
        }) else {
            throw SessionError.invalid("Unknown or already-answered approval")
        }
        let approval = pendingApprovals.remove(at: index)
        guard approval.method != "item/permissions/requestApproval" || decision == "decline" else {
            // The generated permissions response does not provide a safe
            // one-shot grant shape. Keep this request explicitly deny-only.
            pendingApprovals.insert(approval, at: index)
            throw SessionError.invalid("Permissions approvals are deny-only")
        }
        // Respond exactly once with the protocol response shape. We never grant a
        // session-scoped approval, only this single accept/decline decision.
        process.respond(id: approval.requestId, result: approvalResponse(method: approval.method, accept: decision == "accept"))
        return ["status": "ok", "decision": decision]
    }

    // MARK: cancel

    func cancel(scopeDigest: String, token: String) throws -> [String: Any] {
        try requireScope(scopeDigest)
        let key = Self.scopeKey(scopeDigest: scopeDigest, token: token)

        lock.lock(); defer { lock.unlock() }
        guard var session = sessions[key] else {
            throw SessionError.invalid("No active Codex session; call start first")
        }
        guard let turnId = session.currentTurnId, process.isRunning else {
            return ["status": "idle"]
        }
        let params: [String: Any] = ["threadId": session.threadId, "turnId": turnId]
        _ = try? process.request(method: "turn/interrupt", params: params)
        session.currentTurnId = nil
        session.turnState = "interrupted"
        sessions[key] = session
        pendingApprovals.removeAll { $0.threadId == session.threadId }
        return ["status": "interrupted"]
    }

    // MARK: Approval response shapes

    private func approvalResponse(method: String, accept: Bool) -> [String: Any] {
        switch method {
        case "item/permissions/requestApproval":
            // Grant no additional permissions in either case; scope to this turn.
            return ["permissions": [String: Any](), "scope": "turn"]
        default:
            return ["decision": accept ? "accept" : "decline"]
        }
    }

    // MARK: Event ingestion

    private func ingestEventsLocked() {
        let newEvents = process.drainEvents(after: processedCursor)
        for event in newEvents {
            if event.cursor > processedCursor { processedCursor = event.cursor }

            if event.channel == "notification" {
                if let threadId = event.fields["threadId"] as? String,
                   let method = event.fields["method"] as? String {
                    updateTurnStateLocked(threadId: threadId, method: method, fields: event.fields)
                }
                continue
            }

            guard let requestId = event.approvalRequestId,
                  let method = event.approvalMethod else { continue }

            // An allowlisted approval must carry a threadId that matches a known
            // session. Otherwise auto-decline it and never enqueue it.
            guard let threadId = event.fields["threadId"] as? String,
                  sessions.values.contains(where: { $0.threadId == threadId }) else {
                process.respond(id: requestId, result: approvalResponse(method: method, accept: false))
                continue
            }
            pendingApprovals.append(PendingApproval(
                approvalId: "apr-" + UUID().uuidString,
                requestId: requestId,
                method: method,
                threadId: threadId,
                detail: event.approvalDetail ?? [:]
            ))
        }
    }

    /// Marks a turn completed or interrupted from exact turn notifications.
    private func updateTurnStateLocked(threadId: String, method: String, fields: [String: Any]) {
        guard let key = sessions.first(where: { $0.value.threadId == threadId })?.key,
              var session = sessions[key] else { return }
        switch method {
        case "turn/completed":
            let finalStatus = (fields["turnStatus"] as? String ?? "").lowercased()
            switch finalStatus {
            case "completed":
                session.turnState = "completed"
            case "interrupted", "failed", "cancelled", "canceled":
                session.turnState = "interrupted"
            default:
                // Unknown future statuses fail closed rather than presenting an
                // unverified result as completed.
                session.turnState = "interrupted"
            }
            session.currentTurnId = nil
        default:
            return
        }
        sessions[key] = session
    }

    private func currentCursorLocked() -> Int {
        process.drainEvents(after: 0).last?.cursor ?? processedCursor
    }

    // MARK: Result parsing

    private func extractId(_ result: Any?, keys: [String], container: String) -> String? {
        guard let dict = result as? [String: Any] else { return nil }
        for key in keys { if let value = dict[key] as? String { return value } }
        if let nested = dict[container] as? [String: Any], let id = nested["id"] as? String {
            return id
        }
        return nil
    }

    // MARK: Persistence (opaque metadata only, atomic, owner-only)

    private func loadPersistedSessions() {
        guard let data = try? Data(contentsOf: storeURL),
              let records = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return }
        for record in records {
            guard let key = record["scope_key"] as? String,
                  let threadId = record["thread_id"] as? String,
                  let sandbox = record["sandbox"] as? String else { continue }
            let updatedAt = (record["updated_at"] as? NSNumber)?.doubleValue ?? 0
            // A persisted session has no live transport, so it starts interrupted
            // and is resumed on the next start.
            sessions[key] = Session(
                scopeKey: key,
                threadId: threadId,
                sandbox: sandbox,
                updatedAt: updatedAt,
                currentTurnId: nil,
                interrupted: true,
                turnState: "idle"
            )
        }
    }

    private func persistSessions() {
        var records: [[String: Any]] = []
        for session in sessions.values {
            records.append([
                "scope_key": session.scopeKey,
                "thread_id": session.threadId,
                "sandbox": session.sandbox,
                "updated_at": session.updatedAt,
            ])
        }
        guard let data = try? JSONSerialization.data(withJSONObject: records) else { return }
        let directory = storeURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let temp = directory.appendingPathComponent(".codex-app-server-sessions.\(UUID().uuidString).tmp")
        do {
            try data.write(to: temp, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temp.path)
            _ = try FileManager.default.replaceItemAt(storeURL, withItemAt: temp)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storeURL.path)
        } catch {
            try? FileManager.default.removeItem(at: temp)
        }
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
