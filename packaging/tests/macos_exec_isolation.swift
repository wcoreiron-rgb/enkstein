import Foundation
// Mirrors the broker's execWorkspace semantics exactly: minimal env, own
// process group, hardened seatbelt profile, group-wide kill, bounded output.
func runProbe(program: String, arguments: [String], root: URL, timeout: TimeInterval,
              sandbox: Bool = true, cancelAfter: TimeInterval? = nil) -> [String: Any] {
    let process = Process()
    let scratch = root.appendingPathComponent(".marcellus-exec", isDirectory: true)
    try? FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    let environment: [String: String] = [
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": scratch.path, "TMPDIR": scratch.path,
        "LANG": "en_US.UTF-8", "CI": "1", "NO_COLOR": "1",
        "NPM_CONFIG_USERCONFIG": scratch.appendingPathComponent(".npmrc").path,
        "NPM_CONFIG_CACHE": scratch.appendingPathComponent("npm-cache").path,
        "PIP_CONFIG_FILE": scratch.appendingPathComponent("pip.conf").path,
    ]
    let resolvedRoot: String = {
        guard let raw = realpath(root.path, nil) else { return root.path }
        defer { free(raw) }
        return String(cString: raw)
    }()
    let rootParent = URL(fileURLWithPath: resolvedRoot).deletingLastPathComponent().path
    let profile = """
    (version 1)
    (deny default)
    (allow process-exec process-fork sysctl-read mach-lookup)
    (allow file-read-metadata)
    (allow file-read* (literal "/"))
    (allow file-read* (subpath "/usr") (subpath "/bin") (subpath "/sbin"))
    (allow file-read* (subpath "/System") (subpath "/Library"))
    (allow file-read* (subpath "/opt/homebrew") (subpath "/opt/local"))
    (allow file-read* (subpath "/Applications"))
    (allow file-read* (subpath "/private/var/db") (subpath "/private/var/select"))
    (allow file-read* (subpath "/private/etc"))
    (allow file-read* (subpath "/dev"))
    (allow file-read* (literal "\(rootParent)"))
    (allow file-read* (subpath "\(resolvedRoot)"))
    (deny network*)
    (allow file-write* (subpath "\(resolvedRoot)"))
    (allow file-write-data (literal "/dev/null") (literal "/dev/dtracehelper"))
    """
    if sandbox {
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        process.arguments = ["-p", profile, program] + arguments
    } else {
        process.executableURL = URL(fileURLWithPath: program)
        process.arguments = arguments
    }
    process.currentDirectoryURL = root
    process.environment = environment
    process.standardInput = FileHandle.nullDevice
    let captureURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("probe-\(UUID().uuidString).log")
    FileManager.default.createFile(atPath: captureURL.path, contents: nil)
    let capture = try! FileHandle(forWritingTo: captureURL)
    process.standardOutput = capture
    process.standardError = capture
    let started = Date()
    try! process.run()
    let pid = process.processIdentifier
    setpgid(pid, pid)
    let sem = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in sem.signal() }
    var timedOut = false
    var cancelled = false
    if let cancelAfter {
        DispatchQueue.global().asyncAfter(deadline: .now() + cancelAfter) {
            kill(-pid, SIGTERM)
            cancelled = true
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { kill(-pid, SIGKILL) }
        }
    }
    if sem.wait(timeout: .now() + timeout) == .timedOut {
        timedOut = true
        kill(-pid, SIGTERM)
        if sem.wait(timeout: .now() + 5) == .timedOut {
            kill(-pid, SIGKILL)
            _ = sem.wait(timeout: .now() + 5)
        }
    }
    try? capture.synchronize()
    let data = (try? Data(contentsOf: captureURL)) ?? Data()
    var output = String(data: data, encoding: .utf8) ?? ""
    let limit = 20_000
    var truncated = false
    if output.utf8.count > limit { output = String(output.suffix(limit)); truncated = true }
    try? capture.close()
    try? FileManager.default.removeItem(at: captureURL)
    return [
        "success": !timedOut && !cancelled && process.terminationStatus == 0,
        "timed_out": timedOut, "cancelled": cancelled,
        "exit_code": Int(process.terminationStatus),
        "output": output, "truncated": truncated,
        "output_bytes": output.utf8.count,
        "elapsed_ms": Int(Date().timeIntervalSince(started) * 1000),
    ]
}
// Self-provisioning fixture: an approved project root plus a sibling directory
// standing in for another tenant. Both live under one temp parent so the
// "parent is readable but siblings are not" rule is exercised for real.
let base = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("marcellus-exec-tests-\(UUID().uuidString)", isDirectory: true)
let root = base.appendingPathComponent("proj", isDirectory: true)
let otherTenant = base.appendingPathComponent("tenant-b", isDirectory: true)
try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
try? FileManager.default.createDirectory(at: otherTenant, withIntermediateDirectories: true)
let otherSecret = otherTenant.appendingPathComponent("secret.txt").path
try? "OTHER TENANT SECRET".write(toFile: otherSecret, atomically: true, encoding: .utf8)
let outsideWriteTarget = otherTenant.appendingPathComponent("pwned").path
defer { try? FileManager.default.removeItem(at: base) }
let home = FileManager.default.homeDirectoryForCurrentUser.path

var failures: [String] = []
func check(_ name: String, _ condition: Bool, _ detail: String = "") {
    print("\(name.padding(toLength: 30, withPad: " ", startingAt: 0)) \(condition ? "PASS" : "FAIL") \(detail)")
    if !condition { failures.append(name) }
}
let ok = runProbe(program: "/bin/echo", arguments: ["hello"], root: root, timeout: 10)
check("successful_command", ok["success"] as? Bool == true && (ok["output"] as? String ?? "").contains("hello"))
let fail = runProbe(program: "/usr/bin/false", arguments: [], root: root, timeout: 10)
check("failing_command", fail["success"] as? Bool == false && (fail["exit_code"] as? Int ?? 0) != 0,
      "exit=\(fail["exit_code"] ?? -1)")
let slow = runProbe(program: "/bin/sleep", arguments: ["30"], root: root, timeout: 3)
check("timeout", slow["timed_out"] as? Bool == true && (slow["elapsed_ms"] as? Int ?? 0) < 9000,
      "elapsed=\(slow["elapsed_ms"] ?? -1)ms")
let cancelled = runProbe(program: "/bin/sleep", arguments: ["30"], root: root, timeout: 20, cancelAfter: 2)
check("cancellation", cancelled["success"] as? Bool == false && (cancelled["elapsed_ms"] as? Int ?? 0) < 9000,
      "elapsed=\(cancelled["elapsed_ms"] ?? -1)ms")
let marker = root.appendingPathComponent("grandchild.pid").path
try? FileManager.default.removeItem(atPath: marker)
let script = "sleep 60 & echo $! > \(marker); wait"
try? script.write(toFile: root.appendingPathComponent("spawn.sh").path, atomically: true, encoding: .utf8)
let tree = runProbe(program: "/bin/sh", arguments: ["spawn.sh"], root: root, timeout: 4)
Thread.sleep(forTimeInterval: 1.5)
var grandchildAlive = false
if let pidText = try? String(contentsOfFile: marker, encoding: .utf8),
   let gpid = Int32(pidText.trimmingCharacters(in: .whitespacesAndNewlines)) {
    grandchildAlive = kill(gpid, 0) == 0
    print("  grandchild pid=\(gpid) alive=\(grandchildAlive)")
}
check("child_process_cleanup", !grandchildAlive, "timed_out=\(tree["timed_out"] ?? false)")
let big = runProbe(program: "/usr/bin/yes", arguments: ["flood"], root: root, timeout: 3)
check("output_truncation", big["truncated"] as? Bool == true && (big["output_bytes"] as? Int ?? 0) <= 20_000,
      "bytes=\(big["output_bytes"] ?? -1)")
setenv("MARCELLUS_FAKE_SECRET", "SUPERSECRET", 1)
let env = runProbe(program: "/usr/bin/env", arguments: [], root: root, timeout: 10)
let envOut = env["output"] as? String ?? ""
check("env_isolation", !envOut.contains("SUPERSECRET") && !envOut.contains("SSH_AUTH_SOCK"))
let readOutside = runProbe(program: "/bin/cat", arguments: [otherSecret], root: root, timeout: 10)
check("containment_read_denied", readOutside["success"] as? Bool == false)
let writeOutside = runProbe(program: "/usr/bin/touch", arguments: [outsideWriteTarget], root: root, timeout: 10)
check("containment_write_denied", writeOutside["success"] as? Bool == false
      && !FileManager.default.fileExists(atPath: outsideWriteTarget))
let writeInside = runProbe(program: "/usr/bin/touch", arguments: ["allowed.txt"], root: root, timeout: 10)
check("containment_write_allowed", writeInside["success"] as? Bool == true)

// Sensitive host locations an approved command must never be able to read.
for (label, path) in [
    ("ssh_dir", "\(home)/.ssh"),
    ("keychain", "\(home)/Library/Keychains"),
    ("desktop", "\(home)/Desktop"),
    ("aws_credentials", "\(home)/.aws"),
    ("shell_history", "\(home)/.zsh_history"),
] {
    guard FileManager.default.fileExists(atPath: path) else { continue }
    var isDirectory: ObjCBool = false
    _ = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
    // Directories are listed; regular files are read. `ls` on a file only stats
    // it, and metadata is deliberately readable, so it would not prove anything.
    let reader = isDirectory.boolValue ? "/bin/ls" : "/bin/cat"
    let probe = runProbe(program: reader, arguments: [path], root: root, timeout: 10)
    check("deny_read_\(label)", probe["success"] as? Bool == false)
}
print("---RESULT---")
print(failures.isEmpty ? "ALL_PASS" : "FAILURES: \(failures.joined(separator: ", "))")
