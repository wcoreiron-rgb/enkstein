import Cocoa
import WebKit

private let defaultURL = URL(string: "http://127.0.0.1:3000/marcellus")!

/// Name of the dedicated theme channel. Kept separate from the workspace
/// channel so a change to folder-granting cannot silently break vibrancy.
private let themeMessageHandler = "marcellusTheme"
private let workspaceMessageHandler = "marcellusWorkspace"

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    private var window: NSWindow!
    private var webView: WKWebView!
    private var contentContainer: NSView!
    private var glassView: NSVisualEffectView!
    private var loadingView: NSView!
    private var statusLabel: NSTextField!
    private var spinner: NSProgressIndicator!
    private var launcher: Process?
    private var outputBuffer = Data()
    private var updateCheck: URLSessionDataTask?
    private var statusItem: NSStatusItem?
    /// Last theme reported by the web layer. Retained so the window can be
    /// re-evaluated when the system accessibility setting changes.
    private var currentTheme = "dark"

    func applicationDidFinishLaunching(_ notification: Notification) {
        configureMenu()
        configureStatusItem()
        configureWindow()
        observeReduceTransparency()
        startRuntime()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openConsole(nil)
        return true
    }

    private func configureMenu() {
        let mainMenu = NSMenu()
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About Enkstein", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Check for Updates…", action: #selector(checkForUpdates(_:)), keyEquivalent: "")
        appMenu.addItem(withTitle: "Relaunch Enkstein", action: #selector(relaunchApplication(_:)), keyEquivalent: "r")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Lock Console", action: #selector(lockConsole(_:)), keyEquivalent: "l")
        appMenu.addItem(withTitle: "Quit Console (Runtime Continues)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        NSApp.mainMenu = mainMenu
    }

    private func configureStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Enkstein")
        let menu = NSMenu()
        menu.addItem(withTitle: "Open Enkstein", action: #selector(openConsole(_:)), keyEquivalent: "")
        menu.addItem(withTitle: "Lock Console", action: #selector(lockConsole(_:)), keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        let runtime = NSMenuItem(title: "Runtime active in background", action: nil, keyEquivalent: "")
        runtime.isEnabled = false
        menu.addItem(runtime)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit Console (Runtime Continues)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "")
        item.menu = menu
        statusItem = item
    }

    @objc private func openConsole(_ sender: Any?) {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func lockConsole(_ sender: Any?) {
        webView.evaluateJavaScript("window.dispatchEvent(new Event('marcellus:lock'))")
        openConsole(nil)
    }

    @objc private func relaunchApplication(_ sender: Any?) {
        let script = "sleep 1; /usr/bin/open -n \"$1\""
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", script, "marcellus-relaunch", Bundle.main.bundlePath]
        do {
            try process.run()
            NSApp.terminate(nil)
        } catch {
            showAlert(
                title: "Relaunch failed",
                message: "Enkstein could not relaunch: \(error.localizedDescription)"
            )
        }
    }

    @objc private func checkForUpdates(_ sender: Any?) {
        guard updateCheck == nil else { return }
        guard let repository = Bundle.main.object(forInfoDictionaryKey: "EnksteinGitHubRepository") as? String,
              repository.split(separator: "/").count == 2,
              let url = URL(string: "https://api.github.com/repos/\(repository)/releases/latest") else {
            showAlert(title: "Update feed unavailable", message: "This build does not have a valid GitHub release feed.")
            return
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Enkstein-Desktop", forHTTPHeaderField: "User-Agent")

        updateCheck = URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self else { return }
                self.updateCheck = nil
                if let error {
                    self.showAlert(title: "Could not check for updates", message: error.localizedDescription)
                    return
                }
                let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                guard (200...299).contains(status),
                      let data,
                      let release = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let tag = release["tag_name"] as? String else {
                    self.showAlert(
                        title: "No published release feed",
                        message: "Enkstein could not find a public GitHub Release. Publish a signed release in the configured repository and try again."
                    )
                    return
                }
                self.presentUpdate(release: release, tag: tag)
            }
        }
        updateCheck?.resume()
    }

    private func presentUpdate(release: [String: Any], tag: String) {
        let latest = tag.trimmingCharacters(in: CharacterSet(charactersIn: "vV"))
        let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
        guard latest.compare(current, options: .numeric) == .orderedDescending else {
            showAlert(title: "Enkstein is up to date", message: "Version \(current) is the newest published release.")
            return
        }

        let expectedNames = [
            "Enkstein-\(latest)-macos.pkg",
            "Enkstein-\(tag)-macos.pkg",
            "Marcellus-\(latest)-macos.pkg",
            "Marcellus-\(tag)-macos.pkg",
        ]
        let assets = release["assets"] as? [[String: Any]] ?? []
        let packageURL = assets.first { asset in
            guard let name = asset["name"] as? String else { return false }
            return expectedNames.contains(name)
        }?["browser_download_url"] as? String
        let releaseURL = release["html_url"] as? String

        let alert = NSAlert()
        alert.messageText = "Enkstein \(latest) is available"
        alert.informativeText = packageURL == nil
            ? "The release exists, but it does not contain the expected signed macOS installer."
            : "Download the notarized installer from GitHub. Installing it replaces the current app and preserves your local data."
        if packageURL != nil { alert.addButton(withTitle: "Download Update") }
        if releaseURL != nil { alert.addButton(withTitle: "View Release") }
        alert.addButton(withTitle: "Later")

        let response = alert.runModal()
        if packageURL != nil, response == .alertFirstButtonReturn, let packageURL, let url = URL(string: packageURL) {
            NSWorkspace.shared.open(url)
        } else if let releaseURL,
                  let url = URL(string: releaseURL),
                  (packageURL == nil ? response == .alertFirstButtonReturn : response == .alertSecondButtonReturn) {
            NSWorkspace.shared.open(url)
        }
    }

    private func showAlert(title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func configureWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1380, height: 880),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Enkstein"
        window.titlebarAppearsTransparent = true
        // Start opaque. Vibrancy is switched on only once the web layer
        // reports the Liquid Glass theme, so the splash and the dark/light
        // themes never render against a see-through window.
        window.isOpaque = true
        window.backgroundColor = NSColor.windowBackgroundColor
        window.minSize = NSSize(width: 960, height: 640)
        window.center()

        contentContainer = NSView(frame: window.contentView!.bounds)
        contentContainer.autoresizingMask = [.width, .height]
        // The container must contribute no paint of its own. A layer-backed
        // view with a default background would sit between the effect view
        // and the desktop and defeat the whole arrangement.
        contentContainer.wantsLayer = true
        contentContainer.layer?.backgroundColor = NSColor.clear.cgColor

        glassView = NSVisualEffectView(frame: contentContainer.bounds)
        glassView.autoresizingMask = [.width, .height]
        // .underWindowBackground samples the desktop behind the window, which
        // is what makes the wallpaper visible. .hudWindow is the fallback on
        // older systems where the former is unavailable.
        glassView.material = NSVisualEffectView.Material.underWindowBackground
        glassView.blendingMode = .behindWindow
        glassView.state = .inactive
        glassView.isHidden = true
        contentContainer.addSubview(glassView)

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.userContentController.add(self, name: workspaceMessageHandler)
        configuration.userContentController.add(self, name: themeMessageHandler)
        configuration.userContentController.addUserScript(WKUserScript(
            source: """
            window.marcellusNativeWorkspace = {
              selectFolder: function() {
                window.webkit.messageHandlers.\(workspaceMessageHandler).postMessage({ action: 'selectFolder' });
              }
            };
            (function () {
              var last = null;
              function reportMarcellusTheme() {
                var theme = document.documentElement.dataset.theme || 'dark';
                if (theme === last) return;
                last = theme;
                window.webkit.messageHandlers.\(themeMessageHandler).postMessage({ theme: theme });
              }
              window.marcellusReportTheme = reportMarcellusTheme;
              new MutationObserver(reportMarcellusTheme).observe(
                document.documentElement,
                { attributes: true, attributeFilter: ['data-theme', 'class'] }
              );
              // The theme is applied by a client effect after hydration, so
              // document-start alone is too early to observe the final value.
              document.addEventListener('DOMContentLoaded', reportMarcellusTheme);
              window.addEventListener('load', reportMarcellusTheme);
              window.addEventListener('pageshow', reportMarcellusTheme);
            })();
            """,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        ))
        webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.autoresizingMask = [.width, .height]
        setWebViewDrawsBackground(false)
        contentContainer.addSubview(webView)

        loadingView = NSView(frame: window.contentView!.bounds)
        loadingView.autoresizingMask = [.width, .height]
        loadingView.wantsLayer = true
        loadingView.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor

        let icon = NSImageView()
        icon.image = NSApp.applicationIconImage
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(labelWithString: "Enkstein")
        title.font = .systemFont(ofSize: 30, weight: .semibold)
        title.alignment = .center

        statusLabel = NSTextField(labelWithString: "Preparing the governed runtime...")
        statusLabel.font = .systemFont(ofSize: 14)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.alignment = .center
        statusLabel.maximumNumberOfLines = 2

        spinner = NSProgressIndicator()
        spinner.style = .spinning
        spinner.controlSize = .regular
        spinner.startAnimation(nil)

        let stack = NSStackView(views: [icon, title, statusLabel, spinner])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        loadingView.addSubview(stack)

        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 112),
            icon.heightAnchor.constraint(equalToConstant: 112),
            statusLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 520),
            stack.centerXAnchor.constraint(equalTo: loadingView.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: loadingView.centerYAnchor)
        ])

        window.contentView = loadingView
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func webView(
        _ webView: WKWebView,
        runOpenPanelWith parameters: WKOpenPanelParameters,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping ([URL]?) -> Void
    ) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.canChooseFiles = !parameters.allowsDirectories
        panel.canCreateDirectories = false
        panel.resolvesAliases = true
        panel.beginSheetModal(for: window) { response in
            completionHandler(response == .OK ? panel.urls : nil)
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any] else { return }

        if message.name == themeMessageHandler {
            currentTheme = body["theme"] as? String ?? "dark"
            applyWindowAppearance()
            return
        }

        guard message.name == workspaceMessageHandler,
              body["action"] as? String == "selectFolder" else { return }
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.resolvesAliases = true
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK, let url = panel.url else { return }
            self?.grantWorkspace(url)
        }
    }

    private func grantWorkspace(_ url: URL) {
        let token = UUID().uuidString.lowercased()
        let support = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Marcellus", isDirectory: true)
        let registry = support.appendingPathComponent("workspace-roots.json")
        do {
            try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
            var roots: [String: [String: String]] = [:]
            if let data = try? Data(contentsOf: registry),
               let stored = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] {
                roots = stored
            }
            roots[token] = ["path": url.resolvingSymlinksInPath().path, "name": url.lastPathComponent]
            let data = try JSONSerialization.data(withJSONObject: roots, options: [.sortedKeys])
            try data.write(to: registry, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: registry.path)
            let payload = try JSONSerialization.data(withJSONObject: ["token": token, "name": url.lastPathComponent])
            let json = String(data: payload, encoding: .utf8) ?? "{}"
            webView.evaluateJavaScript("window.dispatchEvent(new CustomEvent('marcellus:native-workspace-selected', { detail: \(json) }));")
        } catch {
            showAlert(title: "Folder access failed", message: "Enkstein could not create a protected workspace grant.")
        }
    }

    private func startRuntime() {
        guard let helper = Bundle.main.resourceURL?.appendingPathComponent("launcher.sh") else {
            showFailure("The desktop launcher is missing. Reinstall Enkstein.")
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [helper.path]
        var environment = ProcessInfo.processInfo.environment
        environment["MARCELLUS_EMBEDDED"] = "1"
        process.environment = environment

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            DispatchQueue.main.async { self?.consumeOutput(data) }
        }

        process.terminationHandler = { [weak self] completed in
            pipe.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async {
                if completed.terminationStatus == 0 {
                    self?.waitForDesktop()
                } else {
                    self?.showFailure("Enkstein could not start. Open Help > Startup Log for details.")
                }
            }
        }

        do {
            launcher = process
            try process.run()
        } catch {
            showFailure("Enkstein could not launch its local runtime: \(error.localizedDescription)")
        }
    }

    private func consumeOutput(_ data: Data) {
        outputBuffer.append(data)
        while let newline = outputBuffer.firstIndex(of: 0x0A) {
            let lineData = outputBuffer.prefix(upTo: newline)
            outputBuffer.removeSubrange(...newline)
            guard let line = String(data: lineData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !line.isEmpty else { continue }
            statusLabel.stringValue = line.replacingOccurrences(of: "ERROR: ", with: "")
        }
    }

    private func waitForDesktop(attempt: Int = 0) {
        let endpoint = desktopURL()
        var request = URLRequest(url: endpoint)
        request.timeoutInterval = 3
        URLSession.shared.dataTask(with: request) { [weak self] _, response, _ in
            let ready = (response as? HTTPURLResponse).map { (200...499).contains($0.statusCode) } ?? false
            DispatchQueue.main.async {
                if ready {
                    self?.showLogin(from: endpoint)
                } else if attempt < 180 {
                    self?.statusLabel.stringValue = "Waiting for the Enkstein desktop..."
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                        self?.waitForDesktop(attempt: attempt + 1)
                    }
                } else {
                    self?.showFailure("The local Enkstein desktop did not become ready.")
                }
            }
        }.resume()
    }

    private func desktopURL() -> URL {
        let endpointFile = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Marcellus/ui-url")
        guard let value = try? String(contentsOf: endpointFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              let url = URL(string: value) else {
            return defaultURL
        }
        return url
    }

    private func showLogin(from desktopURL: URL) {
        var components = URLComponents(url: desktopURL, resolvingAgainstBaseURL: false)
        components?.path = "/login"
        components?.query = nil
        components?.fragment = nil
        showDesktop(components?.url ?? desktopURL)
    }

    private func showDesktop(_ url: URL) {
        spinner.stopAnimation(nil)
        window.contentView = contentContainer
        webView.frame = contentContainer.bounds
        webView.load(URLRequest(url: url))
    }

    /// Whether the user has asked the system to avoid transparency. Honoring
    /// this is not optional: vibrancy reduces contrast, and someone who turned
    /// it off did so because the effect makes the interface hard to read.
    private var reduceTransparencyEnabled: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency
    }

    private func observeReduceTransparency() {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.applyWindowAppearance()
        }
    }

    /// WKWebView exposes no public `drawsBackground`, but the underlying
    /// property is honored and is the arrangement used by transparent WebKit
    /// shells. `setValue(_:forKey:)` on a missing key would raise, so the call
    /// is guarded rather than assumed.
    private func setWebViewDrawsBackground(_ draws: Bool) {
        guard webView.responds(to: NSSelectorFromString("setDrawsBackground:"))
            || webView.value(forKey: "drawsBackground") != nil else { return }
        webView.setValue(draws, forKey: "drawsBackground")
    }

    /// Applies native vibrancy for Liquid Glass and restores a conventional
    /// opaque window for every other theme.
    private func applyWindowAppearance() {
        let wantsGlass = currentTheme == "liquid" && !reduceTransparencyEnabled

        glassView.isHidden = !wantsGlass
        glassView.state = wantsGlass ? .active : .inactive
        window.isOpaque = !wantsGlass
        window.backgroundColor = wantsGlass ? .clear : NSColor.windowBackgroundColor
        window.hasShadow = true
        setWebViewDrawsBackground(!wantsGlass)

        // The web layer keeps its own translucent surfaces; only the document
        // itself needs to stop painting, and that is handled in CSS. Match the
        // titlebar so the window chrome does not read as a separate opaque
        // strip above a transparent body.
        window.titlebarAppearsTransparent = true
        window.appearance = wantsGlass ? NSAppearance(named: .vibrantLight) : nil
    }

    private func showFailure(_ message: String) {
        spinner.stopAnimation(nil)
        statusLabel.textColor = .systemRed
        statusLabel.stringValue = message
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        let localHosts = Set(["127.0.0.1", "localhost"])
        if let host = url.host, !localHosts.contains(host) {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        showFailure("The desktop view could not load: \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        showFailure("The desktop view could not connect: \(error.localizedDescription)")
    }
}

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
