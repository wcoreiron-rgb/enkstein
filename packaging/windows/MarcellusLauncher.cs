// Enkstein native Windows host.
//
// This window embeds WebView2 directly rather than launching a browser. A
// browser tab cannot be made transparent, so desktop-composited backdrops
// (Mica and Acrylic) are only reachable from a host window we own.
//
// Backdrop selection is driven by the theme the web layer reports: Liquid
// Glass asks the Desktop Window Manager for a system backdrop and clears the
// WebView2 background so the composited surface shows through; every other
// theme keeps a conventional opaque window.
using System;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

internal static class NativeMethods
{
    // Documented DWM window attributes. SYSTEMBACKDROP_TYPE and the immersive
    // dark mode attribute both require Windows 11 build 22621 or later; the
    // calls fail harmlessly with an HRESULT on older systems, which is why
    // every result is checked rather than assumed.
    internal const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    internal const int DWMWA_SYSTEMBACKDROP_TYPE = 38;

    // DWM_SYSTEMBACKDROP_TYPE
    internal const int DWMSBT_AUTO = 0;
    internal const int DWMSBT_NONE = 1;
    internal const int DWMSBT_MAINWINDOW = 2;      // Mica
    internal const int DWMSBT_TRANSIENTWINDOW = 3; // Acrylic
    internal const int DWMSBT_TABBEDWINDOW = 4;    // Mica Alt

    [DllImport("dwmapi.dll", PreserveSig = true)]
    internal static extern int DwmSetWindowAttribute(
        IntPtr hwnd, int attribute, ref int value, int size);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    internal static extern int DwmExtendFrameIntoClientArea(IntPtr hwnd, ref MARGINS margins);

    // Without an explicit AppUserModelID the shell derives one from the process
    // path. Pinning then binds to that derived identity, so a pinned tile can
    // stop matching the running window after an upgrade and the taskbar shows a
    // duplicate ungrouped button. Setting it before any window is created keeps
    // pinning, jump lists, and grouping stable across versions.
    [DllImport("shell32.dll", PreserveSig = true)]
    internal static extern int SetCurrentProcessExplicitAppUserModelID(
        [MarshalAs(UnmanagedType.LPWStr)] string appID);

    [StructLayout(LayoutKind.Sequential)]
    internal struct MARGINS
    {
        public int Left;
        public int Right;
        public int Top;
        public int Bottom;
    }
}

/// Shared product identity. The installer registers the same string, so the
/// shortcut's System.AppUserModel.ID matches the running process.
internal static class AppIdentity
{
    internal const string AppUserModelId = "Enkstein.Desktop";
    internal const string ProductName = "Enkstein";
}

/// Theme + glass level persisted for the native host.
///
/// The web layer owns the setting and persists its own copy; the host keeps a
/// mirror so it can paint the correct opaque surface on the very first frame,
/// before WebView2 has loaded anything. Without that mirror the window shows a
/// flash of the wrong colour on every launch.
internal static class ThemeState
{
    private const string Key = @"HKEY_CURRENT_USER\Software\Enkstein";

    internal static string Load(out string glassLevel)
    {
        glassLevel = "balanced";
        string theme = "dark";
        try
        {
            object storedTheme = Microsoft.Win32.Registry.GetValue(Key, "Theme", "dark");
            if (storedTheme != null)
            {
                string candidate = Convert.ToString(storedTheme, CultureInfo.InvariantCulture);
                if (candidate == "light" || candidate == "dark" || candidate == "liquid") theme = candidate;
            }
            object storedLevel = Microsoft.Win32.Registry.GetValue(Key, "GlassLevel", "balanced");
            if (storedLevel != null)
            {
                string candidate = Convert.ToString(storedLevel, CultureInfo.InvariantCulture);
                if (candidate == "subtle" || candidate == "balanced" || candidate == "clear") glassLevel = candidate;
            }
        }
        catch (Exception)
        {
            // A missing or unreadable key is not fatal; the defaults apply.
        }
        return theme;
    }

    internal static void Save(string theme, string glassLevel)
    {
        try
        {
            Microsoft.Win32.Registry.SetValue(Key, "Theme", theme);
            Microsoft.Win32.Registry.SetValue(Key, "GlassLevel", glassLevel);
        }
        catch (Exception)
        {
            // Persistence is a convenience; failing to write must not break the app.
        }
    }
}

internal sealed class EnksteinWindow : Form
{
    private const string DefaultUrl = "http://localhost:3000";

    // Explicit surfaces rather than SystemColors.Control, which is a grey the
    // web layer never uses. Matching the web palette exactly is what keeps the
    // window from flashing a mismatched colour before the page paints, and
    // keeps Windows looking like the macOS app.
    private static readonly Color LightSurface = Color.FromArgb(0xF8, 0xFA, 0xFC);
    private static readonly Color DarkSurface = Color.FromArgb(0x03, 0x07, 0x12);

    private readonly WebView2 _webView = new WebView2();
    private readonly Label _status = new Label();
    private readonly FlowLayoutPanel _startupActions = new FlowLayoutPanel();
    private readonly Button _retry = new Button();
    private readonly Button _openDocker = new Button();
    private readonly Button _installDocker = new Button();
    private readonly Button _openLog = new Button();
    private Process _runtimeProcess;
    private bool _runtimeStarting;
    private string _theme = "dark";
    private string _glassLevel = "balanced";
    private bool _backdropActive;

    /// The opaque surface for the current non-glass theme.
    private Color OpaqueSurface
    {
        get { return _theme == "light" ? LightSurface : DarkSurface; }
    }

    internal EnksteinWindow()
    {
        Text = AppIdentity.ProductName;
        MinimumSize = new Size(960, 640);
        ClientSize = new Size(1380, 880);
        StartPosition = FormStartPosition.CenterScreen;
        // Start opaque on the saved theme's surface. Beginning transparent (or
        // on a system grey) is what produces the black/white flash before the
        // web layer reports its theme.
        _theme = ThemeState.Load(out _glassLevel);
        BackColor = OpaqueSurface;
        ForeColor = _theme == "light"
            ? Color.FromArgb(0x0F, 0x17, 0x2A)
            : Color.FromArgb(0xE2, 0xE8, 0xF0);

        _status.Dock = DockStyle.Fill;
        _status.TextAlign = ContentAlignment.MiddleCenter;
        _status.Text = "Preparing the governed runtime...";
        Controls.Add(_status);

        _startupActions.Dock = DockStyle.Bottom;
        _startupActions.Height = 44;
        _startupActions.FlowDirection = FlowDirection.LeftToRight;
        _startupActions.WrapContents = false;
        _startupActions.Padding = new Padding(0, 8, 0, 8);
        _startupActions.Visible = false;
        _retry.Text = "Retry";
        _openDocker.Text = "Open Docker";
        _installDocker.Text = "Install Docker";
        _openLog.Text = "Open Startup Log";
        _retry.Click += delegate { RetryStartup(); };
        _openDocker.Click += delegate { OpenDocker(); };
        _installDocker.Click += delegate { OpenDockerInstall(); };
        _openLog.Click += delegate { OpenStartupLog(); };
        _startupActions.Controls.AddRange(new Control[] { _retry, _openDocker, _installDocker, _openLog });
        Controls.Add(_startupActions);

        _webView.Dock = DockStyle.Fill;
        // Keep the first WebView2 paint on the same opaque surface as the native
        // window. The page may later switch to transparent for Liquid Glass,
        // but it must never flash WebView2's default white while the runtime and
        // theme bridge are starting.
        _webView.DefaultBackgroundColor = OpaqueSurface;
        _webView.Visible = false;
        Controls.Add(_webView);
        _startupActions.BringToFront();

        try
        {
            // Use the canonical ICO directly so the native window preserves
            // the rounded alpha corners instead of relying on executable icon
            // extraction, which can flatten the artwork on some Windows builds.
            string icon = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Enkstein.ico");
            if (!File.Exists(icon)) icon = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Enkstein.exe");
            if (File.Exists(icon)) Icon = Icon.ExtractAssociatedIcon(icon);
        }
        catch (Exception)
        {
            // A missing icon must never prevent the console from opening.
        }
    }

    protected override async void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        try
        {
            await StartRuntimeAsync();
        }
        catch (Exception exception)
        {
            _runtimeStarting = false;
            ShowFailure(exception.Message);
        }
    }

    private async Task StartRuntimeAsync()
    {
        if (_runtimeStarting) return;
        _runtimeStarting = true;
        _startupActions.Visible = false;
        _status.ForeColor = ForeColor;
        _status.Text = "Checking Docker Desktop...";
        string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string launchScript = Path.Combine(appDirectory, "runtime", "Start-Enkstein.ps1");
        if (!File.Exists(launchScript))
        {
            ShowFailure("The Enkstein runtime is missing. Reinstall Enkstein.");
            _runtimeStarting = false;
            return;
        }

        if (!await EnsureWebView2RuntimeAsync())
        {
            _runtimeStarting = false;
            return;
        }

        ProcessStartInfo start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + launchScript + "\"",
            WorkingDirectory = Path.GetDirectoryName(launchScript),
            UseShellExecute = false,
            CreateNoWindow = true
        };
        // Tells the startup script that a native host is rendering the console,
        // so it does not also open a browser window.
        start.EnvironmentVariables["ENKSTEIN_EMBEDDED"] = "1";
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        _runtimeProcess = Process.Start(start);
        if (_runtimeProcess != null)
        {
            _runtimeProcess.OutputDataReceived += delegate(object sender, DataReceivedEventArgs args) { HandleStartupOutput(args.Data); };
            _runtimeProcess.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs args) { HandleStartupOutput(args.Data); };
            _runtimeProcess.BeginOutputReadLine();
            _runtimeProcess.BeginErrorReadLine();
        }

        _status.Text = "Waiting for the Enkstein desktop...";
        string url = await WaitForDesktopAsync();
        if (url == null)
        {
            ShowFailure("The local Enkstein desktop did not become ready.");
            _runtimeStarting = false;
            return;
        }

        await InitializeWebViewAsync(url);
        _runtimeStarting = false;
    }

    private void HandleStartupOutput(string line)
    {
        if (String.IsNullOrWhiteSpace(line)) return;
        Action update = delegate
        {
            const string prefix = "ENKSTEIN_DOCKER_STATE=";
            if (line.StartsWith(prefix, StringComparison.Ordinal))
            {
                string payload = line.Substring(prefix.Length);
                string[] fields = payload.Split(new[] { '|' }, 2);
                string state = fields[0];
                string detail = fields.Length > 1 ? fields[1] : "Docker Desktop status unavailable.";
                _status.Text = detail;
                _startupActions.Visible = true;
                _retry.Visible = true;
                _openDocker.Visible = state != "missing";
                _installDocker.Visible = state == "missing";
                _openLog.Visible = true;
                return;
            }
            _status.Text = line.Replace("ERROR: ", String.Empty);
        };
        if (IsHandleCreated && InvokeRequired) BeginInvoke(update); else update();
    }

    private void RetryStartup()
    {
        // Kill(bool) is .NET Core only; the installer compiles against the
        // .NET Framework 4 csc shipped with Windows, so terminate the process
        // itself and let the runtime script's own cleanup reap its children.
        try { if (_runtimeProcess != null && !_runtimeProcess.HasExited) _runtimeProcess.Kill(); } catch { }
        _runtimeProcess = null;
        _startupActions.Visible = false;
        StartRuntimeAsync();
    }

    private void OpenDocker()
    {
        foreach (string candidate in DockerDesktopCandidates())
            if (File.Exists(candidate)) { Process.Start(candidate); return; }
    }

    private void OpenDockerInstall()
    {
        Process.Start(new ProcessStartInfo { FileName = "https://www.docker.com/products/docker-desktop/", UseShellExecute = true });
    }

    private void OpenStartupLog()
    {
        string log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Enkstein", "logs", "launcher.log");
        if (File.Exists(log)) Process.Start(new ProcessStartInfo { FileName = "notepad.exe", Arguments = "\"" + log + "\"", UseShellExecute = true });
    }

    private static string[] DockerDesktopCandidates()
    {
        return new[] {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Docker", "Docker", "Docker Desktop.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Docker", "Docker", "Docker Desktop.exe")
        };
    }

    /// WebView2 is a separate runtime. Detecting it explicitly gives a real
    /// instruction instead of an unhandled exception on a machine without it.
    private async Task<bool> EnsureWebView2RuntimeAsync()
    {
        try
        {
            CoreWebView2Environment.GetAvailableBrowserVersionString();
            await Task.CompletedTask;
            return true;
        }
        catch (WebView2RuntimeNotFoundException)
        {
            DialogResult choice = MessageBox.Show(
                "Enkstein needs the Microsoft Edge WebView2 runtime, which is not installed on this machine.\r\n\r\n" +
                "Open the Microsoft download page now?",
                "Enkstein",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (choice == DialogResult.Yes)
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://developer.microsoft.com/microsoft-edge/webview2/",
                    UseShellExecute = true
                });
            }
            Close();
            return false;
        }
    }

    /// Reads the console URL published by the startup script, then waits for
    /// it to answer before showing the web view.
    private async Task<string> WaitForDesktopAsync()
    {
        string stateFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Enkstein",
            "ui-url");

        using (System.Net.Http.HttpClient client = new System.Net.Http.HttpClient())
        {
            client.Timeout = TimeSpan.FromSeconds(3);
            for (int attempt = 0; attempt < 180; attempt++)
            {
                string url = DefaultUrl;
                try
                {
                    if (File.Exists(stateFile))
                    {
                        string stored = File.ReadAllText(stateFile).Trim();
                        if (stored.Length > 0) url = stored;
                    }
                }
                catch (IOException)
                {
                    // The file is being rewritten; retry on the next pass.
                }

                try
                {
                    System.Net.Http.HttpResponseMessage response =
                        await client.GetAsync(url + "/login");
                    if ((int)response.StatusCode < 500) return url;
                }
                catch (Exception)
                {
                    // Not listening yet.
                }
                await Task.Delay(1000);
            }
        }
        return null;
    }

    private async Task InitializeWebViewAsync(string url)
    {
        string userData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Enkstein",
            "WebView2");
        Directory.CreateDirectory(userData);

        CoreWebView2Environment environment =
            await CoreWebView2Environment.CreateAsync(null, userData, null);
        await _webView.EnsureCoreWebView2Async(environment);

        // Theme bridge. The page posts its active theme and glass level, and the
        // host maps them onto a DWM backdrop. The level rides on the same
        // message so the two states can never disagree.
        _webView.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(
            "(function () {" +
            "  var last = null;" +
            "  function report() {" +
            "    var theme = document.documentElement.dataset.theme || 'dark';" +
            "    var level = document.documentElement.dataset.glass || 'balanced';" +
            "    var key = theme + ':' + level;" +
            "    if (key === last) return;" +
            "    last = key;" +
            "    window.chrome.webview.postMessage(" +
            "      { channel: 'theme', theme: theme, glass: level });" +
            "  }" +
            "  new MutationObserver(report).observe(document.documentElement," +
            "    { attributes: true, attributeFilter: ['data-theme', 'data-glass', 'class'] });" +
            "  document.addEventListener('DOMContentLoaded', report);" +
            "  window.addEventListener('load', report);" +
            "  window.addEventListener('pageshow', report);" +
            "})();");

        _webView.CoreWebView2.WebMessageReceived += OnWebMessageReceived;
        _webView.CoreWebView2.NewWindowRequested += OnNewWindowRequested;

        _status.Visible = false;
        _startupActions.Visible = false;
        _webView.Visible = true;
        _webView.CoreWebView2.Navigate(url + "/login");
    }

    /// External links open in the user's browser; the host stays on the local
    /// console, matching the macOS navigation policy.
    private void OnNewWindowRequested(object sender, CoreWebView2NewWindowRequestedEventArgs e)
    {
        e.Handled = true;
        try
        {
            Process.Start(new ProcessStartInfo { FileName = e.Uri, UseShellExecute = true });
        }
        catch (Exception)
        {
            // An unopenable URI must not take the console down.
        }
    }

    private void OnWebMessageReceived(object sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        string json;
        try
        {
            json = e.WebMessageAsJson;
        }
        catch (Exception)
        {
            return;
        }
        if (json == null || json.IndexOf("\"theme\"", StringComparison.Ordinal) < 0) return;

        // Preserve the concrete theme rather than collapsing to "opaque": the
        // host needs light vs dark to pick the right surface colour and title
        // bar treatment, not merely "is this glass".
        if (json.IndexOf("\"liquid\"", StringComparison.OrdinalIgnoreCase) >= 0) _theme = "liquid";
        else if (json.IndexOf("\"light\"", StringComparison.OrdinalIgnoreCase) >= 0) _theme = "light";
        else _theme = "dark";

        if (json.IndexOf("\"subtle\"", StringComparison.OrdinalIgnoreCase) >= 0) _glassLevel = "subtle";
        else if (json.IndexOf("\"clear\"", StringComparison.OrdinalIgnoreCase) >= 0) _glassLevel = "clear";
        else _glassLevel = "balanced";

        ThemeState.Save(_theme, _glassLevel);
        ApplyWindowAppearance();
    }

    /// True only on Windows 11 22621+, where DWMWA_SYSTEMBACKDROP_TYPE exists.
    private static bool SupportsSystemBackdrop
    {
        get
        {
            OperatingSystem os = Environment.OSVersion;
            return os.Platform == PlatformID.Win32NT
                && os.Version.Major >= 10
                && os.Version.Build >= 22621;
        }
    }

    /// Whether the user has transparency effects turned off in Settings.
    /// Forcing Acrylic over that preference would be the Windows equivalent of
    /// ignoring Reduce Transparency on macOS.
    private static bool TransparencyEffectsEnabled
    {
        get
        {
            try
            {
                object value = Microsoft.Win32.Registry.GetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                    "EnableTransparency",
                    1);
                return value == null || Convert.ToInt32(value, CultureInfo.InvariantCulture) != 0;
            }
            catch (Exception)
            {
                return true;
            }
        }
    }

    private void ApplyWindowAppearance()
    {
        bool wantsGlass = _theme == "liquid"
            && SupportsSystemBackdrop
            && TransparencyEffectsEnabled;

        // Keep the title bar in step with the theme. Without this, light mode
        // keeps a dark caption (or the reverse) and the window stops matching
        // the macOS app.
        int darkTitleBar = (_theme == "light") ? 0 : 1;
        NativeMethods.DwmSetWindowAttribute(
            Handle, NativeMethods.DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkTitleBar, sizeof(int));

        // Deliberately not short-circuiting on `wantsGlass == _backdropActive`:
        // switching light <-> dark leaves both sides non-glass, yet the surface
        // colour and caption still have to change.
        Color surface = OpaqueSurface;

        // Acrylic samples the desktop more aggressively than Mica, so the
        // clearer levels use it while "subtle" stays on Mica, which tints
        // toward the desktop without really revealing it. This is the practical
        // equivalent of a transparency slider: DWM exposes discrete materials
        // rather than an alpha value, and both are within an accessible range.
        int backdrop;
        if (!wantsGlass) backdrop = NativeMethods.DWMSBT_NONE;
        else if (_glassLevel == "subtle") backdrop = NativeMethods.DWMSBT_MAINWINDOW;
        else backdrop = NativeMethods.DWMSBT_TRANSIENTWINDOW;

        int applied = NativeMethods.DwmSetWindowAttribute(
            Handle, NativeMethods.DWMWA_SYSTEMBACKDROP_TYPE, ref backdrop, sizeof(int));
        if (applied != 0)
        {
            // The attribute was rejected, so there is no composited surface to
            // show through. Stay opaque rather than clearing to a black window.
            _backdropActive = false;
            BackColor = surface;
            SetWebViewBackground(surface);
            ReportGlassAvailability(false);
            return;
        }

        // Extending the frame is what lets the backdrop reach the client area.
        NativeMethods.MARGINS margins = wantsGlass
            ? new NativeMethods.MARGINS { Left = -1, Right = -1, Top = -1, Bottom = -1 }
            : new NativeMethods.MARGINS();
        NativeMethods.DwmExtendFrameIntoClientArea(Handle, ref margins);

        // A transparent WebView2 background is the second half of the effect:
        // without it the control paints over the backdrop and the desktop never
        // shows through, however correct the DWM state is.
        BackColor = surface;
        SetWebViewBackground(wantsGlass ? Color.Transparent : surface);

        _backdropActive = wantsGlass;
        // Only meaningful while the liquid theme is selected; for opaque themes
        // the page ignores it.
        ReportGlassAvailability(_theme != "liquid" || wantsGlass);
    }

    /// Tell the page when Liquid Glass was requested but could not be applied
    /// (pre-22621 Windows, transparency effects disabled, or a rejected DWM
    /// attribute). Without this the web layer would keep painting translucent
    /// panels over an opaque native window, which reads as a washed-out UI
    /// rather than glass. The page collapses to an opaque surface instead.
    private void ReportGlassAvailability(bool available)
    {
        if (_webView.CoreWebView2 == null) return;
        try
        {
            _webView.CoreWebView2.ExecuteScriptAsync(
                "document.documentElement.dataset.glassAvailable = '"
                + (available ? "1" : "0") + "';"
                + "if (!" + (available ? "true" : "false")
                + " && document.documentElement.dataset.theme === 'liquid')"
                + " { document.documentElement.dataset.glass = 'off'; }");
        }
        catch (Exception)
        {
            // Reporting is best-effort; a failure here must not break theming.
        }
    }

    /// WebView2 rejects a background change before the core is created, which
    /// happens on the first paint during startup.
    private void SetWebViewBackground(Color color)
    {
        try
        {
            _webView.DefaultBackgroundColor = color;
        }
        catch (Exception)
        {
            // Applied again once the core is ready.
        }
    }

    private void ShowFailure(string message)
    {
        _webView.Visible = false;
        _status.Visible = true;
        _startupActions.Visible = true;
        _retry.Visible = true;
        _openDocker.Visible = true;
        _installDocker.Visible = false;
        _openLog.Visible = true;
        _status.ForeColor = Color.Firebrick;
        _status.Text = message;
    }
}

internal static class EnksteinLauncher
{
    [STAThread]
    private static void Main()
    {
        // Must run before any window is created, otherwise the shell has
        // already derived an identity from the process path and pinning binds
        // to that instead.
        try
        {
            NativeMethods.SetCurrentProcessExplicitAppUserModelID(AppIdentity.AppUserModelId);
        }
        catch (Exception)
        {
            // Older shells without the export still run; only pinning fidelity
            // is affected, so this must not block startup.
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        try
        {
            Application.Run(new EnksteinWindow());
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                "Enkstein could not start: " + exception.Message,
                AppIdentity.ProductName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}
