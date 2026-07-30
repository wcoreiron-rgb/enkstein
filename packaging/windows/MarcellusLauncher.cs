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

    [StructLayout(LayoutKind.Sequential)]
    internal struct MARGINS
    {
        public int Left;
        public int Right;
        public int Top;
        public int Bottom;
    }
}

internal sealed class EnksteinWindow : Form
{
    private const string DefaultUrl = "http://localhost:3000";

    private readonly WebView2 _webView = new WebView2();
    private readonly Label _status = new Label();
    private string _theme = "dark";
    private bool _backdropActive;

    internal EnksteinWindow()
    {
        Text = "Enkstein";
        MinimumSize = new Size(960, 640);
        ClientSize = new Size(1380, 880);
        StartPosition = FormStartPosition.CenterScreen;
        // The host paints black while a backdrop is active: DWM treats black
        // as the transparency key for a frame extended into the client area.
        BackColor = SystemColors.Control;

        _status.Dock = DockStyle.Fill;
        _status.TextAlign = ContentAlignment.MiddleCenter;
        _status.Text = "Preparing the governed runtime...";
        Controls.Add(_status);

        _webView.Dock = DockStyle.Fill;
        _webView.Visible = false;
        Controls.Add(_webView);

        try
        {
            string icon = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Enkstein.exe");
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
            ShowFailure(exception.Message);
        }
    }

    private async Task StartRuntimeAsync()
    {
        string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string launchScript = Path.Combine(appDirectory, "runtime", "Start-Enkstein.ps1");
        if (!File.Exists(launchScript))
        {
            ShowFailure("The Enkstein runtime is missing. Reinstall Enkstein.");
            return;
        }

        if (!await EnsureWebView2RuntimeAsync()) return;

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
        Process.Start(start);

        _status.Text = "Waiting for the Enkstein desktop...";
        string url = await WaitForDesktopAsync();
        if (url == null)
        {
            ShowFailure("The local Enkstein desktop did not become ready.");
            return;
        }

        await InitializeWebViewAsync(url);
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

        // Theme bridge. The page posts its active theme, and the host maps it
        // onto a DWM backdrop.
        _webView.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(
            "(function () {" +
            "  var last = null;" +
            "  function report() {" +
            "    var theme = document.documentElement.dataset.theme || 'dark';" +
            "    if (theme === last) return;" +
            "    last = theme;" +
            "    window.chrome.webview.postMessage({ channel: 'theme', theme: theme });" +
            "  }" +
            "  new MutationObserver(report).observe(document.documentElement," +
            "    { attributes: true, attributeFilter: ['data-theme', 'class'] });" +
            "  document.addEventListener('DOMContentLoaded', report);" +
            "  window.addEventListener('load', report);" +
            "  window.addEventListener('pageshow', report);" +
            "})();");

        _webView.CoreWebView2.WebMessageReceived += OnWebMessageReceived;
        _webView.CoreWebView2.NewWindowRequested += OnNewWindowRequested;

        _status.Visible = false;
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

        _theme = json.IndexOf("liquid", StringComparison.OrdinalIgnoreCase) >= 0 ? "liquid" : "opaque";
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

        if (wantsGlass == _backdropActive) return;

        int backdrop = wantsGlass
            ? NativeMethods.DWMSBT_TRANSIENTWINDOW  // Acrylic: samples the desktop
            : NativeMethods.DWMSBT_NONE;
        int applied = NativeMethods.DwmSetWindowAttribute(
            Handle, NativeMethods.DWMWA_SYSTEMBACKDROP_TYPE, ref backdrop, sizeof(int));
        if (applied != 0)
        {
            // The attribute was rejected, so there is no composited surface to
            // show through. Stay opaque rather than clearing to a black window.
            _backdropActive = false;
            _webView.DefaultBackgroundColor = SystemColors.Control;
            return;
        }

        // Extending the frame is what lets the backdrop reach the client area.
        NativeMethods.MARGINS margins = wantsGlass
            ? new NativeMethods.MARGINS { Left = -1, Right = -1, Top = -1, Bottom = -1 }
            : new NativeMethods.MARGINS();
        NativeMethods.DwmExtendFrameIntoClientArea(Handle, ref margins);

        // A transparent WebView2 background is the second half of the effect:
        // without it the control paints white over the backdrop.
        _webView.DefaultBackgroundColor = wantsGlass
            ? Color.Transparent
            : SystemColors.Control;

        _backdropActive = wantsGlass;
    }

    private void ShowFailure(string message)
    {
        _webView.Visible = false;
        _status.Visible = true;
        _status.ForeColor = Color.Firebrick;
        _status.Text = message;
    }
}

internal static class EnksteinLauncher
{
    [STAThread]
    private static void Main()
    {
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
                "Enkstein",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}
