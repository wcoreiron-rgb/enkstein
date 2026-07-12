using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class RegentClawLauncher
{
    [STAThread]
    private static void Main()
    {
        string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string launchScript = Path.Combine(appDirectory, "runtime", "Start-RegentClaw.ps1");

        if (!File.Exists(launchScript))
        {
            MessageBox.Show(
                "The RegentClaw runtime is missing. Reinstall RegentClaw.",
                "RegentClaw",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error
            );
            return;
        }

        try
        {
            ProcessStartInfo start = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + launchScript + "\"",
                WorkingDirectory = Path.GetDirectoryName(launchScript),
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Normal
            };
            Process.Start(start);
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                "RegentClaw could not start: " + exception.Message,
                "RegentClaw",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error
            );
        }
    }
}
