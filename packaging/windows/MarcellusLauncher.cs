using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class MarcellusLauncher
{
    [STAThread]
    private static void Main()
    {
        string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string launchScript = Path.Combine(appDirectory, "runtime", "Start-Marcellus.ps1");

        if (!File.Exists(launchScript))
        {
            MessageBox.Show(
                "The Marcellus runtime is missing. Reinstall Marcellus.",
                "Marcellus",
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
                "Marcellus could not start: " + exception.Message,
                "Marcellus",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error
            );
        }
    }
}
