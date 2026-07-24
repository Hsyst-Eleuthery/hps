using System.Text;

namespace Hps.Cli.Native.Display;

public sealed class CliDisplay : ICliDisplay
{
    private readonly int _consoleWidth;
    public bool NoCli { get; }

    public CliDisplay(bool noCli = false)
    {
        NoCli = noCli;
        _consoleWidth = Console.WindowWidth > 0 ? Console.WindowWidth : 80;
    }

    public void PrintHeader(string text)
    {
        if (NoCli)
        {
            Console.WriteLine($"\n{new string('=', 80)}\n{text}\n{new string('=', 80)}");
            return;
        }

        var line = new string('=', Math.Max(20, _consoleWidth - 2));
        Console.WriteLine($"\n{line}");
        Console.WriteLine(text.PadLeft((line.Length + text.Length) / 2).PadRight(line.Length));
        Console.WriteLine(line);
    }

    public void PrintSection(string text)
    {
        Console.WriteLine($"\n{text}");
        Console.WriteLine(new string('-', Math.Max(6, text.Length)));
    }

    public void PrintSuccess(string text) => Console.WriteLine($"[OK] {text}");
    public void PrintError(string text) => Console.WriteLine($"[ERR] {text}");
    public void PrintWarning(string text) => Console.WriteLine($"[WARN] {text}");
    public void PrintInfo(string text) => Console.WriteLine($"[INFO] {text}");

    public void PrintProgress(int current, int total, string text)
    {
        if (total <= 0)
        {
            total = 1;
        }
        current = Math.Max(0, Math.Min(current, total));
        const int barSize = 40;
        var ratio = (double)current / total;
        var done = (int)Math.Round(ratio * barSize);
        var bar = new string('#', done) + new string('-', Math.Max(0, barSize - done));
        var percent = (int)Math.Round(ratio * 100.0);
        Console.Write($"\r[{bar}] {percent,3}% {text}");
        if (current >= total)
        {
            Console.WriteLine();
        }
    }

    public string GetInput(string prompt, bool password = false)
    {
        Console.Write($"{prompt}");
        if (!password)
        {
            return Console.ReadLine() ?? string.Empty;
        }

        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                }
                continue;
            }
            if (!char.IsControl(key.KeyChar))
            {
                sb.Append(key.KeyChar);
            }
        }
        return sb.ToString();
    }
}
