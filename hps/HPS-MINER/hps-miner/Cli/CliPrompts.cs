using System.Text;

namespace HpsMiner.Cli;

internal static class CliPrompts
{
    public static string AskText(string label)
    {
        while (true)
        {
            Console.Write($"{label}: ");
            var input = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(input))
            {
                return input.Trim();
            }
        }
    }

    public static bool AskYes(string label)
    {
        Console.Write($"{label}? (y/N): ");
        var input = Console.ReadLine();
        return string.Equals(input?.Trim(), "y", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(input?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
    }

    public static string AskPassword(string label)
    {
        Console.Write($"{label}: ");
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

    public static int AskInt(string label, int min, int max, int defaultValue)
    {
        while (true)
        {
            Console.Write($"{label} [{defaultValue}] ({min}-{max}): ");
            var input = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(input))
            {
                return defaultValue;
            }

            if (int.TryParse(input.Trim(), out var value) && value >= min && value <= max)
            {
                return value;
            }

            Console.WriteLine("Valor invalido.");
        }
    }
}
