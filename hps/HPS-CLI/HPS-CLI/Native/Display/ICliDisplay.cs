namespace Hps.Cli.Native.Display;

public interface ICliDisplay
{
    bool NoCli { get; }
    void PrintHeader(string text);
    void PrintSection(string text);
    void PrintSuccess(string text);
    void PrintError(string text);
    void PrintWarning(string text);
    void PrintInfo(string text);
    void PrintProgress(int current, int total, string text);
    string GetInput(string prompt, bool password = false);
}
