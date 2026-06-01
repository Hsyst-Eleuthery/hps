using System;
using System.Windows.Input;

namespace HpsBrowser.Commands;

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = _ => execute();
        _canExecute = canExecute;
    }

    public RelayCommand(Action<object?> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter)
    {
        try
        {
            return _canExecute?.Invoke() ?? true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[RelayCommand.CanExecute] {ex}");
            return false;
        }
    }

    public void Execute(object? parameter)
    {
        try
        {
            _execute(parameter);
        }
        catch (Exception ex)
        {
            // Prevent UI crashes from sync command exceptions.
            Console.Error.WriteLine($"[RelayCommand] {ex}");
        }
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
