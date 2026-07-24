using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace HpsBrowser.Commands;

public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _isRunning;
    private Task? _lastExecutionTask;

    public AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter)
    {
        try
        {
            return !_isRunning && (_canExecute?.Invoke() ?? true);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AsyncRelayCommand.CanExecute] {ex}");
            return false;
        }
    }

    public void Execute(object? parameter)
    {
        _ = ExecuteAsync();
    }

    public async Task ExecuteAsync()
    {
        if (_isRunning)
        {
            return;
        }

        _isRunning = true;
        RaiseCanExecuteChanged();
        try
        {
            _lastExecutionTask = _execute();
            await _lastExecutionTask;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AsyncRelayCommand] {ex}");
        }
        finally
        {
            _isRunning = false;
            RaiseCanExecuteChanged();
        }
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
