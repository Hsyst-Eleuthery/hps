using System;
using System.Collections.Generic;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace HpsBrowser.Converters;

public sealed class ContractRowBackgroundConverter : IMultiValueConverter
{
    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        var isViolation = values.Count > 0 && values[0] is bool b0 && b0;
        var isPending = values.Count > 1 && values[1] is bool b1 && b1;

        if (isViolation)
        {
            return new SolidColorBrush(Color.Parse("#3B1E1E"));
        }
        if (isPending)
        {
            return new SolidColorBrush(Color.Parse("#2A2414"));
        }
        return new SolidColorBrush(Color.Parse("#1A1A1A"));
    }
}
