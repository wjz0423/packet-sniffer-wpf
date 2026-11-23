using System.Text;

namespace PacketSniffer.App.Infrastructure;

public static class HexFormatter
{
    public static string Format(IReadOnlyList<byte> bytes, int bytesPerLine = 16, int maxBytes = 4096)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Count == 0)
        {
            return "(empty)";
        }

        if (bytesPerLine <= 0) throw new ArgumentOutOfRangeException(nameof(bytesPerLine));
        if (maxBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));

        var count = Math.Min(bytes.Count, maxBytes);
        var builder = new StringBuilder(count * 4);
        for (var offset = 0; offset < count; offset += bytesPerLine)
        {
            var lineLength = Math.Min(bytesPerLine, count - offset);
            builder.Append(offset.ToString("X8"));
            builder.Append("  ");

            for (var index = 0; index < bytesPerLine; index++)
            {
                if (index < lineLength)
                {
                    builder.Append(bytes[offset + index].ToString("X2"));
                }
                else
                {
                    builder.Append("  ");
                }

                if (index < bytesPerLine - 1)
                {
                    builder.Append(' ');
                }
            }

            builder.Append("  |");
            for (var index = 0; index < lineLength; index++)
            {
                var value = bytes[offset + index];
                builder.Append(value is >= 0x20 and <= 0x7e ? (char)value : '.');
            }

            builder.Append('|');
            if (offset + lineLength < count)
            {
                builder.AppendLine();
            }
        }

        if (count < bytes.Count)
        {
            builder.AppendLine();
            builder.Append($"... truncated, showing {count} of {bytes.Count} bytes ...");
        }

        return builder.ToString();
    }
}
