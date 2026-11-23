using PacketSniffer.App.Infrastructure;

namespace PacketSniffer.Tests;

public sealed class HexFormatterTests
{
    [Fact]
    public void FormatsBytesWithOffsetHexAndAscii()
    {
        var formatted = HexFormatter.Format(new byte[] { 0x00, 0x41, 0x7f, 0xff });

        Assert.Contains("00000000", formatted);
        Assert.Contains("00 41 7F FF", formatted);
        Assert.Contains(".A..", formatted);
    }

    [Fact]
    public void FormatsEmptyInputAndMarksTruncation()
    {
        Assert.Equal("(empty)", HexFormatter.Format(Array.Empty<byte>()));

        var formatted = HexFormatter.Format(Enumerable.Range(0, 40).Select(value => (byte)value).ToArray(), maxBytes: 16);
        Assert.Contains("truncated", formatted, StringComparison.OrdinalIgnoreCase);
    }
}
