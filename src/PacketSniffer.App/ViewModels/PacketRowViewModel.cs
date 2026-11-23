using PacketSniffer.App.Infrastructure;
using PacketSniffer.App.Models;

namespace PacketSniffer.App.ViewModels;

public sealed class PacketRowViewModel
{
    public PacketRowViewModel(PacketSummary packet)
    {
        Summary = packet ?? throw new ArgumentNullException(nameof(packet));
    }

    public PacketSummary Summary { get; }

    public long Index => Summary.Index;

    public string TimestampText => Summary.Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

    public string Source => Summary.Source;

    public string Destination => Summary.Destination;

    public string Protocol => Summary.Protocol;

    public int Length => Summary.Length;

    public string Info => Summary.Info;

    public string HexText => HexFormatter.Format(Summary.Bytes);
}
