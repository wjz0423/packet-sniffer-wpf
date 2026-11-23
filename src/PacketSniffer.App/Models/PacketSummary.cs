namespace PacketSniffer.App.Models;

public sealed record PacketSummary(
    long Index,
    DateTimeOffset Timestamp,
    int Length,
    string LinkLayer,
    string Source,
    string Destination,
    string Protocol,
    string Info,
    IReadOnlyList<PacketLayer> Layers,
    IReadOnlyList<byte> Bytes);
