namespace PacketSniffer.App.Models;

public sealed record FlowSummary(
    string Key,
    string Protocol,
    string EndpointA,
    string EndpointB,
    long PacketCount,
    long ByteCount,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen)
{
    public string DisplayName => $"{Protocol} {EndpointA} ↔ {EndpointB}";
}
