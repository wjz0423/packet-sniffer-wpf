namespace PacketSniffer.App.Models;

public sealed record PacketLayer(
    string Name,
    string Summary,
    IReadOnlyList<PacketField> Fields);
