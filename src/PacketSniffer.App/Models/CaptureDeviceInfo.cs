namespace PacketSniffer.App.Models;

public sealed record CaptureDeviceInfo(
    string Name,
    string Description,
    string LinkLayer);
