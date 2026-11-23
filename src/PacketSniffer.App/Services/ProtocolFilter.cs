using PacketSniffer.App.Models;

namespace PacketSniffer.App.Services;

public sealed class ProtocolFilter : IProtocolFilter
{
    public bool Matches(PacketSummary packet, ProtocolFilterSelection selection)
    {
        ArgumentNullException.ThrowIfNull(packet);

        return selection switch
        {
            ProtocolFilterSelection.All => true,
            ProtocolFilterSelection.Http => Is(packet, "HTTP"),
            ProtocolFilterSelection.Tcp => Is(packet, "TCP") || Is(packet, "HTTP"),
            ProtocolFilterSelection.Udp => Is(packet, "UDP"),
            ProtocolFilterSelection.Icmp => Is(packet, "ICMP") || Is(packet, "ICMPv6"),
            ProtocolFilterSelection.Ipv4 => HasLayer(packet, "IPv4"),
            ProtocolFilterSelection.Ipv6 => HasLayer(packet, "IPv6"),
            ProtocolFilterSelection.Other => !IsKnown(packet),
            _ => true
        };
    }

    private static bool Is(PacketSummary packet, string protocol)
    {
        return string.Equals(packet.Protocol, protocol, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasLayer(PacketSummary packet, string layerName)
    {
        return packet.Layers.Any(layer => string.Equals(layer.Name, layerName, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsKnown(PacketSummary packet)
    {
        return Is(packet, "HTTP")
            || Is(packet, "TCP")
            || Is(packet, "UDP")
            || Is(packet, "ICMP")
            || Is(packet, "ICMPv6")
            || HasLayer(packet, "IPv4")
            || HasLayer(packet, "IPv6");
    }
}
