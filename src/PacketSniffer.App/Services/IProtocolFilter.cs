using PacketSniffer.App.Models;

namespace PacketSniffer.App.Services;

public enum ProtocolFilterSelection
{
    All,
    Http,
    Tcp,
    Udp,
    Icmp,
    Ipv4,
    Ipv6,
    Other
}

public interface IProtocolFilter
{
    bool Matches(PacketSummary packet, ProtocolFilterSelection selection);
}
