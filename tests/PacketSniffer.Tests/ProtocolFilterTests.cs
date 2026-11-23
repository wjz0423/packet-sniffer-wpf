using PacketSniffer.App.Models;
using PacketSniffer.App.Services;

namespace PacketSniffer.Tests;

public sealed class ProtocolFilterTests
{
    private readonly ProtocolFilter _filter = new();

    [Fact]
    public void MatchesSelectedProtocolAndAll()
    {
        var http = CreatePacket("HTTP");
        var udp = CreatePacket("UDP");

        Assert.True(_filter.Matches(http, ProtocolFilterSelection.All));
        Assert.True(_filter.Matches(http, ProtocolFilterSelection.Http));
        Assert.False(_filter.Matches(udp, ProtocolFilterSelection.Http));
        Assert.True(_filter.Matches(udp, ProtocolFilterSelection.Udp));
    }

    [Fact]
    public void IcmpSelectionIncludesIcmpV6()
    {
        Assert.True(_filter.Matches(CreatePacket("ICMPv6"), ProtocolFilterSelection.Icmp));
        Assert.True(_filter.Matches(CreatePacket("ICMP"), ProtocolFilterSelection.Icmp));
        Assert.False(_filter.Matches(CreatePacket("TCP"), ProtocolFilterSelection.Icmp));
    }

    private static PacketSummary CreatePacket(string protocol)
    {
        return new PacketSummary(
            1,
            DateTimeOffset.UtcNow,
            10,
            "Ethernet",
            "10.0.0.1",
            "10.0.0.2",
            protocol,
            protocol,
            Array.Empty<PacketLayer>(),
            Array.Empty<byte>());
    }
}
