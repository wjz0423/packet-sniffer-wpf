using PacketDotNet;
using PacketSniffer.App.Services;
using PacketSniffer.Tests.Fixtures;
using SharpPcap;

namespace PacketSniffer.Tests;

public sealed class PacketParserTests
{
    private readonly PacketParser _parser = new();

    [Fact]
    public void ParsesIpv4TcpAndRecognizesHttp()
    {
        var summary = _parser.Parse(CreateCapture(PacketFixtures.TcpIpv4()));

        Assert.Equal(1, summary.Index);
        Assert.Equal("HTTP", summary.Protocol);
        Assert.Equal("192.168.1.10:51515", summary.Source);
        Assert.Equal("93.184.216.34:80", summary.Destination);
        Assert.Contains("HTTP", summary.Info, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(summary.Layers, layer => layer.Name == "Ethernet");
        Assert.Contains(summary.Layers, layer => layer.Name == "IPv4");
        Assert.Contains(summary.Layers, layer => layer.Name == "TCP");
        Assert.Equal(PacketFixtures.TcpIpv4(), summary.Bytes);
    }

    [Fact]
    public void ParsesIpv4Udp()
    {
        var summary = _parser.Parse(CreateCapture(PacketFixtures.UdpIpv4()));

        Assert.Equal("UDP", summary.Protocol);
        Assert.Equal("10.0.0.7:5353", summary.Source);
        Assert.Equal("8.8.8.8:53", summary.Destination);
        Assert.Contains(summary.Layers, layer => layer.Name == "UDP");
    }

    [Fact]
    public void ParsesIpv6Icmp()
    {
        var summary = _parser.Parse(CreateCapture(PacketFixtures.IcmpV6()));

        Assert.Equal("ICMPv6", summary.Protocol);
        Assert.Equal("2001:db8::1", summary.Source);
        Assert.Equal("2001:db8::2", summary.Destination);
        Assert.Contains(summary.Layers, layer => layer.Name == "IPv6");
        Assert.Contains(summary.Layers, layer => layer.Name == "ICMPv6");
    }

    [Fact]
    public void KeepsNonIpFramesInspectable()
    {
        var summary = _parser.Parse(CreateCapture(PacketFixtures.NonIpEthernet()));

        Assert.Equal("LLDP", summary.Protocol);
        Assert.Equal("-", summary.Source);
        Assert.Equal("-", summary.Destination);
        Assert.Contains(summary.Layers, layer => layer.Name == "Ethernet");
    }

    private static RawCapture CreateCapture(byte[] bytes)
    {
        return new RawCapture(LinkLayers.Ethernet, new PosixTimeval(DateTime.UtcNow), bytes, bytes.Length);
    }
}
