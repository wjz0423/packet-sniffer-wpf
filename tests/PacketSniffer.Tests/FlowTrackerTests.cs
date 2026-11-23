using PacketSniffer.App.Models;
using PacketSniffer.App.Services;

namespace PacketSniffer.Tests;

public sealed class FlowTrackerTests
{
    [Fact]
    public void ReverseDirectionsShareOneTcpFlow()
    {
        var tracker = new FlowTracker();
        tracker.Add(CreatePacket(1, "HTTP", "10.0.0.1:50000", "10.0.0.2:80", 100));
        tracker.Add(CreatePacket(2, "TCP", "10.0.0.2:80", "10.0.0.1:50000", 50));

        var flow = Assert.Single(tracker.Snapshot());
        Assert.Equal("TCP", flow.Protocol);
        Assert.Equal(2, flow.PacketCount);
        Assert.Equal(150, flow.ByteCount);
    }

    [Fact]
    public void SnapshotSortsFlowsByPacketCount()
    {
        var tracker = new FlowTracker();
        tracker.Add(CreatePacket(1, "UDP", "10.0.0.1:1", "10.0.0.2:2", 20));
        tracker.Add(CreatePacket(2, "UDP", "10.0.0.1:1", "10.0.0.2:2", 20));
        tracker.Add(CreatePacket(3, "TCP", "10.0.0.3:3", "10.0.0.4:4", 30));

        var snapshot = tracker.Snapshot();
        Assert.Equal(2, snapshot.Count);
        Assert.Equal(2, snapshot[0].PacketCount);
        Assert.Equal("UDP", snapshot[0].Protocol);
    }

    private static PacketSummary CreatePacket(long index, string protocol, string source, string destination, int length)
    {
        return new PacketSummary(
            index,
            DateTimeOffset.UtcNow.AddSeconds(index),
            length,
            "Ethernet",
            source,
            destination,
            protocol,
            protocol,
            Array.Empty<PacketLayer>(),
            new byte[length]);
    }
}
