using PacketSniffer.App.Models;

namespace PacketSniffer.App.Services;

public sealed class FlowTracker : IFlowTracker
{
    private readonly object _gate = new();
    private readonly Dictionary<string, FlowState> _flows = new(StringComparer.Ordinal);

    public void Add(PacketSummary packet)
    {
        ArgumentNullException.ThrowIfNull(packet);
        if (packet.Source == "-" || packet.Destination == "-")
        {
            return;
        }

        var protocol = NormalizeProtocol(packet.Protocol);
        var endpoints = new[] { packet.Source, packet.Destination };
        Array.Sort(endpoints, StringComparer.Ordinal);
        var key = $"{protocol}|{endpoints[0]}|{endpoints[1]}";

        lock (_gate)
        {
            if (!_flows.TryGetValue(key, out var state))
            {
                state = new FlowState(key, protocol, endpoints[0], endpoints[1], packet.Timestamp);
                _flows.Add(key, state);
            }

            state.PacketCount++;
            state.ByteCount += packet.Length;
            if (packet.Timestamp < state.FirstSeen) state.FirstSeen = packet.Timestamp;
            if (packet.Timestamp > state.LastSeen) state.LastSeen = packet.Timestamp;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _flows.Clear();
        }
    }

    public IReadOnlyList<FlowSummary> Snapshot()
    {
        lock (_gate)
        {
            return _flows.Values
                .Select(state => state.ToSummary())
                .OrderByDescending(flow => flow.PacketCount)
                .ThenByDescending(flow => flow.ByteCount)
                .ToArray();
        }
    }

    private static string NormalizeProtocol(string protocol)
    {
        return string.Equals(protocol, "HTTP", StringComparison.OrdinalIgnoreCase) ? "TCP" : protocol.ToUpperInvariant();
    }

    private sealed class FlowState
    {
        public FlowState(string key, string protocol, string endpointA, string endpointB, DateTimeOffset timestamp)
        {
            Key = key;
            Protocol = protocol;
            EndpointA = endpointA;
            EndpointB = endpointB;
            FirstSeen = timestamp;
            LastSeen = timestamp;
        }

        public string Key { get; }
        public string Protocol { get; }
        public string EndpointA { get; }
        public string EndpointB { get; }
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }

        public FlowSummary ToSummary()
        {
            return new FlowSummary(Key, Protocol, EndpointA, EndpointB, PacketCount, ByteCount, FirstSeen, LastSeen);
        }
    }
}
