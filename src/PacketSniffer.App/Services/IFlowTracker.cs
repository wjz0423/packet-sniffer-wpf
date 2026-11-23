using PacketSniffer.App.Models;

namespace PacketSniffer.App.Services;

public interface IFlowTracker
{
    void Add(PacketSummary packet);

    void Clear();

    IReadOnlyList<FlowSummary> Snapshot();
}
