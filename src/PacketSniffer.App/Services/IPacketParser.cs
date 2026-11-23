using PacketSniffer.App.Models;
using SharpPcap;

namespace PacketSniffer.App.Services;

public interface IPacketParser
{
    PacketSummary Parse(RawCapture capture);
}
