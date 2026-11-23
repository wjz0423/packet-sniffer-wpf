using System.Net;
using System.Text;
using PacketDotNet;
using PacketSniffer.App.Models;
using SharpPcap;

namespace PacketSniffer.App.Services;

public sealed class PacketParser : IPacketParser
{
    private static readonly string[] HttpMethods = { "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE " };
    private long _nextIndex;

    public PacketSummary Parse(RawCapture capture)
    {
        ArgumentNullException.ThrowIfNull(capture);

        var bytes = capture.Data.ToArray();
        var layers = new List<PacketLayer>();
        var source = "-";
        var destination = "-";
        var protocol = "RAW";
        var info = $"{capture.LinkLayerType} frame";

        try
        {
            var packet = Packet.ParsePacket(capture.LinkLayerType, bytes);
            var ethernet = packet.Extract<EthernetPacket>();
            if (ethernet is not null)
            {
                layers.Add(new PacketLayer(
                    "Ethernet",
                    $"{ethernet.SourceHardwareAddress} → {ethernet.DestinationHardwareAddress}",
                    new[]
                    {
                        new PacketField("Source", ethernet.SourceHardwareAddress.ToString()),
                        new PacketField("Destination", ethernet.DestinationHardwareAddress.ToString()),
                        new PacketField("Type", ethernet.Type.ToString())
                    }));
            }

            var ip = packet.Extract<IPPacket>();
            if (ip is not null)
            {
                source = ip.SourceAddress.ToString();
                destination = ip.DestinationAddress.ToString();
                var ipName = ip.Version == IPVersion.IPv6 ? "IPv6" : "IPv4";
                layers.Add(new PacketLayer(
                    ipName,
                    $"{source} → {destination}",
                    new[]
                    {
                        new PacketField("Source", source),
                        new PacketField("Destination", destination),
                        new PacketField("Protocol", ip.Protocol.ToString()),
                        new PacketField("Header length", $"{ip.HeaderLength} bytes"),
                        new PacketField("Payload length", $"{ip.PayloadLength} bytes")
                    }));
            }

            var tcp = packet.Extract<TcpPacket>();
            if (tcp is not null)
            {
                protocol = "TCP";
                source = FormatEndpoint(source, tcp.SourcePort);
                destination = FormatEndpoint(destination, tcp.DestinationPort);
                var flags = FormatTcpFlags(tcp);
                info = string.IsNullOrWhiteSpace(flags) ? $"TCP {source} → {destination}" : $"TCP [{flags}]";
                var http = TryGetHttpSummary(tcp.PayloadData);
                if (http is not null)
                {
                    protocol = "HTTP";
                    info = http;
                }

                layers.Add(new PacketLayer(
                    "TCP",
                    $"{source} → {destination}",
                    new[]
                    {
                        new PacketField("Source port", tcp.SourcePort.ToString()),
                        new PacketField("Destination port", tcp.DestinationPort.ToString()),
                        new PacketField("Sequence", tcp.SequenceNumber.ToString()),
                        new PacketField("Acknowledgment", tcp.AcknowledgmentNumber.ToString()),
                        new PacketField("Flags", flags),
                        new PacketField("Payload", $"{tcp.PayloadData.Length} bytes")
                    }));
            }
            else
            {
                var udp = packet.Extract<UdpPacket>();
                if (udp is not null)
                {
                    protocol = "UDP";
                    source = FormatEndpoint(source, udp.SourcePort);
                    destination = FormatEndpoint(destination, udp.DestinationPort);
                    info = $"UDP {source} → {destination}";
                    layers.Add(new PacketLayer(
                        "UDP",
                        $"{source} → {destination}",
                        new[]
                        {
                            new PacketField("Source port", udp.SourcePort.ToString()),
                            new PacketField("Destination port", udp.DestinationPort.ToString()),
                            new PacketField("Length", $"{udp.Length} bytes"),
                            new PacketField("Payload", $"{udp.PayloadData.Length} bytes")
                        }));
                }
                else
                {
                    var icmpV6 = packet.Extract<IcmpV6Packet>();
                    var icmpV4 = packet.Extract<IcmpV4Packet>();
                    if (icmpV6 is not null)
                    {
                        protocol = "ICMPv6";
                        info = $"ICMPv6 {icmpV6.Type} code {icmpV6.Code}";
                        layers.Add(new PacketLayer(
                            "ICMPv6",
                            info,
                            new[]
                            {
                                new PacketField("Type", icmpV6.Type.ToString()),
                                new PacketField("Code", icmpV6.Code.ToString()),
                                new PacketField("Checksum", $"0x{icmpV6.Checksum:X4}")
                            }));
                    }
                    else if (icmpV4 is not null)
                    {
                        protocol = "ICMP";
                        info = $"ICMP type {icmpV4.TypeCode}";
                        layers.Add(new PacketLayer(
                            "ICMP",
                            info,
                            new[]
                            {
                                new PacketField("Type", icmpV4.TypeCode.ToString()),
                                new PacketField("Checksum", $"0x{icmpV4.Checksum:X4}")
                            }));
                    }
                    else if (ip is not null)
                    {
                        protocol = NormalizeProtocolName(ip.Protocol.ToString());
                        info = $"{protocol} {source} → {destination}";
                    }
                    else if (ethernet is not null)
                    {
                        protocol = NormalizeEthernetName(ethernet.Type.ToString());
                        info = $"{protocol} frame";
                    }
                }
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or IndexOutOfRangeException)
        {
            protocol = "RAW";
            info = $"Unable to decode frame: {exception.Message}";
            layers.Add(new PacketLayer("Raw", info, Array.Empty<PacketField>()));
        }

        return new PacketSummary(
            Interlocked.Increment(ref _nextIndex),
            ToUtcOffset(capture.Timeval.Date),
            capture.PacketLength > 0 ? capture.PacketLength : bytes.Length,
            capture.LinkLayerType.ToString(),
            source,
            destination,
            protocol,
            info,
            layers,
            Array.AsReadOnly(bytes));
    }

    private static DateTimeOffset ToUtcOffset(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        return new DateTimeOffset(utc);
    }

    private static string FormatEndpoint(string address, ushort port)
    {
        if (address == "-")
        {
            return $"-:{port}";
        }

        return address.Contains(':', StringComparison.Ordinal) ? $"[{address}]:{port}" : $"{address}:{port}";
    }

    private static string FormatTcpFlags(TcpPacket tcp)
    {
        var flags = new List<string>();
        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Push) flags.Add("PSH");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Urgent) flags.Add("URG");
        return string.Join(", ", flags);
    }

    private static string? TryGetHttpSummary(byte[] payload)
    {
        if (payload.Length == 0)
        {
            return null;
        }

        var text = Encoding.ASCII.GetString(payload);
        var isRequest = HttpMethods.Any(method => text.StartsWith(method, StringComparison.OrdinalIgnoreCase));
        var isResponse = text.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase);
        if (!isRequest && !isResponse)
        {
            return null;
        }

        var firstLine = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)[0];
        return $"HTTP {firstLine}";
    }

    private static string NormalizeProtocolName(string name)
    {
        return name switch
        {
            "Tcp" => "TCP",
            "Udp" => "UDP",
            "Icmp" => "ICMP",
            "IcmpV6" => "ICMPv6",
            _ => name.ToUpperInvariant()
        };
    }

    private static string NormalizeEthernetName(string name)
    {
        return name switch
        {
            "Lldp" => "LLDP",
            "Arp" => "ARP",
            "IPv4" => "IPv4",
            "IPv6" => "IPv6",
            _ => name.ToUpperInvariant()
        };
    }
}
