using System.Net;
using System.Text;

namespace PacketSniffer.Tests.Fixtures;

internal static class PacketFixtures
{
    private static readonly byte[] DestinationMac = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    private static readonly byte[] SourceMac = { 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };

    public static byte[] TcpIpv4()
    {
        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var bytes = EthernetHeader(0x0800);
        var totalLength = 20 + 20 + payload.Length;

        bytes.Add(0x45);
        bytes.Add(0x00);
        AddUInt16(bytes, (ushort)totalLength);
        AddUInt16(bytes, 0x1234);
        AddUInt16(bytes, 0x4000);
        bytes.Add(64);
        bytes.Add(6);
        AddUInt16(bytes, 0);
        AddIpv4(bytes, "192.168.1.10");
        AddIpv4(bytes, "93.184.216.34");

        AddUInt16(bytes, 51515);
        AddUInt16(bytes, 80);
        AddUInt32(bytes, 0x01020304);
        AddUInt32(bytes, 0x05060708);
        bytes.Add(0x50);
        bytes.Add(0x18);
        AddUInt16(bytes, 0x4000);
        AddUInt16(bytes, 0);
        AddUInt16(bytes, 0);
        bytes.AddRange(payload);
        return bytes.ToArray();
    }

    public static byte[] UdpIpv4()
    {
        var payload = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var bytes = EthernetHeader(0x0800);
        var totalLength = 20 + 8 + payload.Length;

        bytes.Add(0x45);
        bytes.Add(0x00);
        AddUInt16(bytes, (ushort)totalLength);
        AddUInt16(bytes, 0x1235);
        AddUInt16(bytes, 0x0000);
        bytes.Add(64);
        bytes.Add(17);
        AddUInt16(bytes, 0);
        AddIpv4(bytes, "10.0.0.7");
        AddIpv4(bytes, "8.8.8.8");

        AddUInt16(bytes, 5353);
        AddUInt16(bytes, 53);
        AddUInt16(bytes, (ushort)(8 + payload.Length));
        AddUInt16(bytes, 0);
        bytes.AddRange(payload);
        return bytes.ToArray();
    }

    public static byte[] IcmpV6()
    {
        var bytes = EthernetHeader(0x86dd);
        bytes.Add(0x60);
        bytes.Add(0x00);
        bytes.Add(0x00);
        bytes.Add(0x00);
        AddUInt16(bytes, 8);
        bytes.Add(58);
        bytes.Add(64);
        AddIpv6(bytes, "2001:db8::1");
        AddIpv6(bytes, "2001:db8::2");
        bytes.Add(128);
        bytes.Add(0);
        AddUInt16(bytes, 0);
        AddUInt16(bytes, 1);
        AddUInt16(bytes, 1);
        return bytes.ToArray();
    }

    public static byte[] NonIpEthernet()
    {
        var bytes = EthernetHeader(0x88cc);
        bytes.AddRange(new byte[] { 0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33 });
        return bytes.ToArray();
    }

    private static List<byte> EthernetHeader(ushort etherType)
    {
        var bytes = new List<byte>(64);
        bytes.AddRange(DestinationMac);
        bytes.AddRange(SourceMac);
        AddUInt16(bytes, etherType);
        return bytes;
    }

    private static void AddUInt16(List<byte> bytes, ushort value)
    {
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }

    private static void AddUInt32(List<byte> bytes, uint value)
    {
        bytes.Add((byte)(value >> 24));
        bytes.Add((byte)(value >> 16));
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }

    private static void AddIpv4(List<byte> bytes, string address)
    {
        bytes.AddRange(IPAddress.Parse(address).GetAddressBytes());
    }

    private static void AddIpv6(List<byte> bytes, string address)
    {
        bytes.AddRange(IPAddress.Parse(address).GetAddressBytes());
    }
}
