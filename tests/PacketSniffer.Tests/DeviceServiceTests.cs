using PacketSniffer.App.Services;

namespace PacketSniffer.Tests;

public sealed class DeviceServiceTests
{
    [Fact]
    public void ListsDevicesWhenNpcapIsInstalled()
    {
        if (!File.Exists("C:\\Windows\\System32\\Npcap\\wpcap.dll"))
        {
            return;
        }

        var devices = new DeviceService().ListDevices();

        Assert.NotEmpty(devices);
    }
}
