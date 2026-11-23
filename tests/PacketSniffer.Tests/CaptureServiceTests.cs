using PacketSniffer.App.Models;
using PacketSniffer.App.Services;

namespace PacketSniffer.Tests;

public sealed class CaptureServiceTests
{
    [Fact]
    public void StopIsSafeBeforeCaptureStarts()
    {
        var service = new CaptureService(_ => null);

        service.Stop();
        service.Stop();

        Assert.False(service.IsCapturing);
    }

    [Fact]
    public void StartRejectsMissingDevice()
    {
        var service = new CaptureService(_ => null);

        Assert.Throws<ArgumentNullException>(() => service.Start(null!, null));
        Assert.False(service.IsCapturing);
    }

    [Fact]
    public void StartRejectsUnknownDeviceWithoutOpeningNpcap()
    {
        var service = new CaptureService(_ => null);
        var device = new CaptureDeviceInfo("missing", "Missing adapter", "Ethernet");

        var exception = Assert.Throws<InvalidOperationException>(() => service.Start(device, "tcp"));

        Assert.Contains("not available", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(service.IsCapturing);
    }
}
