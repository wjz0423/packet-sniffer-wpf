using PacketSniffer.App.Models;
using SharpPcap;

namespace PacketSniffer.App.Services;

public sealed class DeviceService
{
    public IReadOnlyList<CaptureDeviceInfo> ListDevices()
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            devices.Refresh();
            return devices
                .Select(device => new CaptureDeviceInfo(
                    device.Name,
                    string.IsNullOrWhiteSpace(device.Description) ? device.Name : device.Description,
                    "Auto"))
                .ToArray();
        }
        catch (Exception exception) when (exception is DllNotFoundException or TypeInitializationException or PcapException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                "Npcap is unavailable. Install Npcap and restart the application before capturing.",
                exception);
        }
    }

    public ILiveDevice? Resolve(CaptureDeviceInfo device)
    {
        ArgumentNullException.ThrowIfNull(device);

        try
        {
            var devices = CaptureDeviceList.Instance;
            devices.Refresh();
            return devices.FirstOrDefault(candidate => string.Equals(candidate.Name, device.Name, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception exception) when (exception is DllNotFoundException or TypeInitializationException or PcapException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                "Npcap is unavailable. Install Npcap and restart the application before capturing.",
                exception);
        }
    }
}
