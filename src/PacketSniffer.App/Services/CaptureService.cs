using PacketSniffer.App.Models;
using SharpPcap;

namespace PacketSniffer.App.Services;

public sealed class CaptureService : ICaptureService
{
    private readonly Func<CaptureDeviceInfo, ILiveDevice?> _deviceResolver;
    private ILiveDevice? _activeDevice;
    private bool _disposed;
    private bool _isPaused;

    public CaptureService()
        : this(new DeviceService().Resolve)
    {
    }

    public CaptureService(Func<CaptureDeviceInfo, ILiveDevice?> deviceResolver)
    {
        _deviceResolver = deviceResolver ?? throw new ArgumentNullException(nameof(deviceResolver));
    }

    public event EventHandler<RawCaptureEventArgs>? PacketCaptured;

    public event EventHandler<CaptureErrorEventArgs>? CaptureError;

    public bool IsCapturing { get; private set; }

    public bool IsPaused => _isPaused;

    public void Start(CaptureDeviceInfo device, string? bpfFilter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(device);

        Stop();
        var liveDevice = _deviceResolver(device)
            ?? throw new InvalidOperationException($"Capture device '{device.Name}' is not available.");

        try
        {
            liveDevice.Open(new DeviceConfiguration
            {
                Mode = DeviceModes.Promiscuous,
                ReadTimeout = 1000,
                Snaplen = 65535
            });

            if (!string.IsNullOrWhiteSpace(bpfFilter))
            {
                liveDevice.Filter = bpfFilter.Trim();
            }

            liveDevice.OnPacketArrival += HandlePacketArrival;
            liveDevice.OnCaptureStopped += HandleCaptureStopped;
            _activeDevice = liveDevice;
            liveDevice.StartCapture();
            IsCapturing = true;
            _isPaused = false;
        }
        catch
        {
            CleanupDevice(liveDevice);
            throw;
        }
    }

    public void Stop()
    {
        var liveDevice = Interlocked.Exchange(ref _activeDevice, null);
        IsCapturing = false;
        _isPaused = false;
        if (liveDevice is null)
        {
            return;
        }

        CleanupDevice(liveDevice);
    }

    public void Pause()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var liveDevice = _activeDevice;
        if (liveDevice is null || !IsCapturing || _isPaused)
        {
            return;
        }

        liveDevice.StopCapture();
        _isPaused = true;
    }

    public void Resume()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var liveDevice = _activeDevice;
        if (liveDevice is null || !IsCapturing || !_isPaused)
        {
            return;
        }

        liveDevice.StartCapture();
        _isPaused = false;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Stop();
        GC.SuppressFinalize(this);
    }

    private void HandlePacketArrival(object sender, PacketCapture capture)
    {
        var rawCapture = capture.GetPacket();
        if (rawCapture is not null)
        {
            PacketCaptured?.Invoke(this, new RawCaptureEventArgs(rawCapture));
        }
    }

    private void HandleCaptureStopped(object sender, CaptureStoppedEventStatus status)
    {
        if (status == CaptureStoppedEventStatus.ErrorWhileCapturing)
        {
            CaptureError?.Invoke(this, new CaptureErrorEventArgs("Npcap stopped capturing because of an error."));
        }
    }

    private void CleanupDevice(ILiveDevice liveDevice)
    {
        liveDevice.OnPacketArrival -= HandlePacketArrival;
        liveDevice.OnCaptureStopped -= HandleCaptureStopped;
        try
        {
            if (liveDevice.Started)
            {
                liveDevice.StopCapture();
            }
        }
        finally
        {
            liveDevice.Close();
            liveDevice.Dispose();
        }
    }
}
