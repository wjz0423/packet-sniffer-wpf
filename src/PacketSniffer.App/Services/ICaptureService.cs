using PacketSniffer.App.Models;
using SharpPcap;

namespace PacketSniffer.App.Services;

public sealed class RawCaptureEventArgs : EventArgs
{
    public RawCaptureEventArgs(RawCapture capture)
    {
        Capture = capture ?? throw new ArgumentNullException(nameof(capture));
    }

    public RawCapture Capture { get; }
}

public sealed class CaptureErrorEventArgs : EventArgs
{
    public CaptureErrorEventArgs(string message)
    {
        Message = string.IsNullOrWhiteSpace(message) ? "Unknown capture error." : message;
    }

    public string Message { get; }
}

public interface ICaptureService : IDisposable
{
    event EventHandler<RawCaptureEventArgs>? PacketCaptured;

    event EventHandler<CaptureErrorEventArgs>? CaptureError;

    bool IsCapturing { get; }

    bool IsPaused { get; }

    void Start(CaptureDeviceInfo device, string? bpfFilter);

    void Pause();

    void Resume();

    void Stop();
}
