using PacketDotNet;
using PacketSniffer.App.Models;
using PacketSniffer.App.Services;
using PacketSniffer.App.ViewModels;
using SharpPcap;

namespace PacketSniffer.Tests;

public sealed class MainViewModelTests
{
    [Fact]
    public void ProcessesCapturedPacketsInBatches()
    {
        var packet = CreatePacket(1, "TCP");
        var capture = new FakeCaptureService();
        var viewModel = CreateViewModel(capture, packet);

        capture.Emit(CreateRawCapture());

        Assert.Equal(1, viewModel.ProcessPendingPackets());
        var row = Assert.Single(viewModel.Packets);
        Assert.Equal(1, row.Index);
        Assert.Equal("TCP", row.Protocol);
    }

    [Fact]
    public void ProtocolSelectionRebuildsVisibleRowsAndFlows()
    {
        var capture = new FakeCaptureService();
        var viewModel = CreateViewModel(capture, CreatePacket(1, "TCP"), CreatePacket(2, "UDP"));

        capture.Emit(CreateRawCapture());
        capture.Emit(CreateRawCapture());
        while (viewModel.ProcessPendingPackets() > 0) { }

        viewModel.SelectedProtocol = ProtocolFilterSelection.Udp;

        var row = Assert.Single(viewModel.Packets);
        Assert.Equal("UDP", row.Protocol);
        Assert.Single(viewModel.Flows);
    }

    [Fact]
    public void PacketListIsBoundedAtFiveThousandRows()
    {
        var packets = Enumerable.Range(1, 5005).Select(index => CreatePacket(index, "UDP")).ToArray();
        var capture = new FakeCaptureService();
        var viewModel = CreateViewModel(capture, packets);

        foreach (var _ in packets)
        {
            capture.Emit(CreateRawCapture());
        }

        while (viewModel.ProcessPendingPackets() > 0) { }

        Assert.Equal(5000, viewModel.Packets.Count);
        Assert.Equal(6, viewModel.Packets[0].Index);
        Assert.Equal(5005, viewModel.Packets[^1].Index);
    }

    [Fact]
    public void PendingCaptureQueueDropsOldestAndReportsCount()
    {
        var count = MainViewModel.MaxPendingPacketCount + 100;
        var packets = Enumerable.Range(1, count).Select(index => CreatePacket(index, "UDP")).ToArray();
        var capture = new FakeCaptureService();
        var viewModel = CreateViewModel(capture, packets);

        foreach (var _ in packets)
        {
            capture.Emit(CreateRawCapture());
        }

        while (viewModel.ProcessPendingPackets() > 0) { }

        Assert.Equal(100, viewModel.DroppedPacketCount);
        Assert.Contains("丢弃", viewModel.Status, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IgnoresAnInFlightCaptureAfterDispose()
    {
        var parser = new BlockingPacketParser(CreatePacket(1, "TCP"));
        var capture = new FakeCaptureService();
        using var viewModel = new MainViewModel(
            capture,
            parser,
            new ProtocolFilter(),
            new FlowTracker(),
            () => new[] { new CaptureDeviceInfo("test", "Test adapter", "Ethernet") },
            startTimer: false,
            startParserWorker: true);

        var emitTask = Task.Run(() => capture.Emit(CreateRawCapture()));
        Assert.True(parser.Entered.Wait(TimeSpan.FromSeconds(2)));
        viewModel.Dispose();
        parser.Release.Set();
        await emitTask;
        await Task.Delay(50);

        Assert.Equal(0, viewModel.ProcessPendingPackets());
        Assert.Empty(viewModel.Packets);
    }

    [Fact]
    public void PauseCommandTogglesCaptureState()
    {
        var capture = new FakeCaptureService();
        var viewModel = CreateViewModel(capture, CreatePacket(1, "TCP"));

        viewModel.StartCommand.Execute(null);
        viewModel.PauseCommand.Execute(null);
        Assert.True(capture.IsPaused);
        Assert.Equal("继续", viewModel.PauseActionText);

        viewModel.PauseCommand.Execute(null);
        Assert.False(capture.IsPaused);
        Assert.Equal("暂停", viewModel.PauseActionText);
    }

    [Fact]
    public void CaptureErrorsReachStatusBar()
    {
        var capture = new FakeCaptureService();
        var viewModel = CreateViewModel(capture, CreatePacket(1, "TCP"));

        capture.EmitError("capture failed");
        viewModel.ProcessPendingPackets();

        Assert.Equal("capture failed", viewModel.Status);
    }

    private static MainViewModel CreateViewModel(FakeCaptureService capture, params PacketSummary[] packets)
    {
        var parser = new QueuePacketParser(packets);
        return new MainViewModel(
            capture,
            parser,
            new ProtocolFilter(),
            new FlowTracker(),
            () => new[] { new CaptureDeviceInfo("test", "Test adapter", "Ethernet") },
            startTimer: false,
            startParserWorker: false);
    }

    private static PacketSummary CreatePacket(long index, string protocol)
    {
        return new PacketSummary(
            index,
            DateTimeOffset.UtcNow.AddSeconds(index),
            100,
            "Ethernet",
            "10.0.0.1:1000",
            "10.0.0.2:2000",
            protocol,
            protocol,
            new[] { new PacketLayer("IPv4", "", Array.Empty<PacketField>()) },
            new byte[100]);
    }

    private static RawCapture CreateRawCapture()
    {
        return new RawCapture(LinkLayers.Ethernet, new PosixTimeval(DateTime.UtcNow), new byte[] { 0x00 }, 1);
    }

    private sealed class QueuePacketParser : IPacketParser
    {
        private readonly Queue<PacketSummary> _packets;

        public QueuePacketParser(IEnumerable<PacketSummary> packets)
        {
            _packets = new Queue<PacketSummary>(packets);
        }

        public PacketSummary Parse(RawCapture capture)
        {
            return _packets.Dequeue();
        }
    }

    private sealed class BlockingPacketParser : IPacketParser
    {
        private readonly PacketSummary _summary;

        public BlockingPacketParser(PacketSummary summary)
        {
            _summary = summary;
        }

        public ManualResetEventSlim Entered { get; } = new();

        public ManualResetEventSlim Release { get; } = new();

        public PacketSummary Parse(RawCapture capture)
        {
            Entered.Set();
            Release.Wait();
            return _summary;
        }
    }

    private sealed class FakeCaptureService : ICaptureService
    {
        public event EventHandler<RawCaptureEventArgs>? PacketCaptured;

        public event EventHandler<CaptureErrorEventArgs>? CaptureError;

        public bool IsCapturing { get; private set; }

        public bool IsPaused { get; private set; }

        public void Start(CaptureDeviceInfo device, string? bpfFilter)
        {
            IsCapturing = true;
            IsPaused = false;
        }

        public void Pause()
        {
            IsPaused = true;
        }

        public void Resume()
        {
            IsPaused = false;
        }

        public void Stop()
        {
            IsCapturing = false;
            IsPaused = false;
        }

        public void Emit(RawCapture capture)
        {
            PacketCaptured?.Invoke(this, new RawCaptureEventArgs(capture));
        }

        public void EmitError(string message)
        {
            CaptureError?.Invoke(this, new CaptureErrorEventArgs(message));
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
