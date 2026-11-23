using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Threading;
using PacketSniffer.App.Infrastructure;
using PacketSniffer.App.Models;
using PacketSniffer.App.Services;
using SharpPcap;

namespace PacketSniffer.App.ViewModels;

public sealed record ProtocolFilterOption(ProtocolFilterSelection Value, string Label);

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    public const int MaxPacketCount = 5000;
    public const int MaxPendingPacketCount = 10000;

    private readonly ICaptureService _captureService;
    private readonly IPacketParser _packetParser;
    private readonly IProtocolFilter _protocolFilter;
    private readonly IFlowTracker _flowTracker;
    private readonly Func<IReadOnlyList<CaptureDeviceInfo>> _deviceLoader;
    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer? _batchTimer;
    private readonly object _lifecycleGate = new();
    private readonly Queue<RawCaptureEnvelope> _pendingRawCaptures = new();
    private readonly SemaphoreSlim _rawCaptureSignal = new(0);
    private readonly CancellationTokenSource _parserCancellation = new();
    private readonly ConcurrentQueue<PacketSummary> _pendingPackets = new();
    private readonly ConcurrentQueue<string> _pendingErrors = new();
    private readonly List<PacketSummary> _capturedPackets = new();
    private readonly bool _parserWorkerEnabled;
    private readonly RelayCommand _startCommand;
    private readonly RelayCommand _pauseCommand;
    private readonly RelayCommand _stopCommand;
    private readonly RelayCommand _refreshDevicesCommand;
    private readonly RelayCommand _clearCommand;
    private CaptureDeviceInfo? _selectedDevice;
    private string _bpfFilter = string.Empty;
    private ProtocolFilterSelection _selectedProtocol = ProtocolFilterSelection.All;
    private PacketRowViewModel? _selectedPacket;
    private string _status = "Ready. Select an adapter and start capture.";
    private Task? _parserWorker;
    private int _captureGeneration;
    private long _droppedPacketCount;
    private long _lastReportedDroppedPacketCount;
    private bool _disposed;

    public MainViewModel()
        : this(
            new CaptureService(),
            new PacketParser(),
            new ProtocolFilter(),
            new FlowTracker(),
            () => new DeviceService().ListDevices(),
            Dispatcher.CurrentDispatcher,
            startTimer: true,
            startParserWorker: true)
    {
    }

    public MainViewModel(
        ICaptureService captureService,
        IPacketParser packetParser,
        IProtocolFilter protocolFilter,
        IFlowTracker flowTracker,
        Func<IReadOnlyList<CaptureDeviceInfo>> deviceLoader,
        Dispatcher? dispatcher = null,
        bool startTimer = true,
        bool startParserWorker = true)
    {
        _captureService = captureService ?? throw new ArgumentNullException(nameof(captureService));
        _packetParser = packetParser ?? throw new ArgumentNullException(nameof(packetParser));
        _protocolFilter = protocolFilter ?? throw new ArgumentNullException(nameof(protocolFilter));
        _flowTracker = flowTracker ?? throw new ArgumentNullException(nameof(flowTracker));
        _deviceLoader = deviceLoader ?? throw new ArgumentNullException(nameof(deviceLoader));
        _dispatcher = dispatcher ?? Dispatcher.CurrentDispatcher;
        _parserWorkerEnabled = startParserWorker;

        ProtocolOptions = new ObservableCollection<ProtocolFilterOption>
        {
            new(ProtocolFilterSelection.All, "全部"),
            new(ProtocolFilterSelection.Http, "HTTP"),
            new(ProtocolFilterSelection.Tcp, "TCP"),
            new(ProtocolFilterSelection.Udp, "UDP"),
            new(ProtocolFilterSelection.Icmp, "ICMP / ICMPv6"),
            new(ProtocolFilterSelection.Ipv4, "IPv4"),
            new(ProtocolFilterSelection.Ipv6, "IPv6"),
            new(ProtocolFilterSelection.Other, "其他")
        };

        _startCommand = new RelayCommand(StartCapture, CanStartCapture);
        _pauseCommand = new RelayCommand(PauseCapture, CanPauseCapture);
        _stopCommand = new RelayCommand(StopCapture, () => _captureService.IsCapturing);
        _refreshDevicesCommand = new RelayCommand(RefreshDevices);
        _clearCommand = new RelayCommand(ClearPackets);

        _captureService.PacketCaptured += OnPacketCaptured;
        _captureService.CaptureError += OnCaptureError;
        RefreshDevices();

        if (_parserWorkerEnabled)
        {
            _parserWorker = Task.Run(ParseRawCaptureLoopAsync);
        }

        if (startTimer)
        {
            _batchTimer = new DispatcherTimer(DispatcherPriority.Background, _dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(100)
            };
            _batchTimer.Tick += OnBatchTimerTick;
            _batchTimer.Start();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<CaptureDeviceInfo> Devices { get; } = new();

    public ObservableCollection<ProtocolFilterOption> ProtocolOptions { get; }

    public ObservableCollection<PacketRowViewModel> Packets { get; } = new();

    public ObservableCollection<FlowSummary> Flows { get; } = new();

    public CaptureDeviceInfo? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            if (SetField(ref _selectedDevice, value))
            {
                RaiseCommandStates();
            }
        }
    }

    public string BpfFilter
    {
        get => _bpfFilter;
        set => SetField(ref _bpfFilter, value);
    }

    public ProtocolFilterSelection SelectedProtocol
    {
        get => _selectedProtocol;
        set
        {
            if (SetField(ref _selectedProtocol, value))
            {
                RebuildVisibleCollections();
            }
        }
    }

    public PacketRowViewModel? SelectedPacket
    {
        get => _selectedPacket;
        set
        {
            if (SetField(ref _selectedPacket, value))
            {
                OnPropertyChanged(nameof(SelectedLayers));
                OnPropertyChanged(nameof(SelectedHexText));
            }
        }
    }

    public IReadOnlyList<PacketLayer> SelectedLayers => SelectedPacket?.Summary.Layers ?? Array.Empty<PacketLayer>();

    public string SelectedHexText => SelectedPacket?.HexText ?? "选择一条数据包查看原始字节";

    public string Status
    {
        get => _status;
        private set => SetField(ref _status, value);
    }

    public int CapturedCount => _capturedPackets.Count;

    public long DroppedPacketCount => Interlocked.Read(ref _droppedPacketCount);

    public bool IsPaused => _captureService.IsPaused;

    public string PauseActionText => IsPaused ? "继续" : "暂停";

    public ICommand StartCommand => _startCommand;

    public ICommand PauseCommand => _pauseCommand;

    public ICommand StopCommand => _stopCommand;

    public ICommand RefreshDevicesCommand => _refreshDevicesCommand;

    public ICommand ClearCommand => _clearCommand;

    public int ProcessPendingPackets()
    {
        if (_parserWorker is null)
        {
            ParseRawCapturesSynchronously(256);
        }

        var processed = 0;
        while (processed < 256 && _pendingPackets.TryDequeue(out var packet))
        {
            _capturedPackets.Add(packet);
            processed++;
        }

        if (_capturedPackets.Count > MaxPacketCount)
        {
            _capturedPackets.RemoveRange(0, _capturedPackets.Count - MaxPacketCount);
        }

        while (_pendingErrors.TryDequeue(out var error))
        {
            Status = error;
        }

        var dropped = DroppedPacketCount;
        if (dropped != _lastReportedDroppedPacketCount)
        {
            _lastReportedDroppedPacketCount = dropped;
            OnPropertyChanged(nameof(DroppedPacketCount));
            if (dropped > 0)
            {
                Status = $"已丢弃 {dropped} 个等待解析的数据包，已保留最新数据。";
            }
        }

        if (processed > 0)
        {
            RebuildVisibleCollections();
            OnPropertyChanged(nameof(CapturedCount));
        }

        return processed;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        lock (_lifecycleGate)
        {
            _disposed = true;
            _captureGeneration++;
            _pendingRawCaptures.Clear();
        }

        if (_batchTimer is not null)
        {
            _batchTimer.Stop();
            _batchTimer.Tick -= OnBatchTimerTick;
        }

        _captureService.PacketCaptured -= OnPacketCaptured;
        _captureService.CaptureError -= OnCaptureError;
        _captureService.Dispose();
        _parserCancellation.Cancel();
        try
        {
            _rawCaptureSignal.Release();
        }
        catch (ObjectDisposedException)
        {
        }

        GC.SuppressFinalize(this);
    }

    private void RefreshDevices()
    {
        try
        {
            Devices.Clear();
            foreach (var device in _deviceLoader())
            {
                Devices.Add(device);
            }

            SelectedDevice ??= Devices.FirstOrDefault();
            Status = Devices.Count == 0
                ? "No capture adapter found. Install Npcap, then refresh."
                : $"{Devices.Count} adapter(s) ready.";
        }
        catch (Exception exception)
        {
            Devices.Clear();
            SelectedDevice = null;
            Status = exception.Message;
        }

        RaiseCommandStates();
    }

    private void StartCapture()
    {
        if (SelectedDevice is null)
        {
            Status = "Select a capture adapter first.";
            return;
        }

        try
        {
            _captureService.Start(SelectedDevice, BpfFilter);
            Status = $"Capturing on {SelectedDevice.Description}";
        }
        catch (Exception exception)
        {
            Status = exception.Message;
        }

        RaiseCommandStates();
    }

    private void PauseCapture()
    {
        try
        {
            if (_captureService.IsPaused)
            {
                _captureService.Resume();
                Status = "Capture resumed.";
            }
            else
            {
                _captureService.Pause();
                Status = "Capture paused.";
            }
        }
        catch (Exception exception)
        {
            Status = exception.Message;
        }

        OnPropertyChanged(nameof(IsPaused));
        OnPropertyChanged(nameof(PauseActionText));
        RaiseCommandStates();
    }

    private void StopCapture()
    {
        InvalidatePendingCaptures();
        _captureService.Stop();
        Status = "Capture stopped.";
        OnPropertyChanged(nameof(IsPaused));
        OnPropertyChanged(nameof(PauseActionText));
        RaiseCommandStates();
    }

    private void ClearPackets()
    {
        InvalidatePendingCaptures();
        while (_pendingPackets.TryDequeue(out _)) { }
        while (_pendingErrors.TryDequeue(out _)) { }
        _capturedPackets.Clear();
        Packets.Clear();
        Flows.Clear();
        _flowTracker.Clear();
        SelectedPacket = null;
        OnPropertyChanged(nameof(CapturedCount));
        Status = "Packet list cleared.";
    }

    private void OnPacketCaptured(object? sender, RawCaptureEventArgs eventArgs)
    {
        lock (_lifecycleGate)
        {
            if (_disposed)
            {
                return;
            }

            if (_pendingRawCaptures.Count >= MaxPendingPacketCount)
            {
                _pendingRawCaptures.Dequeue();
                Interlocked.Increment(ref _droppedPacketCount);
            }

            _pendingRawCaptures.Enqueue(new RawCaptureEnvelope(eventArgs.Capture, _captureGeneration));
        }

        if (_parserWorker is not null)
        {
            _rawCaptureSignal.Release();
        }
    }

    private void OnCaptureError(object? sender, CaptureErrorEventArgs eventArgs)
    {
        lock (_lifecycleGate)
        {
            if (!_disposed)
            {
                _pendingErrors.Enqueue(eventArgs.Message);
            }
        }
    }

    private void OnBatchTimerTick(object? sender, EventArgs eventArgs)
    {
        ProcessPendingPackets();
    }

    private async Task ParseRawCaptureLoopAsync()
    {
        try
        {
            while (true)
            {
                await _rawCaptureSignal.WaitAsync(_parserCancellation.Token).ConfigureAwait(false);
                while (TryDequeueRawCapture(out var envelope))
                {
                    ParseRawCapture(envelope);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void ParseRawCapturesSynchronously(int maxCount)
    {
        var parsed = 0;
        while (parsed < maxCount && TryDequeueRawCapture(out var envelope))
        {
            ParseRawCapture(envelope);
            parsed++;
        }
    }

    private void ParseRawCapture(RawCaptureEnvelope envelope)
    {
        try
        {
            var packet = _packetParser.Parse(envelope.Capture);
            lock (_lifecycleGate)
            {
                if (_disposed || envelope.Generation != _captureGeneration)
                {
                    return;
                }

                _pendingPackets.Enqueue(packet);
            }
        }
        catch (Exception exception)
        {
            lock (_lifecycleGate)
            {
                if (!_disposed && envelope.Generation == _captureGeneration)
                {
                    _pendingErrors.Enqueue($"Packet parse error: {exception.Message}");
                }
            }
        }
    }

    private bool TryDequeueRawCapture(out RawCaptureEnvelope envelope)
    {
        lock (_lifecycleGate)
        {
            if (_pendingRawCaptures.Count == 0)
            {
                envelope = default;
                return false;
            }

            envelope = _pendingRawCaptures.Dequeue();
            return true;
        }
    }

    private void InvalidatePendingCaptures()
    {
        lock (_lifecycleGate)
        {
            _captureGeneration++;
            _pendingRawCaptures.Clear();
        }
    }

    private void RebuildVisibleCollections()
    {
        var selectedIndex = SelectedPacket?.Index;
        SelectedPacket = null;
        Packets.Clear();
        Flows.Clear();
        _flowTracker.Clear();

        foreach (var packet in _capturedPackets)
        {
            if (!_protocolFilter.Matches(packet, SelectedProtocol))
            {
                continue;
            }

            Packets.Add(new PacketRowViewModel(packet));
            _flowTracker.Add(packet);
        }

        foreach (var flow in _flowTracker.Snapshot())
        {
            Flows.Add(flow);
        }

        SelectedPacket = selectedIndex is null
            ? Packets.LastOrDefault()
            : Packets.FirstOrDefault(row => row.Index == selectedIndex);
    }

    private bool CanStartCapture()
    {
        return SelectedDevice is not null && !_captureService.IsCapturing;
    }

    private bool CanPauseCapture()
    {
        return _captureService.IsCapturing;
    }

    private void RaiseCommandStates()
    {
        _startCommand.RaiseCanExecuteChanged();
        _pauseCommand.RaiseCanExecuteChanged();
        _stopCommand.RaiseCanExecuteChanged();
        _clearCommand.RaiseCanExecuteChanged();
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private readonly record struct RawCaptureEnvelope(RawCapture Capture, int Generation);
}
