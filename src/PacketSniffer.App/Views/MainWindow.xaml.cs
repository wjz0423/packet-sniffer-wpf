using System.Windows;
using PacketSniffer.App.ViewModels;

namespace PacketSniffer.App.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainViewModel();
        DataContext = _viewModel;
    }

    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _viewModel.Dispose();
    }
}
