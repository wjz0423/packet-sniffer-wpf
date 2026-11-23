namespace PacketSniffer.Tests;

public sealed class MainWindowMarkupTests
{
    [Fact]
    public void ReadOnlyHexTextBindingIsOneWay()
    {
        var root = FindRepositoryRoot();
        var markupPath = Path.Combine(root, "src", "PacketSniffer.App", "Views", "MainWindow.xaml");
        var markup = File.ReadAllText(markupPath);

        Assert.Contains("Text=\"{Binding SelectedHexText, Mode=OneWay}\"", markup, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PacketSniffer.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
