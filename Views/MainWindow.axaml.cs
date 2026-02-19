using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using SharpPcap;
using PacketDotNet; 
using System;
using System.Collections.Generic;
using System.Linq; 

namespace Velvest.Views;

public partial class MainWindow : Window
{
    private ILiveDevice? _activeDevice;
    private int _totalPackets = 0, _tcpCount = 0, _udpCount = 0;
    
    // хранилище статистики по ip
    private Dictionary<string, int> _ipStats = new Dictionary<string, int>();
    
    // список для хранения детальной информации (для нижней панели)
    private List<string> _packetDetailsStorage = new List<string>();

    // список подозрительных портов
    private readonly int[] _suspiciousPorts = { 21, 22, 23, 3306, 3389 };

    public MainWindow() => InitializeComponent();

    // поиск активных сетевых интерфейсов
    private void OnScanClick(object sender, RoutedEventArgs e)
    {
        InterfaceList.Items.Clear();
        foreach (var dev in CaptureDeviceList.Instance) InterfaceList.Items.Add(dev);
    }

    // запуск процесса перехвата
    private void OnStartCaptureClick(object sender, RoutedEventArgs e)
    {
        if (InterfaceList.SelectedItem is ILiveDevice device)
        {
            _activeDevice = device;
            _activeDevice.OnPacketArrival += OnPacketArrival;
            _activeDevice.Open(DeviceModes.Promiscuous, 1000);
            _activeDevice.StartCapture();
            StatusText.Text = "SYSTEM: MONITORING ACTIVE";
        }
    }

    // временная остановка захвата
    private void OnStopCaptureClick(object sender, RoutedEventArgs e)
    {
        _activeDevice?.StopCapture();
        StatusText.Text = "SYSTEM: PAUSED";
    }

    // полная очистка всех накопленных данных
    private void OnClearLogClick(object sender, RoutedEventArgs e)
    {
        PacketLog.Items.Clear();
        TopSourcesList.Items.Clear();
        _ipStats.Clear();
        _packetDetailsStorage.Clear();
        _totalPackets = 0; _tcpCount = 0; _udpCount = 0;
        DetailsText.Text = "select a packet to inspect";
        UpdateStatsDisplay();
    }

    // событие клика по строке в логе
    private void OnPacketSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (PacketLog.SelectedIndex >= 0 && PacketLog.SelectedIndex < _packetDetailsStorage.Count)
        {
            DetailsText.Text = _packetDetailsStorage[PacketLog.SelectedIndex];
        }
    }

    // логика обработки каждого прилетевшего пакета
    private void OnPacketArrival(object sender, PacketCapture e)
    {
        var raw = e.GetPacket();
        var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
        var ip = packet.Extract<IPPacket>();

        if (ip != null)
        {
            _totalPackets++;
            // фиксация номера пакета сразу, чтобы асинхронность его не сбила
            int currentNum = _totalPackets;

            string srcIp = ip.SourceAddress.ToString();
            
            if (_ipStats.ContainsKey(srcIp)) _ipStats[srcIp]++;
            else _ipStats[srcIp] = 1;

            var tcp = packet.Extract<TcpPacket>();
            var udp = packet.Extract<UdpPacket>();
            if (tcp != null) _tcpCount++;
            if (udp != null) _udpCount++;

            string alert = "";
            bool suspicious = false;

            if (tcp != null && _suspiciousPorts.Contains(tcp.DestinationPort))
            {
                alert = "[!] ";
                suspicious = true;
            }

            if (ip.TimeToLive < 10)
            {
                alert = "[!] ";
                suspicious = true;
            }

            string chksum = "n/a";
            if (ip is IPv4Packet ipv4) chksum = "0x" + ipv4.Checksum.ToString("X");

            // отчет для нижней панели
            string details = $"[ packet #{currentNum} ]\n" +
                             $"status: {(suspicious ? "warning / anomaly detected" : "normal")}\n" +
                             $"timestamp: {DateTime.Now:HH:mm:ss.fff}\n" +
                             $"protocol: {ip.Protocol}\n" +
                             $"source: {ip.SourceAddress}\n" +
                             $"destination: {ip.DestinationAddress}\n" +
                             $"payload size: {raw.Data.Length} bytes\n" +
                             $"ttl: {ip.TimeToLive}\n" +
                             $"checksum: {chksum}";

            Dispatcher.UIThread.InvokeAsync(() =>
            {
                // форматир строку для главного лога
                string idStr = $"#{currentNum}".PadRight(7);
                string timeStr = $"[{DateTime.Now:HH:mm:ss}]".PadRight(12);
                string entry = $"{idStr} {timeStr} {alert}{ip.Protocol}: {srcIp} -> {ip.DestinationAddress}";
                
                // фильтр поиска
                if (string.IsNullOrEmpty(FilterInput.Text) || entry.Contains(FilterInput.Text, StringComparison.OrdinalIgnoreCase))
                {
                    PacketLog.Items.Add(entry);
                    _packetDetailsStorage.Add(details);

                    // лог в пределах 100 записей(пока что), чтобы не тормозило
                    if (PacketLog.Items.Count > 100) 
                    {
                        PacketLog.Items.RemoveAt(0);
                        _packetDetailsStorage.RemoveAt(0);
                    }
                }
                UpdateStatsDisplay();
                UpdateTopSources(); 
            });
        }
    }

    // обновление визуальных счетчиков
    private void UpdateStatsDisplay()
    {
        TotalPacketsText.Text = _totalPackets.ToString();
        TcpCountText.Text = _tcpCount.ToString();
        UdpCountText.Text = _udpCount.ToString();
    }

    // обновление рейтинга самых активных ip
    private void UpdateTopSources()
    {
        TopSourcesList.Items.Clear();
        var top = _ipStats.OrderByDescending(x => x.Value).Take(5);
        foreach (var item in top)
        {
            TopSourcesList.Items.Add($"{item.Key} ({item.Value})");
        }
    }
}