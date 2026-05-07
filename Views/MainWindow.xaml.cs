using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using WireGuardGen.Models;
using WireGuardGen.Services;

namespace WireGuardGen.Views
{
    public partial class MainWindow : Window
    {
        private string _lastOutputPath = "";

        public MainWindow()
        {
            InitializeComponent();
            InitPlaceholders();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Biztosítja hogy az első panel látható legyen betöltés után
            ShowPanel(1);
            RbTab1.IsChecked = true;
        }

        // ──────────────────────────────────────────────────────────────
        // Tab váltás – RadioButton alapú, TabControl template NÉLKÜL
        // ──────────────────────────────────────────────────────────────

        private void TabBtn_Checked(object sender, RoutedEventArgs e)
        {
            if (Panel1 == null) return; // design-time guard
            if (sender == RbTab1) ShowPanel(1);
            else if (sender == RbTab2) ShowPanel(2);
            else if (sender == RbTab3) ShowPanel(3);
        }

        private void ShowPanel(int n)
        {
            if (Panel1 == null) return;
            Panel1.Visibility = n == 1 ? Visibility.Visible : Visibility.Collapsed;
            Panel2.Visibility = n == 2 ? Visibility.Visible : Visibility.Collapsed;
            Panel3.Visibility = n == 3 ? Visibility.Visible : Visibility.Collapsed;
        }

        // ──────────────────────────────────────────────────────────────
        // Placeholder kezelés
        // ──────────────────────────────────────────────────────────────

        private static readonly SolidColorBrush MutedBrush  = new(Color.FromRgb(0x48, 0x4F, 0x58));
        private static readonly SolidColorBrush NormalBrush = new(Color.FromRgb(0xE6, 0xED, 0xF3));

        private void InitPlaceholders()
        {
            TextBox[] fields =
            [
                TxtProjectName, TxtNetworkBase, TxtEndpoint1, TxtDns1, TxtPostUp, TxtPostDown,
                TxtProjectName2, TxtServerPubKey, TxtServerPrivKey,
                TxtEndpoint2, TxtNetBase2, TxtClientDns1, TxtClientDns2
            ];
            foreach (var tb in fields) SetPlaceholder(tb);
        }

        private static void SetPlaceholder(TextBox tb)
        {
            if (tb.Tag is not string tag || string.IsNullOrEmpty(tag)) return;
            if (string.IsNullOrEmpty(tb.Text) || tb.Text == tag)
            {
                tb.Text = tag;
                tb.Foreground = MutedBrush;
            }
        }

        private void Placeholder_GotFocus(object sender, RoutedEventArgs e)
        {
            if (sender is TextBox tb && tb.Tag is string tag && tb.Text == tag)
            {
                tb.Text = "";
                tb.Foreground = NormalBrush;
            }
        }

        private void Placeholder_LostFocus(object sender, RoutedEventArgs e)
        {
            if (sender is TextBox tb) SetPlaceholder(tb);
        }

        private string Val(TextBox tb)
        {
            var v = tb.Text?.Trim() ?? "";
            return (tb.Tag is string tag && v == tag) ? "" : v;
        }

        // ──────────────────────────────────────────────────────────────
        // Mappa böngésző
        // ──────────────────────────────────────────────────────────────

        private static string? BrowseFolder()
        {
            var dlg = new OpenFolderDialog { Title = "Válassza ki a mentési mappát" };
            return dlg.ShowDialog() == true ? dlg.FolderName : null;
        }

        private void BrowseOutput1_Click(object sender, RoutedEventArgs e)
        {
            var p = BrowseFolder();
            if (p != null) { TxtOutputPath1.Text = p; TxtOutputPath1.Foreground = NormalBrush; }
        }

        private void BrowseOutput2_Click(object sender, RoutedEventArgs e)
        {
            var p = BrowseFolder();
            if (p != null) { TxtOutputPath2.Text = p; TxtOutputPath2.Foreground = NormalBrush; }
        }

        // ──────────────────────────────────────────────────────────────
        // TAB 1 – Teljes generálás
        // ──────────────────────────────────────────────────────────────

        private void BtnGenerate1_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var projectName = Val(TxtProjectName);
                var outputPath  = TxtOutputPath1.Text?.Trim() ?? "";
                var networkBase = Val(TxtNetworkBase);
                var endpoint    = Val(TxtEndpoint1);
                var ifName      = TxtIfName1.Text?.Trim() ?? "";

                if (!Validate(projectName,  "Kérjük adja meg a projekt nevét!"))                    return;
                if (!ValidatePath(outputPath, "Kérjük válassza ki a mentési mappát!"))               return;
                if (!Validate(networkBase,   "Kérjük adja meg a hálózat alapját!\nPl.: 10.0.0"))    return;
                if (!Validate(endpoint,      "Kérjük adja meg az Endpoint-ot!\nPl.: vpn.ceged.hu:51820")) return;
                if (!Validate(ifName,        "Kérjük adja meg az interface nevét!"))                 return;
                if (!ParseInt(TxtPort1.Text,        1, 65535, out int port,      "Érvénytelen port! (1-65535)")) return;
                if (!ParseInt(TxtSubnetMask.Text,   8, 30,    out int mask,      "Érvénytelen maszk! (8-30)")) return;
                if (!ParseInt(TxtClientCount1.Text, 1, 250,   out int cnt,       "Érvénytelen kliens szám! (1-250)")) return;
                if (!ParseInt(TxtStartIp.Text,      2, 253,   out int startIp,   "Érvénytelen kezdő IP oktet! (2-253)")) return;
                if (!ParseInt(TxtServerIpOctet.Text,1, 254,   out int srvOctet,  "Érvénytelen szerver oktet!")) return;
                if (!ParseInt(TxtKeepalive1.Text,   0, 3600,  out int keepalive, "Érvénytelen Keepalive!")) return;

                SetStatus("Kulcspárok generálása…", "#D29922");

                var (srvPriv, srvPub) = WireGuardService.GenerateKeyPair();

                var server = new ServerConfig
                {
                    PrivateKey    = srvPriv,
                    PublicKey     = srvPub,
                    Address       = $"{networkBase}.{srvOctet}/{mask}",
                    ListenPort    = port,
                    DNS           = Val(TxtDns1),
                    Endpoint      = endpoint,
                    InterfaceName = ifName,
                    PostUp        = Val(TxtPostUp),
                    PostDown      = Val(TxtPostDown),
                    AllowedIPs    = TxtAllowedIPs1.Text.Trim(),
                    PersistentKeepalive = keepalive
                };

                var clients = BuildClients(cnt, 1, networkBase, startIp, mask, srvPub, endpoint,
                                           TxtAllowedIPs1.Text.Trim(), Val(TxtClientDns1), keepalive);

                var req = new GenerationRequest
                {
                    Mode        = GenerationMode.NewComplete,
                    ProjectName = projectName,
                    OutputPath  = outputPath
                };

                SetStatus("Fájlok mentése…", "#D29922");
                WireGuardService.SaveAll(req, server, clients);

                if (ChkQr1.IsChecked == true)
                {
                    SetStatus("QR kódok generálása…", "#D29922");
                    SaveQrCodes(req, clients);
                }

                _lastOutputPath = Path.Combine(outputPath, projectName);
                ShowResult(req, server, clients, true);
                SetStatus($"✅ Sikeres! {cnt} kliens konfig + QR kódok mentve.", "#3FB950");
            }
            catch (Exception ex)
            {
                Error($"Hiba a generálás során:\n{ex.Message}");
                SetStatus("❌ Hiba!", "#F85149");
            }
        }

        // ──────────────────────────────────────────────────────────────
        // TAB 2 – Kliens generálás
        // ──────────────────────────────────────────────────────────────

        private void BtnGenerate2_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var projectName = Val(TxtProjectName2);
                var outputPath  = TxtOutputPath2.Text?.Trim() ?? "";
                var srvPub      = Val(TxtServerPubKey);
                var srvPriv     = Val(TxtServerPrivKey);
                var endpoint    = Val(TxtEndpoint2);
                var ifName      = TxtIfName2.Text?.Trim() ?? "";
                var netBase     = Val(TxtNetBase2);

                if (!Validate(projectName, "Kérjük adja meg a projekt nevét!"))                      return;
                if (!ValidatePath(outputPath, "Kérjük válassza ki a mentési mappát!"))               return;
                if (!Validate(srvPub,      "A szerver publikus kulcsa kötelező!"))                   return;
                if (!Validate(endpoint,    "Kérjük adja meg az Endpoint-ot!"))                       return;
                if (!Validate(netBase,     "Kérjük adja meg a hálózat alapját!\nPl.: 10.101.0"))    return;
                if (!Validate(ifName,      "Kérjük adja meg az interface nevét!"))                   return;
                if (!ParseInt(TxtPort2.Text,        1, 65535, out int port,      "Érvénytelen port!")) return;
                if (!ParseInt(TxtMask2.Text,        8, 30,    out int mask,      "Érvénytelen maszk!")) return;
                if (!ParseInt(TxtClientCount2.Text, 1, 250,   out int cnt,       "Érvénytelen kliens szám!")) return;
                if (!ParseInt(TxtStartIp2.Text,     2, 253,   out int startIp,   "Érvénytelen kezdő IP oktet!")) return;
                if (!ParseInt(TxtSrvOctet2.Text,    1, 254,   out int srvOctet,  "Érvénytelen szerver oktet!")) return;
                if (!ParseInt(TxtKeepalive2.Text,   0, 3600,  out int keepalive, "Érvénytelen Keepalive!")) return;
                if (!ParseInt(TxtIndexOffset.Text,  1, 9999,  out int offset,    "Érvénytelen sorszám offset!")) return;

                var server = new ServerConfig
                {
                    PrivateKey    = srvPriv,
                    PublicKey     = srvPub,
                    Address       = $"{netBase}.{srvOctet}/{mask}",
                    ListenPort    = port,
                    Endpoint      = endpoint,
                    InterfaceName = ifName,
                    AllowedIPs    = TxtAllowedIPs2.Text.Trim(),
                    PersistentKeepalive = keepalive
                };

                var clients = BuildClients(cnt, offset, netBase, startIp, mask, srvPub, endpoint,
                                           TxtAllowedIPs2.Text.Trim(), Val(TxtClientDns2), keepalive);

                var req = new GenerationRequest
                {
                    Mode        = GenerationMode.ClientsFromServer,
                    ProjectName = projectName,
                    OutputPath  = outputPath
                };

                WireGuardService.SaveAll(req, server, clients);

                if (ChkQr2.IsChecked == true)
                {
                    SetStatus("QR kódok generálása…", "#D29922");
                    SaveQrCodes(req, clients);
                }

                _lastOutputPath = Path.Combine(outputPath, projectName);
                ShowResult(req, server, clients, false);
                SetStatus($"✅ Kész! {cnt} kliens konfig mentve.", "#3FB950");
            }
            catch (Exception ex)
            {
                Error($"Hiba:\n{ex.Message}");
                SetStatus("❌ Hiba!", "#F85149");
            }
        }

        // ──────────────────────────────────────────────────────────────
        // Segéd: kliens lista
        // ──────────────────────────────────────────────────────────────

        private static List<ClientConfig> BuildClients(int count, int indexOffset,
            string netBase, int startIp, int mask, string srvPub, string endpoint,
            string allowedIPs, string dns, int keepalive)
        {
            var list = new List<ClientConfig>();
            for (int i = 0; i < count; i++)
            {
                var (priv, pub) = WireGuardService.GenerateKeyPair();
                list.Add(new ClientConfig
                {
                    Index           = indexOffset + i,
                    Name            = $"WG_{indexOffset + i:D3}",
                    PrivateKey      = priv,
                    PublicKey       = pub,
                    Address         = $"{netBase}.{startIp + i}/{mask}",
                    DNS             = dns,
                    ServerPublicKey = srvPub,
                    AllowedIPs      = allowedIPs,
                    Endpoint        = endpoint,
                    PersistentKeepalive = keepalive
                });
            }
            return list;
        }

        // ──────────────────────────────────────────────────────────────
        // QR mentés
        // ──────────────────────────────────────────────────────────────

        private static void SaveQrCodes(GenerationRequest req, List<ClientConfig> clients)
        {
            var cliDir = Path.Combine(req.OutputPath, req.ProjectName, "kliensek");
            Directory.CreateDirectory(cliDir);
            foreach (var c in clients)
            {
                var confText = WireGuardService.GenerateClientConfig(c);
                var pngPath  = Path.Combine(cliDir, $"WG_{c.Index:D3}_qr.png");
                QrService.SaveQrPng(confText, pngPath);
            }
        }

        // ──────────────────────────────────────────────────────────────
        // Eredmény megjelenítés
        // ──────────────────────────────────────────────────────────────

        private void ShowResult(GenerationRequest req, ServerConfig server,
                                List<ClientConfig> clients, bool isNew)
        {
            var root = Path.Combine(req.OutputPath, req.ProjectName);
            var sb   = new System.Text.StringBuilder();

            sb.AppendLine("╔══════════════════════════════════════════════════════════════════╗");
            sb.AppendLine($"║  WireGuard Konfiguráció — {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("╚══════════════════════════════════════════════════════════════════╝");
            sb.AppendLine();
            sb.AppendLine($"  Projekt   : {req.ProjectName}");
            sb.AppendLine($"  Mappa     : {root}");
            sb.AppendLine($"  Kliensek  : {clients.Count} db");
            sb.AppendLine();

            if (isNew)
            {
                sb.AppendLine("── SZERVER ─────────────────────────────────────────────────────────");
                sb.AppendLine($"  Privát kulcs  : {server.PrivateKey}");
                sb.AppendLine($"  Publikus kulcs: {server.PublicKey}");
                sb.AppendLine($"  Address       : {server.Address}");
                sb.AppendLine($"  ListenPort    : {server.ListenPort}");
                sb.AppendLine($"  Endpoint      : {server.Endpoint}");
                sb.AppendLine();
            }

            sb.AppendLine("── KLIENSEK ────────────────────────────────────────────────────────");
            foreach (var c in clients)
            {
                var ip = c.Address.Split('/')[0];
                sb.AppendLine($"  [{c.Name}]  IP: {ip,-15}  PubKey: {c.PublicKey[..24]}…");
            }

            sb.AppendLine();
            sb.AppendLine("── FÁJLOK ──────────────────────────────────────────────────────────");
            sb.AppendLine($"  {Path.Combine(root, "szerver", "mikrotik_parancsok.txt")}");
            if (isNew || !string.IsNullOrEmpty(server.PrivateKey))
                sb.AppendLine($"  {Path.Combine(root, "szerver", "wg-server.conf")}");
            foreach (var c in clients)
            {
                sb.AppendLine($"  {Path.Combine(root, "kliensek", $"WG_{c.Index:D3}.conf")}");
                sb.AppendLine($"  {Path.Combine(root, "kliensek", $"WG_{c.Index:D3}_qr.png")}");
            }

            TxtLog.Text = sb.ToString();
            TxtResultTitle.Text = $"✅  {req.ProjectName} — {clients.Count} kliens konfig generálva";
            TxtResultPath.Text  = $"Mappa: {root}";
            BtnOpenFolder.IsEnabled = true;

            // Átváltás az Eredmény panelre
            RbTab3.IsChecked = true;
        }

        // ──────────────────────────────────────────────────────────────
        // Eredmény tab gombok
        // ──────────────────────────────────────────────────────────────

        private void BtnOpenFolder_Click(object sender, RoutedEventArgs e)
        {
            if (Directory.Exists(_lastOutputPath))
                Process.Start("explorer.exe", _lastOutputPath);
            else
                Error("A mappa nem található:\n" + _lastOutputPath);
        }

        private void BtnCopyLog_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(TxtLog.Text);
            SetStatus("📋 Log vágólapra másolva.", "#3FB950");
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            TxtLog.Text = "Log törölve.";
            BtnOpenFolder.IsEnabled = false;
            TxtResultTitle.Text = "Generálás eredménye";
            TxtResultPath.Text  = "Mappa: —";
        }

        // ──────────────────────────────────────────────────────────────
        // Validáció
        // ──────────────────────────────────────────────────────────────

        private static bool Validate(string v, string msg)
        {
            if (!string.IsNullOrWhiteSpace(v)) return true;
            MessageBox.Show(msg, "Hiányzó adat", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        private static bool ValidatePath(string v, string msg)
        {
            if (!string.IsNullOrWhiteSpace(v) && v != "Válasszon mappát…") return true;
            MessageBox.Show(msg, "Hiányzó adat", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        private static bool ParseInt(string s, int min, int max, out int result, string msg)
        {
            if (int.TryParse(s?.Trim(), out result) && result >= min && result <= max) return true;
            MessageBox.Show($"{msg}\nMegengedett tartomány: {min} – {max}", "Érvénytelen adat",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        private static void Error(string msg)
            => MessageBox.Show(msg, "Hiba", MessageBoxButton.OK, MessageBoxImage.Warning);

        private void SetStatus(string msg, string hex = "#8B949E")
        {
            StatusText.Text = msg;
            try { StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); }
            catch { /* ignore */ }
        }
    }
}
