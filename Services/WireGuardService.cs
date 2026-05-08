using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using WireGuardGen.Models;

namespace WireGuardGen.Services
{
    public static class WireGuardService
    {
        // ──────────────────────────────────────────────────────────────
        // Kulcs generálás – BouncyCastle X25519 (RFC 7748 hitelesített)
        // ──────────────────────────────────────────────────────────────

        public static (string privateKey, string publicKey) GenerateKeyPair()
        {
            // 32 véletlen byte = privát kulcs nyersanyag
            var privBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(privBytes);

            // WireGuard kötelező clamping (RFC 7748 §5)
            privBytes[0]  &= 248;
            privBytes[31] &= 127;
            privBytes[31] |= 64;

            // Publikus kulcs levezetése BouncyCastle X25519-gyel
            var privParams = new X25519PrivateKeyParameters(privBytes, 0);
            var pubParams  = privParams.GeneratePublicKey();
            var pubBytes   = pubParams.GetEncoded();

            return (Convert.ToBase64String(privBytes), Convert.ToBase64String(pubBytes));
        }

        // ──────────────────────────────────────────────────────────────
        // SZERVER konfig (.conf fájl)
        // ──────────────────────────────────────────────────────────────

        public static string GenerateServerConfig(ServerConfig server, List<ClientConfig> clients)
        {
            var sb = new StringBuilder();
            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {server.PrivateKey}");
            sb.AppendLine($"Address = {server.Address}");
            sb.AppendLine($"ListenPort = {server.ListenPort}");
            if (!string.IsNullOrWhiteSpace(server.DNS))
                sb.AppendLine($"DNS = {server.DNS}");
            if (!string.IsNullOrWhiteSpace(server.PostUp))
                sb.AppendLine($"PostUp = {server.PostUp}");
            if (!string.IsNullOrWhiteSpace(server.PostDown))
                sb.AppendLine($"PostDown = {server.PostDown}");

            foreach (var client in clients)
            {
                sb.AppendLine();
                sb.AppendLine($"# {client.Name}");
                sb.AppendLine("[Peer]");
                sb.AppendLine($"PublicKey = {client.PublicKey}");
                var clientIp = client.Address.Split('/')[0];
                sb.AppendLine($"AllowedIPs = {clientIp}/32");
                if (client.PersistentKeepalive > 0)
                    sb.AppendLine($"PersistentKeepalive = {client.PersistentKeepalive}");
            }

            return sb.ToString();
        }

        // ──────────────────────────────────────────────────────────────
        // KLIENS konfig (.conf fájl)
        // ──────────────────────────────────────────────────────────────

        public static string GenerateClientConfig(ClientConfig client)
        {
            var sb = new StringBuilder();
            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {client.PrivateKey}");
            var addrParts = client.Address.Split('/');
            var mask = addrParts.Length > 1 ? addrParts[1] : "24";
            sb.AppendLine($"Address = {addrParts[0]}/{mask}");
            if (!string.IsNullOrWhiteSpace(client.DNS))
                sb.AppendLine($"DNS = {client.DNS}");

            sb.AppendLine();
            sb.AppendLine("[Peer]");
            sb.AppendLine($"PublicKey = {client.ServerPublicKey}");
            sb.AppendLine($"AllowedIPs = {client.AllowedIPs}");
            if (!string.IsNullOrWhiteSpace(client.Endpoint))
                sb.AppendLine($"Endpoint = {client.Endpoint}");
            if (client.PersistentKeepalive > 0)
                sb.AppendLine($"PersistentKeepalive = {client.PersistentKeepalive}");

            return sb.ToString();
        }

        // ──────────────────────────────────────────────────────────────
        // MikroTik peer felvételi parancsok
        // ──────────────────────────────────────────────────────────────

        public static string GenerateMikrotikCommands(ServerConfig server, List<ClientConfig> clients)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ================================================================");
            sb.AppendLine("# WireGuard szerver adatok");
            sb.AppendLine("# ================================================================");
            sb.AppendLine($"# Interface neve : {server.InterfaceName ?? "wg"}");
            sb.AppendLine($"# Publikus kulcs  : {server.PublicKey}");
            sb.AppendLine($"# Address         : {server.Address}");
            sb.AppendLine($"# Listen Port     : {server.ListenPort}");
            sb.AppendLine($"# Generálva       : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("# ================================================================");
            sb.AppendLine();
            sb.AppendLine("# Kliens peer felvételi parancsok (MikroTik RouterOS szintaxis)");
            sb.AppendLine();

            foreach (var client in clients)
            {
                var clientIp = client.Address.Split('/')[0];
                sb.AppendLine("-----------------------------------------------");
                sb.AppendLine(client.Name);
                sb.AppendLine($"/interface wireguard peers add name={client.Name} interface={server.InterfaceName ?? "wg"} public-key=\"{client.PublicKey}\" allowed-address={clientIp}/32 persistent-keepalive=00:00:{client.PersistentKeepalive:D2}");
                sb.AppendLine("-----------------------------------------------");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        // ──────────────────────────────────────────────────────────────
        // Mentés lemezre
        // ──────────────────────────────────────────────────────────────

        public static void SaveAll(GenerationRequest req, ServerConfig server, List<ClientConfig> clients)
        {
            var root   = Path.Combine(req.OutputPath, req.ProjectName);
            var srvDir = Path.Combine(root, "szerver");
            var cliDir = Path.Combine(root, "kliensek");

            Directory.CreateDirectory(srvDir);
            Directory.CreateDirectory(cliDir);

            File.WriteAllText(
                Path.Combine(srvDir, "mikrotik_parancsok.txt"),
                GenerateMikrotikCommands(server, clients),
                Encoding.UTF8);

            if (!string.IsNullOrEmpty(server.PrivateKey))
                File.WriteAllText(
                    Path.Combine(srvDir, "wg-server.conf"),
                    GenerateServerConfig(server, clients),
                    Encoding.UTF8);

            foreach (var client in clients)
                File.WriteAllText(
                    Path.Combine(cliDir, $"WG_{client.Index:D3}.conf"),
                    GenerateClientConfig(client),
                    Encoding.UTF8);
        }
    }
}
