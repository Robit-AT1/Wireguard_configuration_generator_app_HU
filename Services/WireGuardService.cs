using System.IO;
using System.Security.Cryptography;
using System.Text;
using WireGuardGen.Models;

namespace WireGuardGen.Services
{
    public static class WireGuardService
    {
        // ──────────────────────────────────────────────────────────────
        // Kulcs generálás (Curve25519, pure managed)
        // ──────────────────────────────────────────────────────────────

        public static (string privateKey, string publicKey) GenerateKeyPair()
        {
            // 32 random byte = privát kulcs
            var privBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(privBytes);

            // WireGuard clamping
            privBytes[0]  &= 248;
            privBytes[31] &= 127;
            privBytes[31] |= 64;

            var pubBytes = Curve25519.GetPublicKey(privBytes);

            return (Convert.ToBase64String(privBytes), Convert.ToBase64String(pubBytes));
        }

        // ──────────────────────────────────────────────────────────────
        // IP cím segédlet
        // ──────────────────────────────────────────────────────────────

        public static string BuildAddress(string networkBase, string lastOctet, int mask)
            => $"{networkBase}.{lastOctet}/{mask}";

        public static string BuildAddressHost(string networkBase, int hostNum, int mask)
            => $"{networkBase}.{hostNum}/{mask}";

        // ──────────────────────────────────────────────────────────────
        // SZERVER konfig generálás
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
                // allowed-address a szerver oldalán = kliens /32 IP-je
                var clientIp = client.Address.Split('/')[0];
                sb.AppendLine($"AllowedIPs = {clientIp}/32");
                if (client.PersistentKeepalive > 0)
                    sb.AppendLine($"PersistentKeepalive = {client.PersistentKeepalive}");
            }

            return sb.ToString();
        }

        // ──────────────────────────────────────────────────────────────
        // KLIENS konfig generálás (.conf fájl)
        // ──────────────────────────────────────────────────────────────

        public static string GenerateClientConfig(ClientConfig client)
        {
            var sb = new StringBuilder();
            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {client.PrivateKey}");
            // Kliens address: saját IP /24-gyel (vagy a megadott maszkkal)
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
        // MikroTik felvételes parancsok (szerver fájlba)
        // ──────────────────────────────────────────────────────────────

        public static string GenerateMikrotikCommands(ServerConfig server, List<ClientConfig> clients)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ================================================================");
            sb.AppendLine("# WireGuard szerver adatok");
            sb.AppendLine("# ================================================================");
            sb.AppendLine($"# Interface neve : {server.InterfaceName ?? "wg-kulsos"}");
            sb.AppendLine($"# Publikus kulcs  : {server.PublicKey}");
            sb.AppendLine($"# Address         : {server.Address}");
            sb.AppendLine($"# Listen Port     : {server.ListenPort}");
            sb.AppendLine($"# Generálva       : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("# ================================================================");
            sb.AppendLine();
            sb.AppendLine("# ----------------------------------------------------------------");
            sb.AppendLine("# Kliens peer felvételi parancsok (MikroTik RouterOS szintaxis)");
            sb.AppendLine("# ----------------------------------------------------------------");
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
        // Teljes mentés a lemezre
        // ──────────────────────────────────────────────────────────────

        public static void SaveAll(GenerationRequest req, ServerConfig server, List<ClientConfig> clients)
        {
            var root    = Path.Combine(req.OutputPath, req.ProjectName);
            var srvDir  = Path.Combine(root, "szerver");
            var cliDir  = Path.Combine(root, "kliensek");

            Directory.CreateDirectory(srvDir);
            Directory.CreateDirectory(cliDir);

            // Szerver: mikrotik parancsok + szerver .conf (ha új generálás)
            var mikrotik = GenerateMikrotikCommands(server, clients);
            File.WriteAllText(Path.Combine(srvDir, "mikrotik_parancsok.txt"), mikrotik, Encoding.UTF8);

            if (!string.IsNullOrEmpty(server.PrivateKey))
            {
                var srvConf = GenerateServerConfig(server, clients);
                File.WriteAllText(Path.Combine(srvDir, "wg-server.conf"), srvConf, Encoding.UTF8);
            }

            // Kliensek
            foreach (var client in clients)
            {
                var fileName = $"WG_{client.Index:D3}.conf";
                var content  = GenerateClientConfig(client);
                File.WriteAllText(Path.Combine(cliDir, fileName), content, Encoding.UTF8);
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Curve25519 scalar multiplication (pure C#, no native deps)
    // RFC 7748 compliant
    // ──────────────────────────────────────────────────────────────────

    internal static class Curve25519
    {
        private static readonly long[] BASE_POINT = { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public static byte[] GetPublicKey(byte[] privateKey)
        {
            var result = ScalarMult(privateKey, BASE_POINT);
            return FieldToBytes(result);
        }

        private static long[] ScalarMult(byte[] n, long[] basePoint)
        {
            long[] x1 = (long[])basePoint.Clone();
            long[] x2 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            long[] z2 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            long[] x3 = (long[])basePoint.Clone();
            long[] z3 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            int swap = 0;
            for (int pos = 254; pos >= 0; pos--)
            {
                int b = (n[pos / 8] >> (pos & 7)) & 1;
                swap ^= b;
                CSwap(swap, x2, x3);
                CSwap(swap, z2, z3);
                swap = b;

                var A  = Add(x2, z2);
                var AA = Square(A);
                var B  = Sub(x2, z2);
                var BB = Square(B);
                var E  = Sub(AA, BB);
                var C  = Add(x3, z3);
                var D  = Sub(x3, z3);
                var DA = Mul(D, A);
                var CB = Mul(C, B);
                var t1 = Add(DA, CB);
                x3 = Square(t1);
                var t2 = Sub(DA, CB);
                z3 = Mul(Square(t2), x1);
                x2 = Mul(AA, BB);
                z2 = Mul(E, Add(AA, MulScalar(E, 121665)));
            }

            CSwap(swap, x2, x3);
            CSwap(swap, z2, z3);

            return Mul(x2, Pow22523(z2));
        }

        private static void CSwap(int swap, long[] a, long[] b)
        {
            long mask = -swap;
            for (int i = 0; i < 10; i++)
            {
                long t = mask & (a[i] ^ b[i]);
                a[i] ^= t;
                b[i] ^= t;
            }
        }

        private static long[] Add(long[] a, long[] b)
        {
            var out_ = new long[10];
            for (int i = 0; i < 10; i++) out_[i] = a[i] + b[i];
            return out_;
        }

        private static long[] Sub(long[] a, long[] b)
        {
            var out_ = new long[10];
            for (int i = 0; i < 10; i++) out_[i] = a[i] - b[i];
            return out_;
        }

        private static long[] MulScalar(long[] a, long b)
        {
            var out_ = new long[10];
            for (int i = 0; i < 10; i++) out_[i] = a[i] * b;
            return out_;
        }

        private static long[] Square(long[] f) => Mul(f, f);

        private static long[] Mul(long[] f, long[] g)
        {
            long f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4],f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
            long g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4],g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];

            long g1_19=19*g1,g2_19=19*g2,g3_19=19*g3,g4_19=19*g4;
            long g5_19=19*g5,g6_19=19*g6,g7_19=19*g7,g8_19=19*g8,g9_19=19*g9;
            long f1_2=2*f1,f3_2=2*f3,f5_2=2*f5,f7_2=2*f7,f9_2=2*f9;

            long h0=f0*g0+f1_2*g9_19+f2*g8_19+f3_2*g7_19+f4*g6_19+f5_2*g5_19+f6*g4_19+f7_2*g3_19+f8*g2_19+f9_2*g1_19;
            long h1=f0*g1+f1*g0+f2*g9_19+f3_2*g8_19+f4*g7_19+f5_2*g6_19+f6*g5_19+f7_2*g4_19+f8*g3_19+f9*g2_19;
            long h2=f0*g2+f1_2*g1+f2*g0+f3_2*g9_19+f4*g8_19+f5_2*g7_19+f6*g6_19+f7_2*g5_19+f8*g4_19+f9_2*g3_19;
            long h3=f0*g3+f1*g2+f2*g1+f3*g0+f4*g9_19+f5_2*g8_19+f6*g7_19+f7_2*g6_19+f8*g5_19+f9*g4_19;
            long h4=f0*g4+f1_2*g3+f2*g2+f3_2*g1+f4*g0+f5_2*g9_19+f6*g8_19+f7_2*g7_19+f8*g6_19+f9_2*g5_19;
            long h5=f0*g5+f1*g4+f2*g3+f3*g2+f4*g1+f5*g0+f6*g9_19+f7_2*g8_19+f8*g7_19+f9*g6_19;
            long h6=f0*g6+f1_2*g5+f2*g4+f3_2*g3+f4*g2+f5_2*g1+f6*g0+f7_2*g9_19+f8*g8_19+f9_2*g7_19;
            long h7=f0*g7+f1*g6+f2*g5+f3*g4+f4*g3+f5*g2+f6*g1+f7*g0+f8*g9_19+f9*g8_19;
            long h8=f0*g8+f1_2*g7+f2*g6+f3_2*g5+f4*g4+f5_2*g3+f6*g2+f7_2*g1+f8*g0+f9_2*g9_19;
            long h9=f0*g9+f1*g8+f2*g7+f3*g6+f4*g5+f5*g4+f6*g3+f7*g2+f8*g1+f9*g0;

            return Carry(h0,h1,h2,h3,h4,h5,h6,h7,h8,h9);
        }

        private static long[] Carry(long h0,long h1,long h2,long h3,long h4,long h5,long h6,long h7,long h8,long h9)
        {
            long c;
            c=h0>>26; h1+=c; h0-=c<<26;
            c=h1>>25; h2+=c; h1-=c<<25;
            c=h2>>26; h3+=c; h2-=c<<26;
            c=h3>>25; h4+=c; h3-=c<<25;
            c=h4>>26; h5+=c; h4-=c<<26;
            c=h5>>25; h6+=c; h5-=c<<25;
            c=h6>>26; h7+=c; h6-=c<<26;
            c=h7>>25; h8+=c; h7-=c<<25;
            c=h8>>26; h9+=c; h8-=c<<26;
            c=h9>>25; h0+=c*19; h9-=c<<25;
            c=h0>>26; h1+=c; h0-=c<<26;
            return new[]{h0,h1,h2,h3,h4,h5,h6,h7,h8,h9};
        }

        private static long[] Pow22523(long[] z)
        {
            // z^(p-2) = z^(2^255-21) for field inversion
            var z2  = Square(z);
            var z8  = Square(Square(z2));
            var z9  = Mul(z, z8);
            var z11 = Mul(z2, z9);
            var z22 = Square(z11);
            var z_5_0 = Mul(z9, z22);
            long[] t = z_5_0;
            for (int i=0;i<5;i++) t=Square(t);
            var z_10_0 = Mul(t, z_5_0);
            t = z_10_0;
            for (int i=0;i<10;i++) t=Square(t);
            var z_20_0 = Mul(t, z_10_0);
            t = z_20_0;
            for (int i=0;i<20;i++) t=Square(t);
            t = Mul(t, z_20_0);
            for (int i=0;i<10;i++) t=Square(t);
            var z_40_0 = Mul(t, z_10_0);
            t = z_40_0;
            for (int i=0;i<40;i++) t=Square(t);
            t = Mul(t, z_40_0);
            for (int i=0;i<5;i++) t=Square(t);
            return Mul(t, z_5_0);
        }

        private static byte[] FieldToBytes(long[] h)
        {
            // Reduce
            long[] f = (long[])h.Clone();
            long c;
            c=f[9]>>25; f[0]+=c*19; f[9]-=c<<25;
            c=f[0]>>26; f[1]+=c; f[0]-=c<<26;

            var s = new byte[32];
            s[ 0] = (byte)(f[0]>>0);
            s[ 1] = (byte)(f[0]>>8);
            s[ 2] = (byte)(f[0]>>16);
            s[ 3] = (byte)((f[0]>>24)|(f[1]<<2));
            s[ 4] = (byte)(f[1]>>6);
            s[ 5] = (byte)(f[1]>>14);
            s[ 6] = (byte)((f[1]>>22)|(f[2]<<3));
            s[ 7] = (byte)(f[2]>>5);
            s[ 8] = (byte)(f[2]>>13);
            s[ 9] = (byte)((f[2]>>21)|(f[3]<<5));
            s[10] = (byte)(f[3]>>3);
            s[11] = (byte)(f[3]>>11);
            s[12] = (byte)((f[3]>>19)|(f[4]<<6));
            s[13] = (byte)(f[4]>>2);
            s[14] = (byte)(f[4]>>10);
            s[15] = (byte)(f[4]>>18);
            s[16] = (byte)(f[5]>>0);
            s[17] = (byte)(f[5]>>8);
            s[18] = (byte)(f[5]>>16);
            s[19] = (byte)((f[5]>>24)|(f[6]<<1));
            s[20] = (byte)(f[6]>>7);
            s[21] = (byte)(f[6]>>15);
            s[22] = (byte)((f[6]>>23)|(f[7]<<3));
            s[23] = (byte)(f[7]>>5);
            s[24] = (byte)(f[7]>>13);
            s[25] = (byte)((f[7]>>21)|(f[8]<<4));
            s[26] = (byte)(f[8]>>4);
            s[27] = (byte)(f[8]>>12);
            s[28] = (byte)((f[8]>>20)|(f[9]<<6));
            s[29] = (byte)(f[9]>>2);
            s[30] = (byte)(f[9]>>10);
            s[31] = (byte)(f[9]>>18);
            return s;
        }
    }
}
