namespace WireGuardGen.Models
{
    public class ServerConfig
    {
        public string PrivateKey { get; set; } = "";
        public string PublicKey { get; set; } = "";
        public string Address { get; set; } = "";       // pl. 10.0.0.1/24
        public int ListenPort { get; set; } = 51820;
        public string DNS { get; set; } = "";
        public string Endpoint { get; set; } = "";      // pl. vpn.example.com:51820
        public string InterfaceName { get; set; } = "wg-kulsos";
        public string PostUp { get; set; } = "";
        public string PostDown { get; set; } = "";
        public string AllowedIPs { get; set; } = "0.0.0.0/0";
        public int PersistentKeepalive { get; set; } = 15;
    }

    public class ClientConfig
    {
        public int Index { get; set; }
        public string Name { get; set; } = "";
        public string PrivateKey { get; set; } = "";
        public string PublicKey { get; set; } = "";
        public string Address { get; set; } = "";       // pl. 10.0.0.2/24
        public string DNS { get; set; } = "";
        public string ServerPublicKey { get; set; } = "";
        public string AllowedIPs { get; set; } = "0.0.0.0/0";
        public string Endpoint { get; set; } = "";
        public int PersistentKeepalive { get; set; } = 15;
    }

    public class GenerationRequest
    {
        public GenerationMode Mode { get; set; }
        public string ProjectName { get; set; } = "WireGuardVPN";
        public string OutputPath { get; set; } = "";

        // Hálózat beállítások
        public string NetworkBase { get; set; } = "10.0.0";    // pl. 10.0.0
        public int SubnetMask { get; set; } = 24;
        public int StartingClientIp { get; set; } = 2;         // .2-vel kezd kliensenként

        // Szerver
        public string ServerIpLastOctet { get; set; } = "1";
        public string ServerPrivateKey { get; set; } = "";
        public string ServerPublicKey { get; set; } = "";
        public int ServerPort { get; set; } = 51820;
        public string ServerEndpoint { get; set; } = "";
        public string ServerInterfaceName { get; set; } = "wg-kulsos";
        public string ServerDNS { get; set; } = "";
        public string ServerPostUp { get; set; } = "";
        public string ServerPostDown { get; set; } = "";

        // Kliensek
        public int ClientCount { get; set; } = 5;
        public string ClientAllowedIPs { get; set; } = "0.0.0.0/0";
        public string ClientDNS { get; set; } = "8.8.8.8, 8.8.4.4";
        public int PersistentKeepalive { get; set; } = 15;
    }

    public enum GenerationMode
    {
        NewComplete,        // Teljesen új: szerver + kliensek
        ClientsFromServer   // Meglévő szerver kulcsból csak kliensek
    }
}
