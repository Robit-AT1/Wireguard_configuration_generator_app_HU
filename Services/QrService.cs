using System.IO;
using QRCoder;

namespace WireGuardGen.Services
{
    public static class QrService
    {
        /// <summary>
        /// WireGuard kliens .conf szövegéből QR-kód PNG fájl.
        /// A WireGuard mobil app közvetlenül be tudja szkennelni.
        /// </summary>
        public static bool SaveQrPng(string configText, string pngPath, int pixelsPerModule = 10)
        {
            try
            {
                using var generator = new QRCodeGenerator();
                var data    = generator.CreateQrCode(configText, QRCodeGenerator.ECCLevel.M);
                using var qr = new PngByteQRCode(data);
                var bytes   = qr.GetGraphic(pixelsPerModule);
                File.WriteAllBytes(pngPath, bytes);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
