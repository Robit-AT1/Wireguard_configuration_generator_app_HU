# Wireguard_configuration_generator_app_HU
Az alkalmazás képes teljesen új wireguard privát és publikus kulcsokat generálni mind szerver és kliens oldalon majd ezeket a kulcspárokat kicserélni, és fájlokba szervezni, ezen kívül mikrotik -hez parancsokat generál, ezzel könnyítve a wireguard szerver könnyebb létrehozását.

---------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Letöltés:
https://github.com/Robit-AT1/Wireguard_configuration_generator_app_HU/releases/tag/v1.0
Ha nem bíznál az exe fájlokban akkor magad is futtathatod a nyilt forráskód alapján!

Publish:

A programot használat előtt javasolt .exe fájlá alakítani ehez szükséges, a gépre telepített dotnet platform majd az adott mappában egy command promptot nyitva az alábbi parancsal lehet publish-olni:

dotnet publish -c Release -r win-x64 --self-contained true ^
-p:PublishSingleFile=true ^
-p:IncludeNativeLibrariesForSelfExtract=true ^
-p:EnableCompressionInSingleFile=true

Ennek a parancsnak a sikeres lefutása esetén ezt kell látnunk:

C:\Users\YOURUSERNAME\Desktop\WireGuardGen>dotnet publish -c Release -r win-x64 --self-contained true ^
More? -p:PublishSingleFile=true ^
More? -p:IncludeNativeLibrariesForSelfExtract=true ^
More? -p:EnableCompressionInSingleFile=true
Restore complete (1,7s)
  WireGuardGen succeeded (9,2s) → bin\Release\net8.0-windows\win-x64\publish\

Build succeeded in 11,4s

C:\Users\Tibike\YOURUSERNAME\WireGuardGen>

Ezután a program az alábbi útvonalon lesz elérhető: bin\Release\net8.0-windows\win-x64\publish\
Az ebben található .exe fájl egy teljes értékű, hordozható verziót tartalmaz.

---------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Figyelmeztetés:

A program használatakor vegye figyelembe a kitöltendő adatoknál megjelenő szövegeket, hiszen egy adott információt ha nem úgy ad meg ahogy a program kéri akkor az egész wireguard esetenként nem működhet.
Például:
Ahol az endpoint megadása van nem elég a DNS nevet VAGY IP címet megadni, hanem : után ki kell írni a portot is!

---------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Használat:

A Program két fő részre bomlik:
 1. Teljesen új konfigurációt épít ki. Ez akkor hasznos ha egy wireguard szervert a 0-ról szeretnénk felhúzni
 2. Egy már meglévő szerver konfigurációhoz ad hozzá kliens konfigurációkat

Mind a két résznél értelmezés és példák szerint ki kell tölteni az adott mezőket információkkal. A csillaggal megjelölt mezők kötelezőek, amelyek nem csillaggal jelöltek azok opcionálisak.

---------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Funkciók:

A program a kiválasztott mappában létre fog hozni két új mappa állományt.
Az egyik mappaállomány neve kliensek lesz, amelyben létre fog jönni az összes kliens konfiguráció fájlja és az esetleges kliensek felvételét segítő QR kódok.
A másik mappaállomány neve szerver lesz, amelyben értelem szerűen a szerverhez tartozó adatok lesznek.
Fontosnak tartom megjegyezni hogy ez a program MikroTik specifikus állományt is tartalmaz, amely segíti a kliensek felvételét mikrotik eszközökre, ámbár más eszközön Linuxon is ugyanúgy használható!

A szerver mappában a .conf fájlban lévő dolgokat leginkább linuxnál lehet használni, míg a mikrotik_parancsok.txt fájlt a mikrotik eszközre történő kliensek felvételére.

---------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
