using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;

namespace PcDiagnostico
{
    /// <summary>Chamadas nativas do Windows usadas pelo programa.</summary>
    static class Nativo
    {
        // ---------------- Lixeira
        [StructLayout(LayoutKind.Sequential)]
        public struct SHQUERYRBINFO { public int cbSize; public long i64Size; public long i64NumItems; }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHQueryRecycleBin(string pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHEmptyRecycleBin(IntPtr hwnd, string pszRootPath, uint dwFlags);

        public static bool ConsultarLixeira(out long bytes, out long itens)
        {
            var info = new SHQUERYRBINFO();
            info.cbSize = Marshal.SizeOf(typeof(SHQUERYRBINFO));
            int r = SHQueryRecycleBin(null, ref info);
            bytes = info.i64Size; itens = info.i64NumItems;
            return r == 0;
        }

        /// <summary>Esvazia a Lixeira (usado somente no modo de melhorias, após confirmação).</summary>
        public static bool EsvaziarLixeira()
        {
            // SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
            int r = SHEmptyRecycleBin(IntPtr.Zero, null, 0x1 | 0x2 | 0x4);
            return r == 0 || r == unchecked((int)0x8000FFFF); // E_UNEXPECTED = lixeira já vazia
        }

        // ---------------- Caminho de processos
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);

        public static string CaminhoProcesso(int pid)
        {
            IntPtr h = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024);
                int n = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }

        // ---------------- Efeitos visuais
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint action, uint uiParam, ref int pvParam, uint winIni);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint action, uint uiParam, IntPtr pvParam, uint winIni);

        [StructLayout(LayoutKind.Sequential)]
        public struct ANIMATIONINFO { public uint cbSize; public int iMinAnimate; }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(uint action, uint uiParam, ref ANIMATIONINFO pvParam, uint winIni);
    }

    enum EstadoAssinatura { Assinado, SemAssinatura, Invalida, Desconhecido }

    /// <summary>Verificação de assinatura digital (Authenticode) via WinVerifyTrust, sem consulta online.</summary>
    static class Assinatura
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        class WINTRUST_FILE_INFO
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            public string pcwszFilePath;
            public IntPtr hFile = IntPtr.Zero;
            public IntPtr pgKnownSubject = IntPtr.Zero;
        }

        [StructLayout(LayoutKind.Sequential)]
        class WINTRUST_DATA
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            public IntPtr pPolicyCallbackData = IntPtr.Zero;
            public IntPtr pSIPClientData = IntPtr.Zero;
            public uint dwUIChoice = 2;           // WTD_UI_NONE
            public uint fdwRevocationChecks = 0;  // WTD_REVOKE_NONE
            public uint dwUnionChoice = 1;        // WTD_CHOICE_FILE
            public IntPtr pFile;
            public uint dwStateAction = 0;
            public IntPtr hWVTStateData = IntPtr.Zero;
            public IntPtr pwszURLReference = IntPtr.Zero;
            public uint dwProvFlags = 0x10 | 0x1000; // WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            public uint dwUIContext = 0;
            public IntPtr pSignatureSettings = IntPtr.Zero;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, IntPtr data);

        static readonly Guid AcaoGenerica = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        static readonly Dictionary<string, EstadoAssinatura> cache = new Dictionary<string, EstadoAssinatura>(StringComparer.OrdinalIgnoreCase);
        static readonly string Windir = (Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows").TrimEnd('\\') + "\\";

        /// <summary>Arquivos do Windows e de apps da Store são assinados por catálogo/pacote; consideramos confiáveis.</summary>
        public static bool ConfiavelPorLocal(string caminho)
        {
            return caminho.StartsWith(Windir, StringComparison.OrdinalIgnoreCase)
                || caminho.IndexOf(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static EstadoAssinatura Verificar(string caminho)
        {
            if (string.IsNullOrEmpty(caminho) || !File.Exists(caminho)) return EstadoAssinatura.Desconhecido;
            EstadoAssinatura e;
            if (cache.TryGetValue(caminho, out e)) return e;
            if (ConfiavelPorLocal(caminho)) { cache[caminho] = EstadoAssinatura.Assinado; return EstadoAssinatura.Assinado; }

            var fi = new WINTRUST_FILE_INFO { pcwszFilePath = caminho };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            IntPtr pData = IntPtr.Zero;
            try
            {
                Marshal.StructureToPtr(fi, pFile, false);
                var data = new WINTRUST_DATA { pFile = pFile };
                pData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
                Marshal.StructureToPtr(data, pData, false);
                int r = WinVerifyTrust(IntPtr.Zero, AcaoGenerica, pData);
                if (r == 0) e = EstadoAssinatura.Assinado;
                else if (r == unchecked((int)0x800B0100)) e = EstadoAssinatura.SemAssinatura; // TRUST_E_NOSIGNATURE
                else e = EstadoAssinatura.Invalida;
            }
            catch { e = EstadoAssinatura.Desconhecido; }
            finally
            {
                try { Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO)); } catch { }
                Marshal.FreeHGlobal(pFile);
                if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            }
            cache[caminho] = e;
            return e;
        }

        public static string Signatario(string caminho)
        {
            try
            {
                var c = X509Certificate.CreateFromSignedFile(caminho);
                string s = c.Subject;
                int i = s.IndexOf("CN=", StringComparison.Ordinal);
                if (i < 0) return s;
                s = s.Substring(i + 3);
                if (s.StartsWith("\"")) { int f = s.IndexOf('"', 1); return f > 0 ? s.Substring(1, f - 1) : s; }
                int v = s.IndexOf(',');
                return v > 0 ? s.Substring(0, v) : s;
            }
            catch { return null; }
        }

        public static string Texto(EstadoAssinatura e)
        {
            switch (e)
            {
                case EstadoAssinatura.Assinado: return "assinado";
                case EstadoAssinatura.SemAssinatura: return "sem assinatura digital";
                case EstadoAssinatura.Invalida: return "assinatura inválida ou não confiável";
                default: return "assinatura não verificada";
            }
        }
    }

    /// <summary>Utilidades de caminho de arquivo.</summary>
    static class Caminho
    {
        /// <summary>Extrai o executável de uma linha de comando (com ou sem aspas, com variáveis de ambiente).</summary>
        public static string ExtrairExe(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return null;
            cmd = Environment.ExpandEnvironmentVariables(cmd.Trim());
            string exe;
            if (cmd.StartsWith("\""))
            {
                int f = cmd.IndexOf('"', 1);
                exe = f > 0 ? cmd.Substring(1, f - 1) : cmd.Trim('"');
            }
            else
            {
                int i = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                exe = i > 0 ? cmd.Substring(0, i + 4) : cmd.Split(' ')[0];
            }
            exe = exe.Trim();
            if (!Path.IsPathRooted(exe))
            {
                string s = Path.Combine(Environment.SystemDirectory, exe);
                if (File.Exists(s)) return s;
                if (File.Exists(s + ".exe")) return s + ".exe";
            }
            return exe;
        }

        public static readonly string Temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd('\\') + "\\";
        public static readonly string AppDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).TrimEnd('\\') + "\\";
        public static readonly string AppDataLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData).TrimEnd('\\') + "\\";
        public static readonly string PastaUsuarios = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)).TrimEnd('\\') + "\\";

        public static bool EmTemp(string p)
        {
            if (p == null) return false;
            return p.StartsWith(Temp, StringComparison.OrdinalIgnoreCase)
                || p.IndexOf(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) >= 0
                || p.IndexOf(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool EmAppData(string p)
        {
            return p != null && p.IndexOf(@"\AppData\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool EmPastaDeUsuario(string p)
        {
            return p != null && (p.StartsWith(PastaUsuarios, StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"C:\ProgramData\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"C:\Users\Public\", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Lista arquivos recursivamente, ignorando pastas sem acesso e links.</summary>
        public static IEnumerable<FileInfo> Arquivos(string pasta)
        {
            var pilha = new Stack<DirectoryInfo>();
            try { pilha.Push(new DirectoryInfo(pasta)); } catch { yield break; }
            while (pilha.Count > 0)
            {
                var d = pilha.Pop();
                FileSystemInfo[] itens;
                try { itens = d.GetFileSystemInfos(); } catch { continue; }
                foreach (var f in itens)
                {
                    if ((f.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((f.Attributes & FileAttributes.Directory) != 0) pilha.Push((DirectoryInfo)f);
                    else yield return (FileInfo)f;
                }
            }
        }

        /// <summary>Soma o tamanho dos arquivos de uma pasta, com limite de tempo.</summary>
        public static long TamanhoPasta(string pasta, DateTime limite, out int arquivos)
        {
            long total = 0; arquivos = 0;
            var pilha = new Stack<string>();
            pilha.Push(pasta);
            while (pilha.Count > 0 && DateTime.Now < limite)
            {
                string d = pilha.Pop();
                try
                {
                    foreach (var f in new DirectoryInfo(d).EnumerateFileSystemInfos())
                    {
                        if ((f.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if ((f.Attributes & FileAttributes.Directory) != 0) pilha.Push(f.FullName);
                        else { total += ((FileInfo)f).Length; arquivos++; }
                    }
                }
                catch { }
            }
            return total;
        }
    }

    /// <summary>Item que inicia com o Windows (chaves Run e pastas Inicializar), no mesmo formato do Gerenciador de Tarefas.</summary>
    class ItemInicializacao
    {
        public string Nome;          // nome do valor no registro ou do atalho (.lnk)
        public string Comando;
        public string Exe;
        public string Origem;        // texto amigável
        public RegistryHive HiveAprovacao;
        public string SubchaveAprovacao; // Run, Run32 ou StartupFolder
        public bool Ativo;
        public bool Pesado;

        public string ChaveAprovacao { get { return @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\" + SubchaveAprovacao; } }

        public static readonly string[] AppsPesados =
        {
            "teams", "discord", "steam", "epicgames", "epic games", "spotify", "adobe", "creative cloud", "battle.net",
            "ubisoft", "eadesktop", "ea app", "origin", "opera", "skype", "zoom", "dropbox", "googledrive", "google drive",
            "razer", "icue", "armoury", "wallpaper", "riot", "whatsapp", "telegram", "utorrent", "bittorrent", "qbittorrent",
            "overwolf", "gog galaxy", "ccleaner", "lghub", "msi center", "dragon center", "nahimic", "corsair",
            "steelseries", "medal", "outplayed", "parsec", "anydesk", "teamviewer", "onedrive", "icloud", "hp smart", "mcafee", "norton", "avast", "avg"
        };

        public static List<ItemInicializacao> Listar()
        {
            var lista = new List<ItemInicializacao>();
            const string run = @"Software\Microsoft\Windows\CurrentVersion\Run";
            LerRun(lista, RegistryHive.CurrentUser, RegistryView.Registry64, run, "Registro do usuário (HKCU\\Run)", RegistryHive.CurrentUser, "Run");
            LerRun(lista, RegistryHive.LocalMachine, RegistryView.Registry64, run, "Registro do sistema (HKLM\\Run)", RegistryHive.LocalMachine, "Run");
            LerRun(lista, RegistryHive.LocalMachine, RegistryView.Registry32, run, "Registro do sistema 32 bits (HKLM\\Run)", RegistryHive.LocalMachine, "Run32");
            LerPasta(lista, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Pasta Inicializar do usuário", RegistryHive.CurrentUser);
            LerPasta(lista, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Pasta Inicializar de todos os usuários", RegistryHive.LocalMachine);

            foreach (var it in lista)
            {
                byte[] v = Reg.Valor(it.HiveAprovacao, it.ChaveAprovacao, it.Nome) as byte[];
                it.Ativo = !(v != null && v.Length > 0 && (v[0] & 1) == 1);
                string tudo = (it.Nome + " " + it.Comando).ToLowerInvariant();
                it.Pesado = AppsPesados.Any(x => tudo.Contains(x));
            }
            return lista;
        }

        static void LerRun(List<ItemInicializacao> lista, RegistryHive hive, RegistryView view, string caminho, string origem, RegistryHive hiveAprov, string sub)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, view))
                using (var k = b.OpenSubKey(caminho))
                {
                    if (k == null) return;
                    foreach (var n in k.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(n)) continue;
                        string cmd = Convert.ToString(k.GetValue(n));
                        if (lista.Any(x => x.Nome == n && x.Comando == cmd)) continue;
                        lista.Add(new ItemInicializacao { Nome = n, Comando = cmd, Exe = Caminho.ExtrairExe(cmd), Origem = origem, HiveAprovacao = hiveAprov, SubchaveAprovacao = sub });
                    }
                }
            }
            catch { }
        }

        static void LerPasta(List<ItemInicializacao> lista, string pasta, string origem, RegistryHive hiveAprov)
        {
            try
            {
                if (string.IsNullOrEmpty(pasta) || !Directory.Exists(pasta)) return;
                foreach (var f in Directory.GetFiles(pasta))
                {
                    string nome = Path.GetFileName(f);
                    if (nome.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    string alvo = f;
                    if (f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) alvo = AlvoAtalho(f) ?? f;
                    lista.Add(new ItemInicializacao { Nome = nome, Comando = alvo, Exe = alvo, Origem = origem, HiveAprovacao = hiveAprov, SubchaveAprovacao = "StartupFolder" });
                }
            }
            catch { }
        }

        public static string AlvoAtalho(string lnk)
        {
            try
            {
                dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
                dynamic at = sh.CreateShortcut(lnk);
                string t = at.TargetPath;
                return string.IsNullOrEmpty(t) ? null : t;
            }
            catch { return null; }
        }
    }
}
