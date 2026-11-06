using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace PcDiagnostico
{
    enum Recomendacao { Remover, Opcional, Manter }

    class AppInstalado
    {
        public string Nome, Editor, Versao, Tipo; // Tipo: "Programa" ou "Microsoft Store"
        public long Tamanho;
        public DateTime? InstaladoEm, UltimoUso;
        public bool UsoDesconhecido = true;
        public string PastaInstalacao, ExePrincipal, ComandoDesinstalar, IdPacote;
        public List<string> Classificacao = new List<string>();
        public Recomendacao Recomendacao = Recomendacao.Manter;
        public string Motivo = "";
    }

    partial class Diagnostico
    {
        public readonly List<AppInstalado> Apps = new List<AppInstalado>();

        // Listas de referência (correspondência por trecho do nome, em minúsculas)
        static readonly string[] Pups =
        {
            "driver booster", "driver easy", "driver updater", "drivermax", "driver genius", "driver support", "advanced systemcare", "pc optimizer",
            "reimage", "restoro", "fortect", "pc app store", "webcompanion", "web companion", "onelaunch", "wave browser", "shift browser",
            "segurazo", "bytefence", "search protect", "conduit", "ask toolbar", "babylon", "mywebsearch", "yontoo", "superfish", "hao123",
            "baidu", "pc cleaner", "pc accelerate", "speedup", "registry cleaner", "regclean", "winzip driver updater", "slimcleaner",
            "iobit malware fighter", "smart defrag", "iobit uninstaller", "mobogenie", "outbyte", "auslogics boostspeed", "totalav", "pcprotect",
            "avg tuneup", "avast cleanup", "systweak", "advanced driver updater", "advanced pc cleanup",
            "utorrent", "bittorrent", "opera gx installer", "browser assistant", "mcafee webadvisor", "norton safe web", "avast secure browser", "avg secure browser",
            "ccleaner browser", "dashlane toolbar", "coupon", "shopping", "relevantknowledge", "premieropinion", "spigot", "wajam", "crossrider"
        };

        static readonly string[] Hacktools = { "kmspico", "kmsauto", "kms auto", "kmsnano", "microsoft toolkit", "kms_vl", "aact", "re-loader", "windows loader", "hwidgen", "activator" };

        static readonly string[] BloatWin32 =
        {
            "mcafee", "norton", "wildtangent", "hp jumpstart", "hp support assistant", "dell supportassist remediation", "candy crush", "booking.com",
            "expressvpn", "dropbox promotion", "evernote", "hp wolf", "hp sure", "hp documentation", "acer care", "acer jumpstart", "asus giftbox",
            "cyberlink power2go", "cyberlink powerdvd", "cyberlink youcam", "trend micro", "avast free", "avg antivirus", "avira", "360 total security",
            "lenovo welcome", "mirkat"
        };

        static readonly Dictionary<string, string> BloatStore = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Microsoft.BingNews", "Notícias (Microsoft Start)" }, { "Microsoft.BingWeather", "Clima" }, { "Microsoft.GetHelp", "Obter Ajuda" },
            { "Microsoft.Getstarted", "Dicas" }, { "Microsoft.MicrosoftSolitaireCollection", "Microsoft Solitaire Collection" },
            { "Microsoft.MicrosoftOfficeHub", "Microsoft 365 (Office) — atalho" }, { "Microsoft.People", "Pessoas" }, { "Microsoft.SkypeApp", "Skype" },
            { "Microsoft.WindowsFeedbackHub", "Hub de Feedback" }, { "Microsoft.ZuneVideo", "Filmes e TV" }, { "Microsoft.Todos", "Microsoft To Do" },
            { "Clipchamp.Clipchamp", "Clipchamp" }, { "MicrosoftTeams", "Microsoft Teams (pessoal)" }, { "MSTeams", "Microsoft Teams (pessoal)" },
            { "Microsoft.549981C3F5F10", "Cortana" }, { "Microsoft.WindowsMaps", "Mapas" }, { "Microsoft.MixedReality.Portal", "Portal de Realidade Misturada" },
            { "Microsoft.Microsoft3DViewer", "Visualizador 3D" }, { "Microsoft.BingSearch", "Pesquisa Bing" }, { "Microsoft.PowerAutomateDesktop", "Power Automate" },
            { "Microsoft.MicrosoftJournal", "Journal" }, { "Microsoft.Messaging", "Mensagens" }, { "Microsoft.Office.OneNote", "OneNote (versão Store)" },
            { "Microsoft.OutlookForWindows", "Outlook (novo)" }, { "Microsoft.YourPhone", "Vincular ao Celular" }, { "Microsoft.Copilot", "Copilot" },
            { "Microsoft.Windows.DevHome", "Dev Home" }, { "Microsoft.BingFinance", "Finanças" }, { "Microsoft.BingSports", "Esportes" },
            { "king.com.CandyCrushSaga", "Candy Crush Saga" }, { "king.com.CandyCrushSodaSaga", "Candy Crush Soda Saga" }, { "king.com.BubbleWitch3Saga", "Bubble Witch 3" },
            { "Disney.37853FC22B2CE", "Disney+" }, { "SpotifyAB.SpotifyMusic", "Spotify" }, { "Facebook.Facebook", "Facebook" }, { "Facebook.InstagramBeta", "Instagram" },
            { "BytedancePte.Ltd.TikTok", "TikTok" }, { "AmazonVideo.PrimeVideo", "Prime Video" }, { "7EE7776C.LinkedInforWindows", "LinkedIn" },
            { "4DF9E0F8.Netflix", "Netflix" }, { "Microsoft.GamingApp", "Xbox" }, { "Microsoft.XboxApp", "Xbox Console Companion" },
        };

        static readonly string[] Essenciais =
        {
            "microsoft visual c++", "microsoft windows", ".net", "directx", "microsoft edge", "webview2", "windows sdk", "windows software development", "vcredist", "runtime",
            "nvidia", "amd ", "radeon", "realtek", "intel", "chipset", "driver", "microsoft update health", "windows pc health check",
            "microsoft 365", "office", "onedrive", "teams machine-wide", "windows subsystem", "wsl", "redistributable", "microsoft gameinput",
            "dolby", "waves maxxaudio", "synaptics", "elan", "bluetooth", "thunderbolt", "logitech", "steamvr", "vulkan", "physx"
        };

        static readonly string[] Antivirus =
        {
            "avast", "avg ", "avira", "norton", "mcafee", "kaspersky", "bitdefender", "eset", "panda", "360 total security", "trend micro",
            "sophos", "webroot", "f-secure", "totalav", "malwarebytes", "comodo", "zonealarm", "g data", "k7", "quick heal", "psafe"
        };

        static bool Contem(string texto, IEnumerable<string> lista) { texto = (texto ?? "").ToLowerInvariant(); return lista.Any(x => texto.Contains(x)); }

        // ------------------------------------------------------------------ Uso de programas

        Dictionary<string, DateTime> usoPorExe; // nome do .exe (minúsculo) -> último uso
        Dictionary<string, DateTime> usoPorAumid; // AppUserModelId (Store)

        static string Rot13(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
                else if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
                else sb.Append(c);
            }
            return sb.ToString();
        }

        void Uso(Dictionary<string, DateTime> d, string chave, DateTime t)
        {
            if (string.IsNullOrEmpty(chave) || t.Year < 2000) return;
            chave = chave.ToLowerInvariant();
            DateTime atual;
            if (!d.TryGetValue(chave, out atual) || t > atual) d[chave] = t;
        }

        void ColetarUso()
        {
            usoPorExe = new Dictionary<string, DateTime>();
            usoPorAumid = new Dictionary<string, DateTime>();
            // UserAssist: programas abertos pelo usuário (Menu Iniciar, Explorer, barra de tarefas)
            try
            {
                using (var ua = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"))
                {
                    if (ua != null)
                        foreach (var guid in ua.GetSubKeyNames())
                            using (var k = ua.OpenSubKey(guid + @"\Count"))
                            {
                                if (k == null) continue;
                                foreach (var n in k.GetValueNames())
                                {
                                    var b = k.GetValue(n) as byte[];
                                    if (b == null || b.Length < 68) continue;
                                    long ft = BitConverter.ToInt64(b, 60);
                                    if (ft <= 0) continue;
                                    DateTime t;
                                    try { t = DateTime.FromFileTime(ft); } catch { continue; }
                                    string nome = Rot13(n);
                                    if (nome.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) Uso(usoPorExe, Path.GetFileName(nome), t);
                                    else if (nome.Contains("!")) Uso(usoPorAumid, nome.Substring(0, nome.IndexOf('!')), t);
                                }
                            }
                }
            }
            catch { }
            // Prefetch (somente administrador): registra execuções de qualquer programa
            try
            {
                string pf = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Prefetch");
                foreach (var f in new DirectoryInfo(pf).GetFiles("*.pf"))
                {
                    int i = f.Name.LastIndexOf('-');
                    if (i > 0) Uso(usoPorExe, f.Name.Substring(0, i), f.LastWriteTime);
                }
                prefetchDisponivel = true;
            }
            catch { }
            // Processos em execução agora
            foreach (var p in Process.GetProcesses())
            {
                try { Uso(usoPorExe, p.ProcessName + ".exe", DateTime.Now); } catch { }
                p.Dispose();
            }
        }
        bool prefetchDisponivel;

        static List<string> ExesDaPasta(string pasta)
        {
            var l = new List<string>();
            try
            {
                if (string.IsNullOrEmpty(pasta) || !Directory.Exists(pasta)) return l;
                l.AddRange(Directory.GetFiles(pasta, "*.exe").Select(Path.GetFileName));
                foreach (var d in Directory.GetDirectories(pasta).Take(25))
                    try { l.AddRange(Directory.GetFiles(d, "*.exe").Select(Path.GetFileName)); } catch { }
            }
            catch { }
            return l.Where(x => !Regex.IsMatch(x, "(?i)unins|uninst|setup|update|crash|helper|install")).Take(60).ToList();
        }

        // ------------------------------------------------------------------ Coleta

        void LerUninstall(RegistryHive hive, RegistryView view, Dictionary<string, AppInstalado> mapa)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, view))
                using (var k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (k == null) return;
                    foreach (var sub in k.GetSubKeyNames())
                    {
                        try
                        {
                            using (var a = k.OpenSubKey(sub))
                            {
                                if (a == null) continue;
                                string nome = a.GetValue("DisplayName") as string;
                                if (string.IsNullOrWhiteSpace(nome)) continue;
                                if (Convert.ToInt32(a.GetValue("SystemComponent") ?? 0) == 1) continue;
                                if (a.GetValue("ParentKeyName") != null) continue;
                                string rt = a.GetValue("ReleaseType") as string;
                                if (rt != null && (rt.Contains("Update") || rt.Contains("Hotfix"))) continue;
                                string un = a.GetValue("UninstallString") as string;
                                if (string.IsNullOrWhiteSpace(un)) continue;

                                string chave = nome.Trim().ToLowerInvariant() + "|" + (a.GetValue("DisplayVersion") as string);
                                if (mapa.ContainsKey(chave)) continue;

                                var app = new AppInstalado
                                {
                                    Nome = nome.Trim(),
                                    Editor = (a.GetValue("Publisher") as string ?? "").Trim(),
                                    Versao = a.GetValue("DisplayVersion") as string,
                                    Tipo = "Programa",
                                    PastaInstalacao = (a.GetValue("InstallLocation") as string ?? "").Trim().Trim('"'),
                                };
                                object est = a.GetValue("EstimatedSize");
                                if (est != null) try { app.Tamanho = Convert.ToInt64(est) * 1024; } catch { }
                                string data = a.GetValue("InstallDate") as string;
                                DateTime dt;
                                if (data != null && DateTime.TryParseExact(data.Trim(), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out dt)) app.InstaladoEm = dt;

                                string icone = a.GetValue("DisplayIcon") as string;
                                if (!string.IsNullOrEmpty(icone))
                                {
                                    string exe = icone.Split(',')[0].Trim().Trim('"');
                                    exe = Environment.ExpandEnvironmentVariables(exe);
                                    if (exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(exe))
                                    {
                                        app.ExePrincipal = exe;
                                        if (string.IsNullOrEmpty(app.PastaInstalacao)) app.PastaInstalacao = Path.GetDirectoryName(exe);
                                    }
                                }
                                if (!app.InstaladoEm.HasValue)
                                    try { app.InstaladoEm = a.GetValue("InstallDate") == null && Directory.Exists(app.PastaInstalacao) ? (DateTime?)Directory.GetCreationTime(app.PastaInstalacao) : null; } catch { }

                                // Comando de desinstalação
                                var msi = Regex.Match(un, @"(?i)msiexec(\.exe)?\s+/[IX]\s*(\{[0-9A-F\-]+\})");
                                if (msi.Success) app.ComandoDesinstalar = "msiexec /x " + msi.Groups[2].Value;
                                else app.ComandoDesinstalar = (a.GetValue("QuietUninstallString") as string) ?? un;

                                mapa[chave] = app;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        void LerStore(List<AppInstalado> lista)
        {
            string script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-AppxPackage | Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' -and -not $_.IsResourcePackage } | " +
                            "Select-Object Name,PackageFullName,PackageFamilyName,Publisher,Version,InstallLocation,NonRemovable | ConvertTo-Json -Compress";
            var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script.Replace("\"", "\\\"") + "\"")
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            string json;
            using (var p = Process.Start(psi))
            {
                var tarefa = p.StandardOutput.ReadToEndAsync();
                if (!p.WaitForExit(90000)) { try { p.Kill(); } catch { } return; }
                json = tarefa.Result;
            }
            if (string.IsNullOrWhiteSpace(json)) return;
            var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            object raiz = ser.DeserializeObject(json.Trim());
            var itens = raiz as object[] ?? new[] { raiz };
            var limite = DateTime.Now.AddSeconds(20);
            foreach (var o in itens)
            {
                var d = o as Dictionary<string, object>;
                if (d == null) continue;
                Func<string, string> v = k => d.ContainsKey(k) && d[k] != null ? Convert.ToString(d[k]) : null;
                string nomePacote = v("Name");
                if (nomePacote == null) continue;
                if (v("NonRemovable") == "True") continue;
                string pasta = v("InstallLocation");
                string nome = null;
                if (!BloatStore.TryGetValue(nomePacote, out nome)) nome = NomeManifesto(pasta) ?? nomePacote;
                var app = new AppInstalado
                {
                    Nome = nome, Tipo = "Microsoft Store", Versao = v("Version"), PastaInstalacao = pasta, IdPacote = nomePacote,
                    Editor = EditorCertificado(v("Publisher")),
                    ComandoDesinstalar = "powershell -NoProfile -Command \"Get-AppxPackage -Name '" + nomePacote + "' | Remove-AppxPackage\""
                };
                try
                {
                    if (!string.IsNullOrEmpty(pasta) && Directory.Exists(pasta))
                    {
                        app.InstaladoEm = Directory.GetCreationTime(pasta);
                        if (DateTime.Now < limite) { int n; app.Tamanho = Caminho.TamanhoPasta(pasta, limite, out n); }
                    }
                }
                catch { }
                DateTime u;
                string fam = v("PackageFamilyName");
                if (fam != null && usoPorAumid.TryGetValue(fam.ToLowerInvariant(), out u)) { app.UltimoUso = u; app.UsoDesconhecido = false; }
                lista.Add(app);
            }
        }

        static string NomeManifesto(string pasta)
        {
            try
            {
                string m = Path.Combine(pasta ?? "", "AppxManifest.xml");
                if (!File.Exists(m)) return null;
                var x = System.Xml.Linq.XDocument.Load(m);
                var dn = x.Descendants().FirstOrDefault(e => e.Name.LocalName == "DisplayName");
                if (dn == null || dn.Value.StartsWith("ms-resource", StringComparison.OrdinalIgnoreCase)) return null;
                return dn.Value.Trim();
            }
            catch { return null; }
        }

        static string EditorCertificado(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var m = Regex.Match(s, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
            if (!m.Success) m = Regex.Match(s, @"CN=(""[^""]+""|[^,]+)");
            return m.Success ? m.Groups[1].Value.Trim('"') : s;
        }

        // ------------------------------------------------------------------ Classificação

        void VerificarApps()
        {
            ColetarUso();
            var mapa = new Dictionary<string, AppInstalado>();
            LerUninstall(RegistryHive.LocalMachine, RegistryView.Registry64, mapa);
            LerUninstall(RegistryHive.LocalMachine, RegistryView.Registry32, mapa);
            LerUninstall(RegistryHive.CurrentUser, RegistryView.Registry64, mapa);
            LerUninstall(RegistryHive.CurrentUser, RegistryView.Registry32, mapa);
            Apps.AddRange(mapa.Values);
            try { LerStore(Apps); } catch { }

            // Último uso dos programas
            foreach (var a in Apps.Where(x => x.Tipo == "Programa"))
            {
                var exes = ExesDaPasta(a.PastaInstalacao);
                if (a.ExePrincipal != null) exes.Add(Path.GetFileName(a.ExePrincipal));
                DateTime melhor = DateTime.MinValue;
                foreach (var e in exes)
                {
                    DateTime t;
                    if (usoPorExe.TryGetValue(e.ToLowerInvariant(), out t) && t > melhor) melhor = t;
                }
                if (melhor > DateTime.MinValue) { a.UltimoUso = melhor; a.UsoDesconhecido = false; }
                else if (prefetchDisponivel && exes.Count > 0) a.UsoDesconhecido = false; // sem registro de execução no Prefetch
            }

            var avs = Apps.Where(a => a.Tipo == "Programa" && Contem(a.Nome, Antivirus) && !Contem(a.Nome, new[] { "browser", "vpn", "password", "cleanup", "driver" })).ToList();
            var duplicados = Apps.GroupBy(a => Regex.Replace(a.Nome.ToLowerInvariant(), @"[\d\.\(\)x\-_]+|\b(update|versão|version|edition|bit|64|32)\b", "").Trim())
                .Where(g => g.Count() > 1 && g.Key.Length > 3 && !Contem(g.Key, Essenciais)).ToList();

            foreach (var a in Apps)
            {
                string n = (a.Nome + " " + a.Editor).ToLowerInvariant();
                bool essencial = Contem(n, Essenciais) && !Contem(n, Pups);
                double diasInst = a.InstaladoEm.HasValue ? (DateTime.Now - a.InstaladoEm.Value).TotalDays : 0;

                if (Contem(a.Nome, Hacktools))
                {
                    a.Classificacao.Add("Ativador pirata / hacktool");
                    a.Recomendacao = Recomendacao.Remover;
                    a.Motivo = "Ativadores piratas (KMS e similares) são uma das principais fontes de trojans e são detectados como ameaça pelo Defender.";
                }
                else if (Contem(n, Pups))
                {
                    a.Classificacao.Add("Adware/PUP conhecido");
                    a.Recomendacao = Recomendacao.Remover;
                    a.Motivo = "Programa potencialmente indesejado: costuma exibir propaganda, alterar o navegador, instalar outros programas ou prometer \"otimizações\" que não ajudam.";
                }
                else if (a.Tipo == "Microsoft Store" && BloatStore.ContainsKey(a.IdPacote ?? ""))
                {
                    a.Classificacao.Add("Bloatware (pré-instalado)");
                    a.Recomendacao = Recomendacao.Opcional;
                    a.Motivo = "Veio instalado com o Windows. Remova se não usa; pode ser reinstalado pela Microsoft Store.";
                }
                else if (a.Tipo == "Programa" && Contem(n, BloatWin32) && !essencial)
                {
                    a.Classificacao.Add("Bloatware (pré-instalado/teste)");
                    a.Recomendacao = Recomendacao.Opcional;
                    a.Motivo = "Costuma vir pré-instalado pelo fabricante ou como versão de teste. Remova se não usa.";
                }

                if (avs.Count >= 2 && avs.Contains(a))
                {
                    a.Classificacao.Add("Duplicado: mais de um antivírus");
                    if (a.Recomendacao == Recomendacao.Manter) a.Recomendacao = Recomendacao.Opcional;
                    a.Motivo += (a.Motivo.Length > 0 ? " " : "") + "Há " + avs.Count + " antivírus instalados (" + string.Join(", ", avs.Select(x => x.Nome)) + "). Dois antivírus juntos deixam o PC lento e podem conflitar: mantenha apenas um (o Defender já é suficiente para a maioria).";
                }
                var dup = duplicados.FirstOrDefault(g => g.Contains(a));
                if (dup != null)
                {
                    a.Classificacao.Add("Versões duplicadas");
                    var maisNova = dup.OrderByDescending(x => x.InstaladoEm ?? DateTime.MinValue).First();
                    if (a != maisNova && a.Recomendacao == Recomendacao.Manter)
                    {
                        a.Recomendacao = Recomendacao.Opcional;
                        a.Motivo += (a.Motivo.Length > 0 ? " " : "") + "Existe mais de uma versão instalada; a mais antiga geralmente pode ser removida.";
                    }
                }

                if (string.IsNullOrWhiteSpace(a.Editor))
                {
                    var ass = a.ExePrincipal != null ? Assinatura.Verificar(a.ExePrincipal) : EstadoAssinatura.Desconhecido;
                    if (ass != EstadoAssinatura.Assinado)
                    {
                        a.Classificacao.Add(ass == EstadoAssinatura.Desconhecido ? "Sem editor" : "Sem editor e " + Assinatura.Texto(ass));
                        if (a.Recomendacao == Recomendacao.Manter && !essencial)
                        {
                            a.Recomendacao = Recomendacao.Opcional;
                            a.Motivo += (a.Motivo.Length > 0 ? " " : "") + "Não informa quem publicou o programa. Verifique se você reconhece e instalou de propósito.";
                        }
                    }
                    else a.Editor = Assinatura.Signatario(a.ExePrincipal) ?? "";
                }

                if (!a.UsoDesconhecido && diasInst > 180)
                {
                    double diasUso = a.UltimoUso.HasValue ? (DateTime.Now - a.UltimoUso.Value).TotalDays : diasInst;
                    if (diasUso > 180)
                    {
                        a.Classificacao.Add(a.UltimoUso.HasValue ? "Sem uso há " + (int)(diasUso / 30) + " meses" : "Sem uso registrado");
                        if (a.Recomendacao == Recomendacao.Manter && !essencial)
                        {
                            a.Recomendacao = Recomendacao.Opcional;
                            a.Motivo += (a.Motivo.Length > 0 ? " " : "") + "Não foi aberto há mais de 6 meses. Se não precisa mais, remova para liberar " + (a.Tamanho > 0 ? F.Bytes(a.Tamanho) : "espaço") + ".";
                        }
                    }
                }

                // Bloatware que a pessoa usa de verdade não deve ser sugerido para remoção
                if (a.Recomendacao == Recomendacao.Opcional && a.UltimoUso.HasValue && (DateTime.Now - a.UltimoUso.Value).TotalDays <= 60
                    && a.Classificacao.All(c => c.StartsWith("Bloatware")))
                {
                    a.Recomendacao = Recomendacao.Manter;
                    a.Motivo = "Veio pré-instalado, mas você usou em " + F.Dia(a.UltimoUso.Value) + ". Mantenha se for útil.";
                }

                if (essencial && a.Classificacao.Count == 0) a.Classificacao.Add("Componente, driver ou runtime");
                if (a.Recomendacao == Recomendacao.Manter && a.Motivo.Length == 0)
                    a.Motivo = essencial ? "Necessário para outros programas, drivers ou o próprio Windows. Não remova." : "Nenhum problema encontrado.";
            }

            // Resumo nos cartões
            var remover = Apps.Where(a => a.Recomendacao == Recomendacao.Remover).ToList();
            var opcionais = Apps.Where(a => a.Recomendacao == Recomendacao.Opcional).ToList();
            var perigosos = remover.Where(a => a.Classificacao.Any(c => c.Contains("hacktool"))).ToList();
            if (perigosos.Count > 0)
            {
                var c = Add(Cat.Ameacas, Gravidade.Critico, "Ativador pirata instalado", "Programas de ativação pirata frequentemente trazem trojans e mineradores.",
                    "Desinstale, rode uma verificação completa do Defender e use uma licença legítima do Windows/Office.", "start windowsdefender:");
                c.Suspeito = true;
                foreach (var p in perigosos) c.Detalhes.Add(p.Nome);
            }
            if (remover.Count > 0)
            {
                var c = Add(Cat.Apps, Gravidade.Aviso, remover.Count + " aplicativo(s) recomendados para remover",
                    "Adware, programas potencialmente indesejados (PUP) ou ativadores. Veja a tabela de aplicativos abaixo com o motivo e o comando de cada um.",
                    "Desinstale pelo Configurações > Aplicativos > Aplicativos instalados (ou com o comando mostrado na tabela). O PCDiagnostico nunca remove nada sozinho.",
                    "start ms-settings:appsfeatures");
                foreach (var p in remover) c.Detalhes.Add(p.Nome + " — " + string.Join(", ", p.Classificacao));
            }
            if (opcionais.Count > 0)
            {
                long tam = opcionais.Sum(x => x.Tamanho);
                var c = Add(Cat.Apps, Gravidade.Info, opcionais.Count + " aplicativo(s) que você pode remover se não usa" + (tam > 0 ? " (" + F.Bytes(tam) + ")" : ""),
                    "Bloatware, programas sem uso há meses, duplicados ou sem editor identificado. A decisão é sua: veja a tabela abaixo.",
                    "Remova os que não usa em Configurações > Aplicativos > Aplicativos instalados.", "start ms-settings:appsfeatures");
                foreach (var p in opcionais.OrderBy(x => x.Nome)) c.Detalhes.Add(p.Nome + " — " + string.Join(", ", p.Classificacao));
            }
            if (remover.Count + opcionais.Count == 0)
                Add(Cat.Apps, Gravidade.Ok, "Nenhum aplicativo indesejado encontrado", Apps.Count + " aplicativos analisados.", null);
            if (!prefetchDisponivel)
                Add(Cat.Apps, Gravidade.Info, "Uso de programas parcialmente conhecido",
                    "Sem administrador, o programa só sabe quando você abriu um app pelo Menu Iniciar ou Explorer. Execute como administrador para usar também o histórico de execução do Windows (Prefetch).", null);
        }
    }
}
