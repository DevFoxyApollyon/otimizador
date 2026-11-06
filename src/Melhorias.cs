using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PcDiagnostico
{
    /// <summary>Registro das alterações feitas no modo de melhorias.</summary>
    class LogMelhorias
    {
        public readonly string Arquivo;
        public readonly bool Simulacao;

        public LogMelhorias(bool simulacao)
        {
            Simulacao = simulacao;
            string pasta = Console2.PastaRelatorios();
            Directory.CreateDirectory(pasta);
            Arquivo = Path.Combine(pasta, "melhorias-log.txt");
        }

        public void Linha(string texto)
        {
            string l = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + (Simulacao ? " [SIMULAÇÃO] " : " ") + texto;
            try { File.AppendAllText(Arquivo, l + Environment.NewLine, new UTF8Encoding(true)); } catch { }
            Console.WriteLine("    " + texto);
        }
    }

    class Melhoria
    {
        public string Titulo, Descricao, Estado, Risco;
        public bool Disponivel = true;
        public Func<bool> Preparar;            // escolhas extras (opcional); false = cancelar
        public Func<LogMelhorias, bool> Aplicar;
    }

    /// <summary>Utilidades de console compartilhadas.</summary>
    static class Console2
    {
        public static string PastaRelatorios()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Diagnóstico do PC");
        }

        public static bool EhAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; }
        }

        public static void Cor(ConsoleColor c, string texto)
        {
            Console.ForegroundColor = c;
            Console.WriteLine(texto);
            Console.ResetColor();
        }

        public static string Ler(string pergunta)
        {
            Console.Write(pergunta);
            string r = Console.ReadLine();
            return r == null ? null : r.Trim();
        }

        /// <summary>Pergunta sim/não. Padrão é NÃO.</summary>
        public static bool Confirmar(string pergunta)
        {
            string r = Ler("  " + pergunta + " (s/N): ");
            return r != null && (r.Equals("s", StringComparison.OrdinalIgnoreCase) || r.Equals("sim", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Reabre este programa como administrador (UAC) e espera terminar.</summary>
        public static bool ReabrirComoAdmin(string argumentos)
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, argumentos) { Verb = "runas", UseShellExecute = true });
                if (p != null) { p.WaitForExit(); p.Dispose(); }
                return true;
            }
            catch (Win32Exception) { Cor(ConsoleColor.Yellow, "  Elevação cancelada. Nada foi alterado."); return false; }
        }

        /// <summary>Executa um comando mostrando a saída no próprio console. Retorna o código de saída.</summary>
        public static int Rodar(string exe, string args)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("    > " + exe + " " + args);
            Console.ResetColor();
            try
            {
                using (var p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false }))
                {
                    p.WaitForExit();
                    return p.ExitCode;
                }
            }
            catch (Exception ex) { Console.WriteLine("    Erro: " + ex.Message); return -1; }
        }

        /// <summary>Executa sem mostrar saída; retorna o código de saída.</summary>
        public static int RodarSilencioso(string exe, string args)
        {
            try
            {
                using (var p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }))
                {
                    p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
                    p.WaitForExit(60000);
                    return p.ExitCode;
                }
            }
            catch { return -1; }
        }
        public static string Capturar(string exe, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage) };
                using (var p = Process.Start(psi))
                {
                    string s = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(30000);
                    return s;
                }
            }
            catch { return ""; }
        }
    }

    /// <summary>
    /// Modo de melhorias: o usuário escolhe item por item e confirma; antes de qualquer
    /// alteração é criado um ponto de restauração e tudo é registrado em log.
    /// </summary>
    static class Melhorias
    {
        const string GuidEquilibrado = "381b4222-f694-41f0-9685-ff5bb260df2e";

        internal static string WinDir { get { return Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows"; } }

        internal static long TamanhoAntigo(string pasta, out int n)
        {
            n = 0; long t = 0;
            try
            {
                if (!Directory.Exists(pasta)) return 0;
                var lim = DateTime.Now.AddDays(-1);
                foreach (var f in Caminho.Arquivos(pasta))
                    try { if (f.LastWriteTime < lim) { t += f.Length; n++; } } catch { }
            }
            catch { }
            return t;
        }

        public static bool Smb1Ativo()
        {
            int? smbSrv = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
            int? mrx = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start");
            return (smbSrv.HasValue && smbSrv.Value == 1) || (mrx.HasValue && mrx.Value != 4);
        }

        internal static bool TrimDesligado()
        {
            // DisableDeleteNotification = 1 significa TRIM desligado para NTFS
            int? v = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\FileSystem", "DisableDeleteNotification");
            return v.HasValue && v.Value == 1;
        }

        internal static bool TemSsd()
        {
            try { return W.QS(@"root\Microsoft\Windows\Storage", "SELECT MediaType FROM MSFT_PhysicalDisk").Any(o => W.L(o, "MediaType") == 4); } catch { return false; }
        }

        static int Spi(uint get)
        {
            int v = 0;
            Nativo.SystemParametersInfo(get, 0, ref v, 0);
            return v;
        }

        // Pares GET/SET de efeitos visuais que pesam e não afetam a legibilidade (a suavização de fontes fica ligada)
        static readonly uint[][] Efeitos =
        {
            new uint[] { 0x1042, 0x1043 }, // animações de controles e elementos
            new uint[] { 0x1002, 0x1003 }, // animação de menus
            new uint[] { 0x1004, 0x1005 }, // animação de caixas de combinação
            new uint[] { 0x1006, 0x1007 }, // rolagem suave de listas
            new uint[] { 0x1016, 0x1017 }, // animação de dicas
            new uint[] { 0x1012, 0x1013 }, // menus com fade
            new uint[] { 0x1014, 0x1015 }, // seleção com fade
            new uint[] { 0x1024, 0x1025 }, // sombra sob janelas
            new uint[] { 0x101A, 0x101B }, // sombra do ponteiro
        };

        public static List<Melhoria> Detectar()
        {
            var l = new List<Melhoria>();
            int n1, n2;

            long tUser = TamanhoAntigo(Path.GetTempPath(), out n1);
            long tWin = TamanhoAntigo(Path.Combine(WinDir, "Temp"), out n2);
            l.Add(new Melhoria
            {
                Titulo = "Limpar arquivos temporários",
                Descricao = "Apaga arquivos com mais de 24 horas das pastas temporárias do usuário e do Windows. Arquivos em uso são ignorados.",
                Estado = "Cerca de " + F.Bytes(tUser + tWin) + " em " + (n1 + n2) + " arquivos (o tamanho da pasta do Windows só é conhecido como administrador).",
                Risco = "Baixo. Programas recriam o que precisarem.",
                Disponivel = tUser + tWin > 10L << 20 || !Console2.EhAdmin(),
                Aplicar = log => LimparPasta(Path.GetTempPath(), log) & LimparPasta(Path.Combine(WinDir, "Temp"), log)
            });

            int nd; long tWu = TamanhoAntigo(Path.Combine(WinDir, @"SoftwareDistribution\Download"), out nd);
            l.Add(new Melhoria
            {
                Titulo = "Limpar cache do Windows Update",
                Descricao = "Para os serviços Windows Update e BITS, apaga os instaladores já baixados em SoftwareDistribution\\Download e reinicia os serviços. Também resolve atualizações travadas.",
                Estado = tWu > 0 ? "Cerca de " + F.Bytes(tWu) + " em cache." : "Tamanho só é conhecido como administrador.",
                Risco = "Baixo. Atualizações pendentes serão baixadas de novo.",
                Disponivel = tWu > 50L << 20 || (tWu == 0 && !Console2.EhAdmin()),
                Aplicar = LimparCacheWu
            });

            long lb, li;
            if (Nativo.ConsultarLixeira(out lb, out li) && li > 0)
                l.Add(new Melhoria
                {
                    Titulo = "Esvaziar a Lixeira",
                    Descricao = "Apaga definitivamente os itens da Lixeira.",
                    Estado = li + " itens, " + F.Bytes(lb) + ".",
                    Risco = "Os arquivos da Lixeira NÃO poderão ser recuperados (nem pelo ponto de restauração). Confira antes.",
                    Aplicar = log => { bool ok = Nativo.EsvaziarLixeira(); log.Linha(ok ? "Lixeira esvaziada (" + li + " itens, " + F.Bytes(lb) + ")." : "Falha ao esvaziar a Lixeira."); return ok; }
                });

            var ativos = ItemInicializacao.Listar().Where(x => x.Ativo).OrderByDescending(x => x.Pesado).ThenBy(x => x.Nome).ToList();
            var escolhidos = new List<ItemInicializacao>();
            if (ativos.Count > 0)
                l.Add(new Melhoria
                {
                    Titulo = "Desativar programas na inicialização",
                    Descricao = "Impede que programas escolhidos por você abram junto com o Windows (igual ao Gerenciador de Tarefas). Não desinstala nada; dá para reativar depois em Configurações > Aplicativos > Inicialização.",
                    Estado = ativos.Count + " ativos, " + ativos.Count(x => x.Pesado) + " pesados.",
                    Risco = "Baixo. O programa só deixa de abrir sozinho.",
                    Preparar = () =>
                    {
                        escolhidos.Clear();
                        foreach (var it in ativos)
                            if (Console2.Confirmar("Desativar \"" + it.Nome + "\"" + (it.Pesado ? " [pesado]" : "") + "?")) escolhidos.Add(it);
                        return escolhidos.Count > 0;
                    },
                    Aplicar = log => DesativarInicializacao(escolhidos, log)
                });

            var planos = ListarPlanos();
            string planoEscolhido = null;
            var ativo = planos.FirstOrDefault(p => p.Item3);
            l.Add(new Melhoria
            {
                Titulo = "Trocar o plano de energia",
                Descricao = "Muda o plano de energia ativo. \"Alto desempenho\" deixa o processador sempre pronto (melhor para jogos em PC de mesa); \"Equilibrado\" é o recomendado para a maioria.",
                Estado = "Atual: " + (ativo != null ? ativo.Item2 : "desconhecido") + ".",
                Risco = "Baixo. Em notebooks, \"Alto desempenho\" reduz a duração da bateria.",
                Disponivel = planos.Count > 0,
                Preparar = () =>
                {
                    for (int i = 0; i < planos.Count; i++) Console.WriteLine("     [" + (i + 1) + "] " + planos[i].Item2 + (planos[i].Item3 ? "  (atual)" : ""));
                    if (!planos.Any(p => p.Item1.StartsWith("8c5e7fda", StringComparison.OrdinalIgnoreCase)))
                        Console.WriteLine("     (\"Alto desempenho\" não aparece porque está oculto ou não existe neste PC.)");
                    int k;
                    string r = Console2.Ler("     Escolha o número do plano: ");
                    if (!int.TryParse(r, out k) || k < 1 || k > planos.Count || planos[k - 1].Item3) return false;
                    planoEscolhido = planos[k - 1].Item1;
                    return true;
                },
                Aplicar = log =>
                {
                    log.Linha("Plano anterior: " + (ativo != null ? ativo.Item2 + " (" + ativo.Item1 + ")" : "?") + ". Para voltar: powercfg /setactive " + (ativo != null ? ativo.Item1 : GuidEquilibrado));
                    int c = Console2.Rodar("powercfg", "/setactive " + planoEscolhido);
                    log.Linha(c == 0 ? "Plano de energia alterado para " + planoEscolhido + "." : "powercfg retornou erro " + c + ".");
                    return c == 0;
                }
            });

            l.Add(new Melhoria
            {
                Titulo = "Reparar arquivos do Windows (DISM /RestoreHealth e sfc /scannow)",
                Descricao = "Verifica e repara a imagem do Windows (precisa de internet) e depois os arquivos de sistema. Pode levar de 10 a 40 minutos.",
                Estado = "Recomendado se houve telas azuis, travamentos ou erros estranhos.",
                Risco = "Baixo. Não apaga arquivos pessoais.",
                Aplicar = log =>
                {
                    int d = Console2.Rodar("DISM.exe", "/Online /Cleanup-Image /RestoreHealth");
                    log.Linha("DISM /RestoreHealth terminou com código " + d + (d == 0 ? " (sucesso)." : "."));
                    int s = Console2.Rodar(Path.Combine(Environment.SystemDirectory, "sfc.exe"), "/scannow");
                    log.Linha("sfc /scannow terminou com código " + s + ". Detalhes em " + WinDir + "\\Logs\\CBS\\CBS.log.");
                    return d == 0 && s == 0;
                }
            });

            bool trimOff = TrimDesligado();
            l.Add(new Melhoria
            {
                Titulo = "Ativar o TRIM (SSD)",
                Descricao = "O TRIM avisa o SSD sobre blocos apagados, mantendo o desempenho e a vida útil.",
                Estado = trimOff ? "TRIM DESLIGADO." : "TRIM já está ligado.",
                Risco = "Nenhum.",
                Disponivel = trimOff && TemSsd(),
                Aplicar = log =>
                {
                    int c = Console2.Rodar("fsutil", "behavior set DisableDeleteNotify 0");
                    log.Linha(c == 0 ? "TRIM ativado (DisableDeleteNotify 0). Para voltar: fsutil behavior set DisableDeleteNotify 1" : "fsutil retornou erro " + c + ".");
                    return c == 0;
                }
            });

            l.Add(new Melhoria
            {
                Titulo = "Otimizar unidades (desfragmentar HD / TRIM em SSD)",
                Descricao = "Roda a otimização do Windows em todas as unidades: desfragmenta HDs e envia TRIM aos SSDs. Em HDs grandes pode demorar.",
                Estado = "O Windows costuma fazer isso semanalmente; útil se a otimização agendada estiver desligada.",
                Risco = "Baixo. Evite desligar o PC durante o processo.",
                Aplicar = log =>
                {
                    int c = Console2.Rodar("defrag.exe", "/C /O /U");
                    log.Linha("defrag /C /O terminou com código " + c + ".");
                    return c == 0;
                }
            });

            bool efeitosLigados = Efeitos.Any(e => Spi(e[0]) != 0);
            int? transp = Reg.Int(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency");
            l.Add(new Melhoria
            {
                Titulo = "Ajustar efeitos visuais para desempenho",
                Descricao = "Desliga animações, sombras, fades e transparência. A suavização de fontes continua ligada. Ajuda em PCs mais fracos.",
                Estado = efeitosLigados || (transp ?? 1) == 1 ? "Efeitos visuais ligados." : "Já ajustado.",
                Risco = "Nenhum. Para voltar: Configurações > Acessibilidade > Efeitos visuais, ou SystemPropertiesPerformance.exe.",
                Disponivel = efeitosLigados || (transp ?? 1) == 1,
                Aplicar = AjustarEfeitos
            });

            l.Add(new Melhoria
            {
                Titulo = "Desativar o SMBv1 (protocolo inseguro)",
                Descricao = "Remove o suporte ao SMB 1.0, explorado por ransomwares como o WannaCry.",
                Estado = "SMBv1 ativo.",
                Risco = "Aparelhos de rede muito antigos (NAS/impressoras de antes de 2014) podem deixar de ser acessados. Requer reiniciar.",
                Disponivel = Smb1Ativo(),
                Aplicar = log =>
                {
                    int c = Console2.Rodar("DISM.exe", "/Online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart");
                    log.Linha("Desativar SMB1Protocol: código " + c + (c == 3010 ? " (reinicie o PC para concluir)." : ".") + " Para voltar: DISM /Online /Enable-Feature /FeatureName:SMB1Protocol");
                    return c == 0 || c == 3010;
                }
            });
            return l;
        }

        // ------------------------------------------------------------------ Implementações

        internal static bool LimparPasta(string pasta, LogMelhorias log)
        {
            if (!Directory.Exists(pasta)) return true;
            if (pasta.StartsWith(WinDir, StringComparison.OrdinalIgnoreCase) && !Console2.EhAdmin()) { log.Linha(pasta + ": ignorada (exige administrador)."); return true; }
            var lim = DateTime.Now.AddDays(-1);
            long liberado = 0; int apagados = 0, ignorados = 0;
            try
            {
                foreach (var f in Caminho.Arquivos(pasta))
                {
                    try
                    {
                        if (f.LastWriteTime >= lim) continue;
                        long t = f.Length;
                        if (log.Simulacao) { liberado += t; apagados++; continue; }
                        if ((f.Attributes & FileAttributes.ReadOnly) != 0) f.Attributes &= ~FileAttributes.ReadOnly;
                        f.Delete();
                        liberado += t; apagados++;
                    }
                    catch { ignorados++; }
                }
                if (!log.Simulacao)
                    foreach (var d in Caminho.Arquivos(pasta).Select(x => x.Directory).Concat(SubPastas(pasta)).GroupBy(x => x.FullName).Select(g => g.First()).Where(x => x.FullName.Length > pasta.TrimEnd('\\').Length).OrderByDescending(x => x.FullName.Length).ToList())
                        try { if (!d.EnumerateFileSystemInfos().Any() && d.LastWriteTime < lim) d.Delete(); } catch { }
            }
            catch (Exception ex) { log.Linha("Não foi possível ler " + pasta + ": " + ex.Message); return false; }
            log.Linha(pasta + ": " + apagados + (log.Simulacao ? " arquivos seriam apagados (" + F.Bytes(liberado) + ")" : " arquivos apagados (" + F.Bytes(liberado) + " liberados)") + ", " + ignorados + " em uso/ignorados.");
            return true;
        }

        static IEnumerable<DirectoryInfo> SubPastas(string pasta)
        {
            var l = new List<DirectoryInfo>();
            var pilha = new Stack<DirectoryInfo>();
            try { pilha.Push(new DirectoryInfo(pasta)); } catch { return l; }
            while (pilha.Count > 0)
            {
                var d = pilha.Pop();
                try { foreach (var s in d.GetDirectories()) if ((s.Attributes & FileAttributes.ReparsePoint) == 0) { l.Add(s); pilha.Push(s); } } catch { }
            }
            return l;
        }

        internal static bool LimparCacheWu(LogMelhorias log)
        {
            string pasta = Path.Combine(WinDir, @"SoftwareDistribution\Download");
            if (log.Simulacao) { log.Linha("Pararia wuauserv e bits, limparia " + pasta + " e reiniciaria os serviços."); return true; }
            var parados = new List<ServiceController>();
            try
            {
                foreach (var nome in new[] { "wuauserv", "bits" })
                {
                    var sc = new ServiceController(nome);
                    if (sc.Status != ServiceControllerStatus.Stopped)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
                        parados.Add(sc);
                        log.Linha("Serviço " + nome + " parado.");
                    }
                }
                long t = 0; int n = 0, falhas = 0;
                foreach (var f in Caminho.Arquivos(pasta))
                    try { long x = f.Length; f.Delete(); t += x; n++; } catch { falhas++; }
                foreach (var d in new DirectoryInfo(pasta).GetDirectories())
                    try { d.Delete(true); } catch { }
                log.Linha("Cache do Windows Update: " + n + " arquivos apagados (" + F.Bytes(t) + "), " + falhas + " ignorados.");
                return true;
            }
            catch (Exception ex) { log.Linha("Erro ao limpar o cache do Windows Update: " + ex.Message); return false; }
            finally
            {
                foreach (var sc in parados)
                {
                    try { sc.Start(); sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60)); log.Linha("Serviço " + sc.ServiceName + " iniciado novamente."); }
                    catch (Exception ex) { log.Linha("Atenção: não foi possível reiniciar o serviço " + sc.ServiceName + " (" + ex.Message + "). Reinicie o PC."); }
                    sc.Dispose();
                }
            }
        }

        internal static bool DesativarInicializacao(List<ItemInicializacao> itens, LogMelhorias log)
        {
            bool tudo = true;
            foreach (var it in itens)
            {
                try
                {
                    byte[] antigo = Reg.Valor(it.HiveAprovacao, it.ChaveAprovacao, it.Nome) as byte[];
                    string antigoTxt = antigo == null ? "(sem valor)" : BitConverter.ToString(antigo);
                    if (!log.Simulacao)
                    {
                        var valor = new byte[12];
                        valor[0] = 0x03; // desativado
                        BitConverter.GetBytes(DateTime.Now.ToFileTimeUtc()).CopyTo(valor, 4);
                        using (var b = RegistryKey.OpenBaseKey(it.HiveAprovacao, RegistryView.Registry64))
                        using (var k = b.CreateSubKey(it.ChaveAprovacao))
                            k.SetValue(it.Nome, valor, RegistryValueKind.Binary);
                    }
                    log.Linha("Inicialização desativada: \"" + it.Nome + "\" (" + (it.HiveAprovacao == RegistryHive.CurrentUser ? "HKCU" : "HKLM") + "\\" + it.ChaveAprovacao + ", valor anterior " + antigoTxt + ").");
                }
                catch (Exception ex) { tudo = false; log.Linha("Falha ao desativar \"" + it.Nome + "\": " + ex.Message); }
            }
            return tudo;
        }

        internal static List<Tuple<string, string, bool>> ListarPlanos()
        {
            var l = new List<Tuple<string, string, bool>>();
            string s = Console2.Capturar("powercfg", "/list");
            foreach (Match m in Regex.Matches(s, @"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s+\(([^)]+)\)(\s*\*)?"))
                l.Add(Tuple.Create(m.Groups[1].Value.ToLowerInvariant(), m.Groups[2].Value.Trim(), m.Groups[3].Success && m.Groups[3].Value.Contains("*")));
            return l;
        }

        internal static bool AjustarEfeitos(LogMelhorias log)
        {
            var antes = new List<string>();
            foreach (var e in Efeitos) antes.Add("0x" + e[1].ToString("X") + "=" + Spi(e[0]));
            var ai = new Nativo.ANIMATIONINFO { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(Nativo.ANIMATIONINFO)) };
            Nativo.SystemParametersInfo(0x0048, ai.cbSize, ref ai, 0);
            antes.Add("animação de minimizar=" + ai.iMinAnimate);
            int? transp = Reg.Int(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency");
            int? fx = Reg.Int(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting");
            antes.Add("EnableTransparency=" + (transp.HasValue ? transp.Value.ToString() : "(padrão)"));
            antes.Add("VisualFXSetting=" + (fx.HasValue ? fx.Value.ToString() : "(padrão)"));
            log.Linha("Efeitos visuais antes: " + string.Join("; ", antes));
            if (log.Simulacao) { log.Linha("Desligaria animações, sombras, fades e transparência."); return true; }

            const uint SPIF = 0x01 | 0x02; // SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
            foreach (var e in Efeitos) Nativo.SystemParametersInfo(e[1], 0, IntPtr.Zero, SPIF);
            ai.iMinAnimate = 0;
            Nativo.SystemParametersInfo(0x0049, ai.cbSize, ref ai, SPIF);
            using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) k.SetValue("EnableTransparency", 0, RegistryValueKind.DWord);
            using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects")) k.SetValue("VisualFXSetting", 3, RegistryValueKind.DWord);
            log.Linha("Efeitos visuais ajustados para desempenho (personalizado). Alguns só mudam totalmente após sair e entrar na conta.");
            return true;
        }

        // ------------------------------------------------------------------ Ponto de restauração

        static DateTime? UltimoPontoRestauracao()
        {
            try
            {
                return W.Q(@"root\default", "SELECT CreationTime FROM SystemRestore").Select(o => W.D(o, "CreationTime")).Where(d => d.HasValue).Max();
            }
            catch { return null; }
        }

        static uint CriarPonto()
        {
            // O Windows só cria 1 ponto a cada 24 h. Para garantir um ponto novo, zeramos
            // SystemRestorePointCreationFrequency só durante a criação e devolvemos o valor original.
            const string chave = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
            object antigo = null; bool alterou = false;
            try
            {
                using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var k = b.CreateSubKey(chave))
                {
                    antigo = k.GetValue("SystemRestorePointCreationFrequency");
                    k.SetValue("SystemRestorePointCreationFrequency", 0, RegistryValueKind.DWord);
                    alterou = true;
                }
            }
            catch { }
            try
            {
                using (var cls = new ManagementClass(@"\\.\root\default", "SystemRestore", null))
                {
                    var inp = cls.GetMethodParameters("CreateRestorePoint");
                    inp["Description"] = "PCDiagnostico - antes das melhorias " + DateTime.Now.ToString("dd/MM HH:mm");
                    inp["RestorePointType"] = 12;  // MODIFY_SETTINGS
                    inp["EventType"] = 100;        // BEGIN_SYSTEM_CHANGE
                    var outp = cls.InvokeMethod("CreateRestorePoint", inp, null);
                    return Convert.ToUInt32(outp["ReturnValue"]);
                }
            }
            finally
            {
                if (alterou)
                    try
                    {
                        using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                        using (var k = b.CreateSubKey(chave))
                        {
                            if (antigo == null) k.DeleteValue("SystemRestorePointCreationFrequency", false);
                            else k.SetValue("SystemRestorePointCreationFrequency", antigo, RegistryValueKind.DWord);
                        }
                    }
                    catch { }
            }
        }

        internal static bool CriarPontoRestauracao(LogMelhorias log)
        {
            Console.WriteLine("\n  Criando ponto de restauração (pode levar 1 minuto)...");
            if (log.Simulacao) { log.Linha("Criaria um ponto de restauração \"PCDiagnostico - antes das melhorias\"."); return true; }
            DateTime inicio = DateTime.Now;
            uint r;
            try { r = CriarPonto(); }
            catch (Exception ex) { log.Linha("Erro ao criar ponto de restauração: " + ex.Message); return false; }
            if (r != 0)
            {
                log.Linha("O Windows recusou o ponto de restauração (código " + r + "). Provavelmente a Proteção do Sistema está desligada.");
                string sist = Path.GetPathRoot(Environment.SystemDirectory);
                if (Console2.Confirmar("Ativar a Proteção do Sistema em " + sist + " (usa até ~5% do disco) e tentar de novo?"))
                {
                    try
                    {
                        using (var cls = new ManagementClass(@"\\.\root\default", "SystemRestore", null))
                        {
                            var inp = cls.GetMethodParameters("Enable");
                            inp["Drive"] = sist;
                            var o = cls.InvokeMethod("Enable", inp, null);
                            log.Linha("Proteção do Sistema ativada em " + sist + " (código " + o["ReturnValue"] + ").");
                        }
                        r = CriarPonto();
                    }
                    catch (Exception ex) { log.Linha("Falha: " + ex.Message); return false; }
                }
                if (r != 0) return false;
            }
            DateTime? ultimo = UltimoPontoRestauracao();
            if (ultimo.HasValue && ultimo.Value >= inicio.AddMinutes(-2))
                log.Linha("Ponto de restauração criado em " + F.Data(ultimo.Value) + ".");
            else if (ultimo.HasValue)
                log.Linha("O Windows não criou um novo ponto porque já existe um recente (" + F.Data(ultimo.Value) + "); ele será o ponto de volta.");
            else
                log.Linha("Ponto de restauração solicitado.");
            return true;
        }

        // ------------------------------------------------------------------ Modo interativo

        public static void ModoInterativo(bool simular)
        {
            Console2.Cor(ConsoleColor.Cyan, "\n  MELHORIAS DO PC" + (simular ? "  —  SIMULAÇÃO (nada será alterado)" : ""));
            Console.WriteLine("  Você escolhe item por item e confirma cada um. Antes de qualquer mudança é criado um");
            Console.WriteLine("  ponto de restauração, e tudo fica registrado em log.\n");

            if (!simular && !Console2.EhAdmin())
            {
                Console.WriteLine("  Aplicar melhorias exige administrador, porque o ponto de restauração (e várias melhorias)");
                Console.WriteLine("  precisam dessa permissão. O Windows vai mostrar o aviso do Controle de Conta de Usuário.");
                if (Console2.Confirmar("Abrir o modo de melhorias como administrador?")) Console2.ReabrirComoAdmin("--melhorias");
                return;
            }

            Console.WriteLine("  Analisando o que pode ser melhorado...");
            var lista = Detectar().Where(m => m.Disponivel).ToList();
            if (lista.Count == 0) { Console2.Cor(ConsoleColor.Green, "  Nenhuma melhoria disponível."); return; }
            Console.WriteLine();
            for (int i = 0; i < lista.Count; i++)
            {
                Console2.Cor(ConsoleColor.White, "  [" + (i + 1) + "] " + lista[i].Titulo);
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("      " + lista[i].Estado);
                Console.ResetColor();
            }
            string r = Console2.Ler("\n  Digite os números das melhorias que deseja (ex.: 1,3,4) ou Enter para cancelar: ");
            if (string.IsNullOrEmpty(r)) { Console.WriteLine("  Cancelado. Nada foi alterado."); return; }
            var idx = r.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => { int k; return int.TryParse(x, out k) ? k : 0; }).Where(k => k >= 1 && k <= lista.Count).Distinct().ToList();

            var confirmadas = new List<Melhoria>();
            foreach (int k in idx)
            {
                var m = lista[k - 1];
                Console.WriteLine();
                Console2.Cor(ConsoleColor.Cyan, "  " + m.Titulo);
                Console.WriteLine("    O que faz: " + m.Descricao);
                Console.WriteLine("    Situação:  " + m.Estado);
                Console.WriteLine("    Risco:     " + m.Risco);
                if (m.Preparar != null && !m.Preparar()) { Console.WriteLine("    Nenhuma opção escolhida; item ignorado."); continue; }
                if (Console2.Confirmar("Aplicar \"" + m.Titulo + "\"?")) confirmadas.Add(m);
            }
            if (confirmadas.Count == 0) { Console.WriteLine("\n  Nenhuma melhoria confirmada. Nada foi alterado."); return; }

            Console.WriteLine("\n  Serão aplicadas:");
            foreach (var m in confirmadas) Console.WriteLine("   - " + m.Titulo);
            if (!Console2.Confirmar("Confirmar e aplicar agora?")) { Console.WriteLine("  Cancelado. Nada foi alterado."); return; }

            var log = new LogMelhorias(simular);
            log.Linha("=== Início das melhorias (" + Environment.UserName + "@" + Environment.MachineName + ") ===");
            Backup.Criar(log);
            if (!CriarPontoRestauracao(log))
            {
                Console2.Cor(ConsoleColor.Yellow, "  Não foi possível criar o ponto de restauração.");
                if (!Console2.Confirmar("Continuar SEM ponto de restauração? (não recomendado)")) { log.Linha("Cancelado pelo usuário: sem ponto de restauração."); return; }
                log.Linha("Usuário optou por continuar sem ponto de restauração.");
            }
            foreach (var m in confirmadas)
            {
                Console2.Cor(ConsoleColor.Cyan, "\n  > " + m.Titulo);
                bool ok;
                try { ok = m.Aplicar(log); }
                catch (Exception ex) { ok = false; log.Linha("Erro: " + ex.Message); }
                log.Linha((ok ? "OK: " : "CONCLUÍDO COM ERROS: ") + m.Titulo);
            }
            log.Linha("=== Fim das melhorias ===");
            Console2.Cor(ConsoleColor.Green, "\n  Pronto. Log salvo em: " + log.Arquivo);
            Console.WriteLine("  Para desfazer tudo: Painel de Controle > Recuperação > Abrir Restauração do Sistema.");
            Reinicio.Perguntar(simular, confirmadas.Where(m => m.Titulo.Contains("SMBv1") || m.Titulo.Contains("Reparar")).Select(m => m.Titulo + " pede reinicialização para concluir"));
        }

        // ------------------------------------------------------------------ Defender e relatórios

        internal static string MpCmdRun()
        {
            try
            {
                string plat = @"C:\ProgramData\Microsoft\Windows Defender\Platform";
                if (Directory.Exists(plat))
                {
                    var d = new DirectoryInfo(plat).GetDirectories().OrderByDescending(x => x.Name).Select(x => Path.Combine(x.FullName, "MpCmdRun.exe")).FirstOrDefault(File.Exists);
                    if (d != null) return d;
                }
            }
            catch { }
            string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
            return File.Exists(pf) ? pf : null;
        }

        public static void VerificacaoRapida(bool simular)
        {
            Console2.Cor(ConsoleColor.Cyan, "\n  VERIFICAÇÃO RÁPIDA DO MICROSOFT DEFENDER");
            string mp = MpCmdRun();
            if (mp == null) { Console2.Cor(ConsoleColor.Yellow, "  MpCmdRun.exe não encontrado. O Defender pode estar desinstalado ou substituído por outro antivírus."); return; }
            Console.WriteLine("  Verifica memória, inicialização e locais onde malwares costumam ficar (leva de 2 a 10 minutos).");
            Console.WriteLine("  Se algo for encontrado, o próprio Defender trata a ameaça conforme as configurações dele.");
            if (!Console2.Confirmar("Iniciar a verificação rápida agora?")) { Console.WriteLine("  Cancelado."); return; }
            if (simular) { Console.WriteLine("  [SIMULAÇÃO] Rodaria: \"" + mp + "\" -Scan -ScanType 1"); return; }
            int c = Console2.Rodar(mp, "-Scan -ScanType 1");
            if (c == 0) Console2.Cor(ConsoleColor.Green, "\n  Verificação concluída: nenhuma ameaça encontrada.");
            else if (c == 2) Console2.Cor(ConsoleColor.Red, "\n  Ameaças encontradas! Abra Segurança do Windows > Proteção contra vírus e ameaças para ver e remover.");
            else Console2.Cor(ConsoleColor.Yellow, "\n  A verificação terminou com código " + c + ". Se pediu permissão, rode o PCDiagnostico como administrador.");
            try { File.AppendAllText(Path.Combine(Console2.PastaRelatorios(), "melhorias-log.txt"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " Verificação rápida do Defender: código " + c + Environment.NewLine, new UTF8Encoding(true)); } catch { }
        }

        public static void RelatoriosWindows(bool apenasEnergia)
        {
            string pasta = Console2.PastaRelatorios();
            Directory.CreateDirectory(pasta);
            string stamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm");
            if (!apenasEnergia)
            {
                Console2.Cor(ConsoleColor.Cyan, "\n  RELATÓRIOS DO WINDOWS (somente leitura; geram arquivos HTML em " + pasta + ")");
                Console.WriteLine("  [1] Relatório de bateria (powercfg /batteryreport) — notebooks");
                Console.WriteLine("  [2] Relatório de eficiência energética (powercfg /energy, 60 s, exige administrador)");
                string r = Console2.Ler("  Escolha (Enter para voltar): ");
                if (r == "1")
                {
                    string arq = Path.Combine(pasta, "bateria-" + stamp + ".html");
                    int c = Console2.Rodar("powercfg", "/batteryreport /output \"" + arq + "\"");
                    if (c == 0 && File.Exists(arq)) Process.Start(new ProcessStartInfo(arq) { UseShellExecute = true });
                    else Console2.Cor(ConsoleColor.Yellow, "  Não foi possível gerar (este PC pode não ter bateria).");
                    return;
                }
                if (r != "2") return;
                if (!Console2.EhAdmin())
                {
                    if (Console2.Confirmar("O relatório de energia exige administrador. Abrir como administrador?")) Console2.ReabrirComoAdmin("--relatorio-energia");
                    return;
                }
            }
            string arqE = Path.Combine(pasta, "energia-" + stamp + ".html");
            Console.WriteLine("  Coletando dados por 60 segundos. Deixe o PC parado...");
            int ce = Console2.Rodar("powercfg", "/energy /output \"" + arqE + "\" /duration 60");
            if (File.Exists(arqE)) { Console.WriteLine("  Salvo em " + arqE); Process.Start(new ProcessStartInfo(arqE) { UseShellExecute = true }); }
            else Console2.Cor(ConsoleColor.Yellow, "  powercfg retornou código " + ce + ".");
        }
    }
}
