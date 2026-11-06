using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace PcDiagnostico
{
    /// <summary>Mede, ao vivo, o que está deixando o PC lento (CPU, RAM, disco por programa, apps travados).</summary>
    class ResultadoTravamento
    {
        public double CpuTotal, MemPct, DiscoPct;
        public List<Tuple<string, double>> TopCpu = new List<Tuple<string, double>>();     // nome, %
        public List<Tuple<string, long>> TopRam = new List<Tuple<string, long>>();         // nome, bytes
        public List<Tuple<string, double>> TopDisco = new List<Tuple<string, double>>();   // nome, bytes/s
        public List<string> NaoRespondendo = new List<string>();
        public List<Tuple<Gravidade, string, string, string>> Causas = new List<Tuple<Gravidade, string, string, string>>(); // gravidade, título, explicação, solução
    }

    static class Travamento
    {
        [StructLayout(LayoutKind.Sequential)]
        struct IO_COUNTERS { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }

        [DllImport("kernel32.dll")] static extern bool GetProcessIoCounters(IntPtr h, out IO_COUNTERS c);
        [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

        static ulong Io(int pid)
        {
            IntPtr h = OpenProcess(0x1000, false, pid);
            if (h == IntPtr.Zero) return 0;
            try { IO_COUNTERS c; return GetProcessIoCounters(h, out c) ? c.ReadBytes + c.WriteBytes : 0; }
            finally { CloseHandle(h); }
        }

        // Processos do Windows que costumam pesar temporariamente, com explicação
        static readonly Dictionary<string, string> Conhecidos = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "MsMpEng", "é o Microsoft Defender verificando arquivos. Costuma passar sozinho; se for constante, adicione exclusões só para pastas de jogos confiáveis" },
            { "TiWorker", "é o Windows Update instalando atualizações. Espere terminar e reinicie" },
            { "TrustedInstaller", "é o Windows instalando atualizações ou recursos. Espere terminar e reinicie" },
            { "SearchIndexer", "é a indexação da pesquisa do Windows. Passa sozinho depois de indexar os arquivos" },
            { "SearchProtocolHost", "é a indexação da pesquisa do Windows" },
            { "CompatTelRunner", "é a telemetria de compatibilidade do Windows. Roda de vez em quando e termina sozinha" },
            { "MoUsoCoreWorker", "é o Windows Update procurando/baixando atualizações" },
            { "svchost", "são serviços do Windows (muitas vezes Windows Update ou Defender)" },
            { "dwm", "é o gerenciador de janelas. Uso alto costuma indicar driver de vídeo desatualizado ou muitos monitores/efeitos" },
            { "System", "é o núcleo do Windows. Uso alto e constante costuma indicar driver com problema" },
            { "Memory Compression", "é o Windows compactando memória porque a RAM está cheia" },
            { "OneDrive", "é o OneDrive sincronizando arquivos" },
        };

        static string Explica(string nome)
        {
            string e;
            return Conhecidos.TryGetValue(nome, out e) ? " (" + e + ")" : "";
        }

        public static ResultadoTravamento Medir(int segundos = 3)
        {
            var r = new ResultadoTravamento();
            int nucleos = Environment.ProcessorCount;
            var cpu0 = new Dictionary<int, TimeSpan>();
            var io0 = new Dictionary<int, ulong>();
            var nomes = new Dictionary<int, string>();
            foreach (var p in Process.GetProcesses())
            {
                try { nomes[p.Id] = p.ProcessName; cpu0[p.Id] = p.TotalProcessorTime; } catch { }
                try { io0[p.Id] = Io(p.Id); } catch { }
                p.Dispose();
            }

            // Disco e CPU total durante a janela de medição
            var discos = new List<double>(); var cpus = new List<double>();
            var sw = Stopwatch.StartNew();
            W.QS(W.Cimv2, "SELECT PercentDiskTime FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk WHERE Name = '_Total'"); // aquece o contador
            while (sw.ElapsedMilliseconds < segundos * 1000)
            {
                Thread.Sleep(700);
                foreach (var o in W.QS(W.Cimv2, "SELECT PercentDiskTime FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk WHERE Name = '_Total'"))
                    discos.Add(Math.Min(100, W.L(o, "PercentDiskTime")));
                foreach (var o in W.QS(W.Cimv2, "SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name = '_Total'"))
                    cpus.Add(W.L(o, "PercentProcessorTime"));
            }
            double dt = sw.Elapsed.TotalSeconds;
            r.DiscoPct = discos.Count > 0 ? discos.Average() : 0;
            r.CpuTotal = cpus.Count > 0 ? cpus.Average() : 0;

            var porNomeCpu = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            var porNomeIo = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            var porNomeRam = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    string n = p.ProcessName;
                    TimeSpan t0;
                    if (cpu0.TryGetValue(p.Id, out t0))
                    {
                        double pct = (p.TotalProcessorTime - t0).TotalSeconds / (dt * nucleos) * 100;
                        double v; porNomeCpu.TryGetValue(n, out v); porNomeCpu[n] = v + pct;
                    }
                    ulong i0;
                    if (io0.TryGetValue(p.Id, out i0) && i0 > 0)
                    {
                        ulong agora = Io(p.Id);
                        double bps = agora >= i0 ? (agora - i0) / dt : 0;
                        double v; porNomeIo.TryGetValue(n, out v); porNomeIo[n] = v + Math.Max(0, bps);
                    }
                    long ws; porNomeRam.TryGetValue(n, out ws); porNomeRam[n] = ws + p.WorkingSet64;
                    if (p.MainWindowHandle != IntPtr.Zero && !p.Responding)
                        r.NaoRespondendo.Add(n + (string.IsNullOrEmpty(p.MainWindowTitle) ? "" : " — \"" + F.Corta(p.MainWindowTitle, 60) + "\""));
                }
                catch { }
                finally { p.Dispose(); }
            }
            porNomeCpu.Remove("Idle");
            r.TopCpu = porNomeCpu.Where(x => x.Value >= 1).OrderByDescending(x => x.Value).Take(6).Select(x => Tuple.Create(x.Key, x.Value)).ToList();
            r.TopDisco = porNomeIo.Where(x => x.Value >= 512 * 1024).OrderByDescending(x => x.Value).Take(5).Select(x => Tuple.Create(x.Key, x.Value)).ToList();
            r.TopRam = porNomeRam.OrderByDescending(x => x.Value).Take(6).Select(x => Tuple.Create(x.Key, x.Value)).ToList();

            foreach (var o in W.QS(W.Cimv2, "SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem"))
            {
                double tot = W.L(o, "TotalVisibleMemorySize"), liv = W.L(o, "FreePhysicalMemory");
                if (tot > 0) r.MemPct = 100 * (tot - liv) / tot;
            }

            Classificar(r);
            return r;
        }

        static string ListaCpu(ResultadoTravamento r) { return string.Join("; ", r.TopCpu.Take(3).Select(x => x.Item1 + " " + x.Item2.ToString("0", F.BR) + "%" + Explica(x.Item1))); }

        static void Classificar(ResultadoTravamento r)
        {
            if (r.CpuTotal >= 85)
                r.Causas.Add(Tuple.Create(Gravidade.Critico, "Processador no limite (" + F.Pct(r.CpuTotal) + ")",
                    "Quem mais usa: " + ListaCpu(r) + ".",
                    "Feche os programas que mais usam o processador (Gerenciador de Tarefas > Processos > clique na coluna CPU). Se for um processo do Windows explicado acima, espere ele terminar. Se o uso alto for constante sem nada aberto, rode a verificação do Defender."));
            else
                foreach (var p in r.TopCpu.Where(x => x.Item2 >= 25))
                    r.Causas.Add(Tuple.Create(Gravidade.Aviso, p.Item1 + " está usando " + p.Item2.ToString("0", F.BR) + "% do processador",
                        "Um único programa ocupando o processador deixa o resto lento" + Explica(p.Item1) + ".",
                        "Se você não está usando esse programa, feche-o pelo Gerenciador de Tarefas (botão direito > Finalizar tarefa). Se ele abrir sozinho sempre, desative-o na inicialização."));

            if (r.MemPct >= 80)
                r.Causas.Add(Tuple.Create(r.MemPct >= 90 ? Gravidade.Critico : Gravidade.Aviso, "Memória RAM quase cheia (" + F.Pct(r.MemPct) + ")",
                    "Com a RAM cheia o Windows passa a usar o disco como memória, e tudo trava. Quem mais usa: " + string.Join("; ", r.TopRam.Take(4).Select(x => x.Item1 + " " + F.Bytes(x.Item2))) + ".",
                    "Feche abas do navegador e programas que não está usando. Desative programas pesados na inicialização (opção [9] ou [2]). Se acontecer sempre, considere mais RAM (veja a seção de peças)."));

            if (r.DiscoPct >= 70)
                r.Causas.Add(Tuple.Create(r.DiscoPct >= 90 ? Gravidade.Critico : Gravidade.Aviso, "Disco muito ocupado (" + F.Pct(r.DiscoPct) + " do tempo)",
                    "O disco está atendendo pedidos quase o tempo todo, o que deixa programas lentos para abrir." +
                    (r.TopDisco.Count > 0 ? " Quem mais lê/grava: " + string.Join("; ", r.TopDisco.Take(3).Select(x => x.Item1 + " " + F.Bytes(x.Item2) + "/s" + Explica(x.Item1))) + "." : ""),
                    "Espere downloads, atualizações ou verificações de antivírus terminarem. Se for um HD mecânico com o Windows, trocar por SSD resolve (veja a seção de peças). Se o disco ficar em 100% sempre, rode o chkdsk e confira a saúde do disco."));

            if (r.NaoRespondendo.Count > 0)
                r.Causas.Add(Tuple.Create(Gravidade.Aviso, r.NaoRespondendo.Count + " programa(s) não está(ão) respondendo",
                    "Travados agora: " + string.Join("; ", r.NaoRespondendo) + ".",
                    "Espere alguns segundos; se não voltar, feche pelo Gerenciador de Tarefas (botão direito > Finalizar tarefa). Se travar sempre, atualize ou reinstale esse programa."));
        }

        public static void Imprimir(ResultadoTravamento r)
        {
            Console.WriteLine();
            Console.WriteLine("  ──────────────── O QUE ESTÁ TRAVANDO O PC AGORA ────────────────");
            Console.WriteLine("  Processador: " + F.Pct(r.CpuTotal) + "   Memória: " + F.Pct(r.MemPct) + "   Disco: " + F.Pct(r.DiscoPct) + " do tempo ocupado");
            if (r.TopCpu.Count > 0) Console2.Cor(ConsoleColor.Gray, "  Mais CPU: " + string.Join(", ", r.TopCpu.Select(x => x.Item1 + " " + x.Item2.ToString("0", F.BR) + "%")));
            if (r.TopRam.Count > 0) Console2.Cor(ConsoleColor.Gray, "  Mais RAM: " + string.Join(", ", r.TopRam.Take(5).Select(x => x.Item1 + " " + F.Bytes(x.Item2))));
            if (r.TopDisco.Count > 0) Console2.Cor(ConsoleColor.Gray, "  Mais disco: " + string.Join(", ", r.TopDisco.Select(x => x.Item1 + " " + F.Bytes(x.Item2) + "/s")));
            if (r.Causas.Count == 0) { Console2.Cor(ConsoleColor.Green, "  Nada está travando o PC neste momento."); return; }
            foreach (var c in r.Causas)
            {
                Console2.Cor(c.Item1 == Gravidade.Critico ? ConsoleColor.Red : ConsoleColor.Yellow, "\n  " + (c.Item1 == Gravidade.Critico ? "[CRÍTICO] " : "[AVISO] ") + c.Item2);
                Console.WriteLine("     " + c.Item3);
                var passos = Passos.De(c.Item4);
                for (int i = 0; i < passos.Count; i++) Console.WriteLine("     Passo " + (i + 1) + ": " + passos[i]);
            }
        }
    }

    partial class Diagnostico
    {
        public ResultadoTravamento Travamento;
        public List<string> MotivosReinicio = new List<string>();

        void VerificarTravamento()
        {
            Travamento = PcDiagnostico.Travamento.Medir(3);
            var r = Travamento;
            if (r.Causas.Count == 0)
            {
                var ok = Add(Cat.Desempenho, Gravidade.Ok, "Nada está travando o PC neste momento",
                    "Processador " + F.Pct(r.CpuTotal) + ", memória " + F.Pct(r.MemPct) + " e disco " + F.Pct(r.DiscoPct) + " ocupados durante a medição.", null);
                if (r.TopCpu.Count > 0) ok.Detalhes.Add("Mais CPU: " + string.Join(", ", r.TopCpu.Select(x => x.Item1 + " " + x.Item2.ToString("0", F.BR) + "%")));
            }
            foreach (var c in r.Causas)
            {
                var a = Add(Cat.Desempenho, c.Item1, "Travando o PC: " + c.Item2, c.Item3, c.Item4, "taskmgr");
                if (c.Item2.Contains("Memória")) a.Detalhes.AddRange(r.TopRam.Select(x => x.Item1 + ": " + F.Bytes(x.Item2)));
                else if (c.Item2.Contains("Disco")) a.Detalhes.AddRange(r.TopDisco.Select(x => x.Item1 + ": " + F.Bytes(x.Item2) + "/s"));
                else a.Detalhes.AddRange(r.TopCpu.Select(x => x.Item1 + ": " + x.Item2.ToString("0", F.BR) + "% do processador"));
            }

            MotivosReinicio = Reinicio.Motivos();
            if (MotivosReinicio.Count > 0)
            {
                var a = Add(Cat.Desempenho, Gravidade.Aviso, "O PC precisa reiniciar",
                    "Há mudanças pendentes que só terminam de ser aplicadas depois de reiniciar. Enquanto isso, o PC pode ficar lento ou instável.",
                    "Salve seus arquivos e reinicie pelo menu Iniciar > Energia > Reiniciar (não use \"Desligar\").");
                a.Detalhes.AddRange(MotivosReinicio);
            }
        }
    }

    /// <summary>Detecta se o Windows precisa reiniciar e oferece reiniciar.</summary>
    static class Reinicio
    {
        public static List<string> Motivos()
        {
            var l = new List<string>();
            if (Reg.Existe(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
                l.Add("Componentes do Windows foram atualizados e só terminam de instalar ao reiniciar");
            if (Reg.Existe(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
                l.Add("O Windows Update instalou atualizações que exigem reinicialização");
            var pfro = Reg.Valor(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations") as string[];
            if (pfro != null && pfro.Any(x => !string.IsNullOrWhiteSpace(x)))
                l.Add("Há arquivos aguardando substituição (comum após instalar, atualizar ou desinstalar programas e drivers)");
            string ativo = Reg.Valor(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", "ComputerName") as string;
            string novo = Reg.Valor(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName") as string;
            if (ativo != null && novo != null && !ativo.Equals(novo, StringComparison.OrdinalIgnoreCase))
                l.Add("O nome do computador foi alterado");
            try
            {
                var boot = W.QS(W.Cimv2, "SELECT LastBootUpTime FROM Win32_OperatingSystem").Select(o => W.D(o, "LastBootUpTime")).FirstOrDefault();
                if (boot.HasValue && (DateTime.Now - boot.Value).TotalDays >= 2)
                    l.Add("O PC está ligado há " + F.Duracao(DateTime.Now - boot.Value) + " sem reiniciar por completo (o \"Desligar\" com Inicialização Rápida não zera isso). Reiniciar libera memória e conclui atualizações");
            }
            catch { }
            return l;
        }

        public static TimeSpan? Ligado()
        {
            try { return TimeSpan.FromMilliseconds(Environment.TickCount & int.MaxValue); } catch { return null; }
        }

        /// <summary>Mostra se precisa reiniciar e pergunta se quer reiniciar agora (nunca reinicia sem confirmação).</summary>
        public static void Perguntar(bool simular, IEnumerable<string> extras = null)
        {
            var m = Motivos();
            if (extras != null) m.AddRange(extras);
            Console.WriteLine();
            if (m.Count == 0) { Console2.Cor(ConsoleColor.Green, "  O PC não precisa reiniciar agora."); return; }
            Console2.Cor(ConsoleColor.Yellow, "  O PC PRECISA REINICIAR para concluir:");
            foreach (var x in m.Distinct()) Console.WriteLine("   - " + x);
            if (!Console2.Confirmar("Reiniciar POR COMPLETO agora? (salve seus arquivos antes; o PC reinicia em 30 segundos)")) { Console.WriteLine("  Ok, reinicie quando puder (use Reiniciar, não Desligar)."); return; }
            ReiniciarCompleto(simular);
        }

        /// <summary>Reinício completo: o "Reiniciar" do Windows não usa a Inicialização Rápida, então zera memória, drivers e serviços.</summary>
        public static void ReiniciarCompleto(bool simular)
        {
            if (simular) { Console.WriteLine("  [SIMULAÇÃO] Rodaria: shutdown /r /t 30"); return; }
            Console2.Rodar("shutdown", "/r /t 30 /c \"PCDiagnostico: reinicio completo em 30 segundos. Para cancelar: shutdown /a\"");
            Console.WriteLine("  Reiniciando por completo em 30 segundos. Para cancelar, rode: shutdown /a");
        }

        /// <summary>Desligamento completo (sem Inicialização Rápida): na próxima vez o Windows inicia do zero.</summary>
        public static void DesligarCompleto(bool simular)
        {
            if (!Console2.Confirmar("Desligar POR COMPLETO agora? (salve seus arquivos; desliga em 30 segundos)")) return;
            if (simular) { Console.WriteLine("  [SIMULAÇÃO] Rodaria: shutdown /s /full /t 30"); return; }
            Console2.Rodar("shutdown", "/s /full /t 30 /c \"PCDiagnostico: desligamento completo em 30 segundos. Para cancelar: shutdown /a\"");
            Console.WriteLine("  Desligando por completo em 30 segundos. Para cancelar, rode: shutdown /a");
        }
    }
}
