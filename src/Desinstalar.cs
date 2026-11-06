using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Win32;

namespace PcDiagnostico
{
    partial class Diagnostico
    {
        /// <summary>Só a análise de aplicativos (usada pelo modo de desinstalação).</summary>
        public void ColetarApps()
        {
            Admin = Console2.EhAdmin();
            VerificarApps();
        }
    }

    /// <summary>
    /// Desinstalação de aplicativos: sempre item por item, com confirmação de cada um,
    /// ponto de restauração antes e log. Usa o desinstalador do próprio programa.
    /// </summary>
    static class Desinstalador
    {
        static bool AindaInstalado(AppInstalado a)
        {
            if (a.Tipo == "Microsoft Store")
            {
                string s = Console2.Capturar("powershell.exe", "-NoProfile -Command \"(Get-AppxPackage -Name '" + a.IdPacote + "' | Measure-Object).Count\"");
                return s.Trim() != "0" && s.Trim() != "";
            }
            foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
                foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                {
                    try
                    {
                        using (var b = RegistryKey.OpenBaseKey(hive, view))
                        using (var k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                        {
                            if (k == null) continue;
                            foreach (var sub in k.GetSubKeyNames())
                                using (var x = k.OpenSubKey(sub))
                                    if (x != null && string.Equals((x.GetValue("DisplayName") as string ?? "").Trim(), a.Nome, StringComparison.OrdinalIgnoreCase)) return true;
                        }
                    }
                    catch { }
                }
            return false;
        }

        static int Rodar(AppInstalado a)
        {
            string cmd = a.ComandoDesinstalar;
            ProcessStartInfo psi;
            if (cmd.StartsWith("powershell", StringComparison.OrdinalIgnoreCase))
                psi = new ProcessStartInfo("powershell.exe", cmd.Substring(cmd.IndexOf(' ') + 1));
            else if (cmd.StartsWith("msiexec /x", StringComparison.OrdinalIgnoreCase))
                psi = new ProcessStartInfo("msiexec.exe", cmd.Substring(8) + " /passive /norestart");
            else
                psi = new ProcessStartInfo("cmd.exe", "/c \"" + cmd + "\"");
            psi.UseShellExecute = false;
            Console2.Cor(ConsoleColor.DarkGray, "    > " + psi.FileName + " " + psi.Arguments);
            using (var p = Process.Start(psi))
            {
                if (!p.WaitForExit(20 * 60 * 1000)) return -2;
                return p.ExitCode;
            }
        }

        public static void Executar(bool simular)
        {
            Console2.Cor(ConsoleColor.Cyan, "\n  DESINSTALAR APLICATIVOS" + (simular ? "  —  SIMULAÇÃO (nada será removido)" : ""));
            Console.WriteLine("  Você escolhe os aplicativos e confirma cada um. Antes, é criado um ponto de restauração.");
            Console.WriteLine("  Cada programa usa o próprio desinstalador (algumas janelas dele podem aparecer).\n");

            if (!simular && !Console2.EhAdmin())
            {
                Console.WriteLine("  Desinstalar exige administrador (o Windows vai mostrar o aviso do UAC).");
                if (Console2.Confirmar("Abrir a desinstalação como administrador?")) Console2.ReabrirComoAdmin("--desinstalar");
                return;
            }

            Console.WriteLine("  Lendo os aplicativos instalados...");
            var d = new Diagnostico();
            d.ColetarApps();
            var sugeridos = d.Apps.Where(a => a.Recomendacao != Recomendacao.Manter && !string.IsNullOrEmpty(a.ComandoDesinstalar))
                .OrderBy(a => a.Recomendacao).ThenByDescending(a => a.Tamanho).ToList();
            var lista = sugeridos;
            Console.WriteLine();
            if (sugeridos.Count == 0) Console2.Cor(ConsoleColor.Green, "  Nenhum aplicativo recomendado para remover.");
            else Imprimir(sugeridos);

            string r = Console2.Ler("\n  Digite os números para desinstalar (ex.: 1,3), T para ver TODOS os aplicativos, ou Enter para sair: ");
            if (r != null && r.Equals("T", StringComparison.OrdinalIgnoreCase))
            {
                lista = d.Apps.Where(a => !string.IsNullOrEmpty(a.ComandoDesinstalar)).OrderBy(a => a.Nome).ToList();
                Imprimir(lista);
                r = Console2.Ler("\n  Digite os números para desinstalar (ex.: 1,3) ou Enter para sair: ");
            }
            if (string.IsNullOrEmpty(r)) { Console.WriteLine("  Nada foi removido."); return; }
            var idx = r.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => { int k; return int.TryParse(x, out k) ? k : 0; }).Where(k => k >= 1 && k <= lista.Count).Distinct().ToList();

            var escolhidos = new List<AppInstalado>();
            foreach (int k in idx)
            {
                var a = lista[k - 1];
                Console.WriteLine();
                Console2.Cor(ConsoleColor.White, "  " + a.Nome + (string.IsNullOrEmpty(a.Editor) ? "" : " — " + a.Editor));
                Console.WriteLine("    Recomendação: " + (a.Recomendacao == Recomendacao.Remover ? "recomendado remover" : a.Recomendacao == Recomendacao.Opcional ? "opcional" : "MANTER") + ". " + a.Motivo);
                if (a.Recomendacao == Recomendacao.Manter && a.Classificacao.Any(c => c.Contains("Componente")))
                    Console2.Cor(ConsoleColor.Red, "    ATENÇÃO: parece ser um componente, driver ou runtime usado por outros programas. Remover pode quebrar outros apps.");
                if (Console2.Confirmar("Desinstalar \"" + a.Nome + "\"?")) escolhidos.Add(a);
            }
            if (escolhidos.Count == 0) { Console.WriteLine("\n  Nada foi removido."); return; }
            Console.WriteLine("\n  Serão desinstalados: " + string.Join(", ", escolhidos.Select(x => x.Nome)));
            if (!Console2.Confirmar("Confirmar e desinstalar agora?")) { Console.WriteLine("  Cancelado. Nada foi removido."); return; }

            var log = new LogMelhorias(simular);
            log.Linha("=== Desinstalação de aplicativos ===");
            if (!Melhorias.CriarPontoRestauracao(log))
            {
                Console2.Cor(ConsoleColor.Yellow, "  Não foi possível criar o ponto de restauração.");
                if (!Console2.Confirmar("Continuar SEM ponto de restauração? (não recomendado)")) { log.Linha("Cancelado: sem ponto de restauração."); return; }
            }
            int ok = 0, falha = 0, pendente = 0;
            foreach (var a in escolhidos)
            {
                Console2.Cor(ConsoleColor.Cyan, "\n  > Desinstalando " + a.Nome);
                if (simular) { log.Linha("Executaria: " + a.ComandoDesinstalar); ok++; continue; }
                int c;
                try { c = Rodar(a); }
                catch (Exception ex) { log.Linha("Falha ao iniciar o desinstalador de " + a.Nome + ": " + ex.Message); falha++; continue; }
                System.Threading.Thread.Sleep(2000);
                if (!AindaInstalado(a)) { ok++; log.Linha("[REMOVIDO] " + a.Nome + " (código " + c + ")."); }
                else if (c == 0 || c == 3010 || c == 1641)
                {
                    pendente++;
                    log.Linha("[VERIFICAR] " + a.Nome + ": o desinstalador terminou (código " + c + "), mas o app ainda aparece. Ele pode ter aberto uma janela própria para concluir ou exigir reinicialização.");
                }
                else { falha++; log.Linha("[FALHOU] " + a.Nome + " (código " + c + "). Tente por Configurações > Aplicativos > Aplicativos instalados."); }
            }
            log.Linha("Resumo: " + ok + (simular ? " seriam removidos, " : " removidos, ") + pendente + " para verificar, " + falha + " falharam.");
            Console2.Cor(ConsoleColor.Green, "\n  Log: " + log.Arquivo);
            Reinicio.Perguntar(simular);
        }

        static void Imprimir(List<AppInstalado> l)
        {
            for (int i = 0; i < l.Count; i++)
            {
                var a = l[i];
                var cor = a.Recomendacao == Recomendacao.Remover ? ConsoleColor.Red : a.Recomendacao == Recomendacao.Opcional ? ConsoleColor.Yellow : ConsoleColor.Gray;
                Console.ForegroundColor = cor;
                Console.Write("  [" + (i + 1).ToString().PadLeft(3) + "] ");
                Console.ResetColor();
                Console.WriteLine(a.Nome + (a.Tamanho > 0 ? " (" + F.Bytes(a.Tamanho) + ")" : "") +
                    (a.Classificacao.Count > 0 ? " — " + string.Join(", ", a.Classificacao) : ""));
            }
        }
    }
}
