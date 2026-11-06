using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PcDiagnostico
{
    /// <summary>
    /// Backup próprio das configurações que as melhorias/otimização alteram (além do ponto de restauração),
    /// e a opção "Desfazer otimização" que restaura esse backup.
    /// </summary>
    static class Backup
    {
        // Chaves exportadas inteiras (reg export). "Substituir" = apaga a chave antes de importar (restauração exata).
        static readonly Tuple<string, bool>[] Chaves =
        {
            Tuple.Create(@"HKCU\Control Panel\Desktop", false),                                             // animações, sombras (UserPreferencesMask, MinAnimate)
            Tuple.Create(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", false),        // transparência
            Tuple.Create(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", false),   // efeitos visuais
            Tuple.Create(@"HKCU\Software\Microsoft\GameBar", false),                                          // Modo de Jogo
            Tuple.Create(@"HKCU\System\GameConfigStore", false),                                              // Game DVR
            Tuple.Create(@"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR", false),
            Tuple.Create(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved", true),  // programas na inicialização
            Tuple.Create(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved", true),
            Tuple.Create(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", false),          // UAC
        };

        // Valores que podem ser criados do zero; se não existiam, são apagados ao desfazer
        static readonly string[][] ValoresCriados =
        {
            new[] { @"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency" },
            new[] { @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting" },
            new[] { @"HKCU\Software\Microsoft\GameBar", "AutoGameModeEnabled" },
            new[] { @"HKCU\System\GameConfigStore", "GameDVR_Enabled" },
            new[] { @"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled" },
        };

        public static string PastaBackups { get { return Path.Combine(Console2.PastaRelatorios(), "backups"); } }

        static bool ValorExiste(string chave, string valor)
        {
            var hive = chave.StartsWith("HKLM") ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
            return Reg.Valor(hive, chave.Substring(5), valor) != null;
        }

        static bool ChaveExiste(string chave)
        {
            var hive = chave.StartsWith("HKLM") ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
            return Reg.Existe(hive, chave.Substring(5));
        }

        static int Reg_(string args) { return Console2.RodarSilencioso("reg.exe", args); }

        /// <summary>Salva o backup. Retorna a pasta ou null se falhar.</summary>
        public static string Criar(LogMelhorias log)
        {
            string pasta = Path.Combine(PastaBackups, DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss"));
            if (log.Simulacao) { log.Linha("Salvaria backup das configurações em " + pasta); return pasta; }
            try
            {
                Directory.CreateDirectory(pasta);
                var manifesto = new StringBuilder();
                var cmd = new StringBuilder("@echo off\r\nchcp 65001 >nul\r\necho Restaurando configuracoes salvas pelo PCDiagnostico...\r\n");
                for (int i = 0; i < Chaves.Length; i++)
                {
                    string ch = Chaves[i].Item1;
                    if (!ChaveExiste(ch)) { manifesto.AppendLine("AUSENTE\t" + ch); cmd.AppendLine("reg delete \"" + ch + "\" /f >nul 2>&1"); continue; }
                    string arq = "chave" + i + ".reg";
                    int c = Reg_("export \"" + ch + "\" \"" + Path.Combine(pasta, arq) + "\" /y");
                    if (c != 0) { log.Linha("Aviso: não foi possível exportar " + ch + " (código " + c + ")."); continue; }
                    manifesto.AppendLine((Chaves[i].Item2 ? "SUBSTITUIR" : "IMPORTAR") + "\t" + ch + "\t" + arq);
                    if (Chaves[i].Item2) cmd.AppendLine("reg delete \"" + ch + "\" /f >nul 2>&1");
                    cmd.AppendLine("reg import \"%~dp0" + arq + "\"");
                }
                foreach (var v in ValoresCriados)
                    if (!ValorExiste(v[0], v[1]))
                    {
                        manifesto.AppendLine("APAGARVALOR\t" + v[0] + "\t" + v[1]);
                        cmd.AppendLine("reg delete \"" + v[0] + "\" /v " + v[1] + " /f >nul 2>&1");
                    }
                var m = Regex.Match(Console2.Capturar("powercfg", "/getactivescheme"), @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
                if (m.Success)
                {
                    manifesto.AppendLine("PLANO\t" + m.Value);
                    cmd.AppendLine("powercfg /setactive " + m.Value);
                }
                cmd.AppendLine("echo Pronto. Saia e entre na sua conta (ou reinicie) para os efeitos visuais voltarem.\r\npause");
                File.WriteAllText(Path.Combine(pasta, "backup.txt"), manifesto.ToString(), new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(pasta, "desfazer.cmd"), cmd.ToString(), new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(pasta, "LEIA-ME.txt"),
                    "Backup das configurações feito pelo PCDiagnostico em " + DateTime.Now.ToString("dd/MM/yyyy HH:mm") + ".\r\n" +
                    "Para desfazer a otimização: abra o PCDiagnostico e escolha \"Desfazer otimização\" (ou clique com o botão direito em desfazer.cmd > Executar como administrador).\r\n" +
                    "Também existe um ponto de restauração do Windows criado no mesmo momento (Painel de Controle > Recuperação > Abrir Restauração do Sistema).\r\n" +
                    "Não voltam com o backup: arquivos temporários apagados e reparos do DISM/SFC (eles não precisam voltar).\r\n", new UTF8Encoding(true));
                log.Linha("Backup das configurações salvo em " + pasta);
                return pasta;
            }
            catch (Exception ex) { log.Linha("Falha ao salvar o backup das configurações: " + ex.Message); return null; }
        }

        /// <summary>Modo interativo para restaurar um backup.</summary>
        public static void Desfazer(bool simular)
        {
            Console2.Cor(ConsoleColor.Cyan, "\n  DESFAZER OTIMIZAÇÃO (restaurar backup)" + (simular ? "  —  SIMULAÇÃO" : ""));
            if (!simular && !Console2.EhAdmin())
            {
                Console.WriteLine("  Restaurar exige administrador (o Windows vai mostrar o aviso do UAC).");
                if (Console2.Confirmar("Abrir como administrador?")) Console2.ReabrirComoAdmin("--desfazer");
                return;
            }
            var lista = Directory.Exists(PastaBackups)
                ? new DirectoryInfo(PastaBackups).GetDirectories().Where(d => File.Exists(Path.Combine(d.FullName, "backup.txt"))).OrderByDescending(d => d.Name).ToList()
                : new List<DirectoryInfo>();
            if (lista.Count == 0)
            {
                Console2.Cor(ConsoleColor.Yellow, "  Nenhum backup encontrado. Você ainda pode usar a Restauração do Sistema (Painel de Controle > Recuperação).");
                return;
            }
            Console.WriteLine("  Backups salvos (o mais recente primeiro):");
            for (int i = 0; i < lista.Count; i++)
            {
                DateTime dt;
                string nome = DateTime.TryParseExact(lista[i].Name, "yyyy-MM-dd_HH-mm-ss", null, System.Globalization.DateTimeStyles.None, out dt) ? F.Data(dt) : lista[i].Name;
                Console.WriteLine("   [" + (i + 1) + "] " + nome);
            }
            int k;
            if (!int.TryParse(Console2.Ler("  Qual backup restaurar? (Enter para cancelar): "), out k) || k < 1 || k > lista.Count) { Console.WriteLine("  Cancelado."); return; }
            var pasta = lista[k - 1].FullName;
            Console.WriteLine("  Isso volta: efeitos visuais, transparência, Modo de Jogo/Game DVR, programas na inicialização, UAC e plano de energia.");
            if (!Console2.Confirmar("Restaurar este backup agora?")) { Console.WriteLine("  Cancelado."); return; }

            var log = new LogMelhorias(simular);
            log.Linha("=== Desfazer otimização: restaurando " + pasta + " ===");
            int falhas = 0;
            foreach (var linha in File.ReadAllLines(pasta + "\\backup.txt"))
            {
                var p = linha.Split('\t');
                if (p.Length < 2) continue;
                if (simular) { log.Linha("Executaria: " + linha.Replace('\t', ' ')); continue; }
                int c = 0;
                switch (p[0])
                {
                    case "SUBSTITUIR": Reg_("delete \"" + p[1] + "\" /f"); c = Reg_("import \"" + Path.Combine(pasta, p[2]) + "\""); break;
                    case "IMPORTAR": c = Reg_("import \"" + Path.Combine(pasta, p[2]) + "\""); break;
                    case "AUSENTE": Reg_("delete \"" + p[1] + "\" /f"); break;
                    case "APAGARVALOR": Reg_("delete \"" + p[1] + "\" /v " + p[2] + " /f"); break;
                    case "PLANO": c = Console2.RodarSilencioso("powercfg", "/setactive " + p[1]); break;
                }
                if (c != 0) falhas++;
                log.Linha((c == 0 ? "OK: " : "FALHOU (código " + c + "): ") + linha.Replace('\t', ' '));
            }
            log.Linha("Restauração concluída" + (falhas > 0 ? " com " + falhas + " falha(s)." : "."));
            Console2.Cor(ConsoleColor.Green, "\n  Configurações restauradas. Saia e entre na conta (ou reinicie) para os efeitos visuais voltarem por completo.");
            Console.WriteLine("  Se quiser voltar TUDO (inclusive arquivos de sistema), use a Restauração do Sistema com o ponto \"PCDiagnostico - antes das melhorias\".");
            Reinicio.Perguntar(simular, new[] { "Aplicar por completo as configurações restauradas" });
        }
    }
}
