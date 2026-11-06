using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using Microsoft.Win32;

namespace PcDiagnostico
{
    enum StatusCorrecao { Corrigido, Falhou, AcaoManual }

    class AcaoCorrecao
    {
        public string Titulo, Detalhe;
        public Func<LogMelhorias, Tuple<StatusCorrecao, string>> Executar;
    }

    /// <summary>
    /// Correção automática: aplica de uma vez apenas correções SEGURAS e reversíveis,
    /// com uma confirmação única, ponto de restauração antes, log e resumo final.
    /// Fica de fora: desinstalar apps, drivers/BIOS, remoção de ameaças além do Defender
    /// e qualquer coisa que apague arquivos do usuário (inclusive a Lixeira).
    /// </summary>
    static class Correcao
    {
        // Itens pesados que NÃO são desativados automaticamente (sincronização de arquivos, segurança e antitrapaça)
        static readonly string[] NaoDesativar = { "onedrive", "dropbox", "google drive", "googledrive", "icloud", "mcafee", "norton", "avast", "avg", "vanguard", "vgtray", "faceit", "easyanticheat", "battleye" };

        static Tuple<StatusCorrecao, string> R(StatusCorrecao s, string m) { return Tuple.Create(s, m); }

        static ManagementBaseObject StatusDefender()
        {
            try { return W.QS(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus").FirstOrDefault(); } catch { return null; }
        }

        static List<string> AntivirusAtivos(bool somenteTerceiros)
        {
            var l = new List<string>();
            try
            {
                foreach (var o in W.QS(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
                {
                    string n = W.S(o, "displayName") ?? "";
                    if (((W.L(o, "productState") >> 12) & 0xF) != 1) continue;
                    if (somenteTerceiros && n.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    l.Add(n);
                }
            }
            catch { }
            return l;
        }

        static List<string> FirewallDesligado()
        {
            var l = new List<string>();
            try
            {
                foreach (var o in W.QS(@"root\StandardCimv2", "SELECT Name, Enabled FROM MSFT_NetFirewallProfile"))
                    if (W.L(o, "Enabled") == 0) l.Add(W.S(o, "Name"));
            }
            catch { }
            if (l.Count > 0)
            {
                try
                {
                    bool terceiro = W.QS(@"root\SecurityCenter2", "SELECT productState FROM FirewallProduct").Any(o => ((W.L(o, "productState") >> 12) & 0xF) == 1);
                    if (terceiro) l.Clear();
                }
                catch { }
            }
            return l;
        }

        public static List<AcaoCorrecao> Montar(out List<string> foraDoAutomatico, bool maximo = false)
        {
            var l = new List<AcaoCorrecao>();
            foraDoAutomatico = new List<string>();
            string winTemp = Path.Combine(Melhorias.WinDir, "Temp");

            l.Add(new AcaoCorrecao
            {
                Titulo = "Limpar arquivos temporários",
                Detalhe = "Apaga arquivos com mais de 24 h de %TEMP% e " + winTemp + " (não toca em Documentos, Downloads, Área de Trabalho nem na Lixeira).",
                Executar = log => R(Melhorias.LimparPasta(Path.GetTempPath(), log) & Melhorias.LimparPasta(winTemp, log) ? StatusCorrecao.Corrigido : StatusCorrecao.Falhou, log.Simulacao ? "(simulação)" : "Temporários limpos.")
            });

            int n; long wu = Melhorias.TamanhoAntigo(Path.Combine(Melhorias.WinDir, @"SoftwareDistribution\Download"), out n);
            if (wu > 50L << 20 || wu == 0)
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Limpar cache do Windows Update",
                    Detalhe = "Para os serviços Windows Update/BITS, apaga instaladores já baixados e reinicia os serviços.",
                    Executar = log => Melhorias.LimparCacheWu(log) ? R(StatusCorrecao.Corrigido, "Cache limpo.") : R(StatusCorrecao.Falhou, "Veja o log.")
                });

            l.Add(new AcaoCorrecao
            {
                Titulo = "Reparar o Windows (DISM /RestoreHealth + sfc /scannow)",
                Detalhe = "Verifica e repara a imagem e os arquivos do sistema. Pode levar de 10 a 40 minutos e precisa de internet.",
                Executar = log =>
                {
                    int d = Console2.Rodar("DISM.exe", "/Online /Cleanup-Image /RestoreHealth");
                    log.Linha("DISM /RestoreHealth: código " + d + ".");
                    int s = Console2.Rodar(Path.Combine(Environment.SystemDirectory, "sfc.exe"), "/scannow");
                    log.Linha("sfc /scannow: código " + s + ".");
                    if (d != 0) return R(StatusCorrecao.Falhou, "DISM falhou (código " + d + "). Verifique a internet e tente de novo; veja C:\\Windows\\Logs\\DISM\\dism.log.");
                    if (s != 0) return R(StatusCorrecao.AcaoManual, "O SFC relatou problemas (código " + s + "). Reinicie e rode \"sfc /scannow\" de novo; detalhes em C:\\Windows\\Logs\\CBS\\CBS.log.");
                    return R(StatusCorrecao.Corrigido, "Imagem e arquivos do sistema verificados.");
                }
            });

            if (Melhorias.TrimDesligado() && Melhorias.TemSsd())
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Ativar o TRIM do SSD",
                    Detalhe = "fsutil behavior set DisableDeleteNotify 0",
                    Executar = log => { int c = Console2.Rodar("fsutil", "behavior set DisableDeleteNotify 0"); log.Linha("TRIM: código " + c + ". Para voltar: fsutil behavior set DisableDeleteNotify 1"); return c == 0 ? R(StatusCorrecao.Corrigido, "TRIM ativado.") : R(StatusCorrecao.Falhou, "fsutil código " + c + "."); }
                });

            l.Add(new AcaoCorrecao
            {
                Titulo = "Otimizar as unidades",
                Detalhe = "defrag /C /O — TRIM em SSDs e desfragmentação em HDs (não apaga nada).",
                Executar = log => { int c = Console2.Rodar("defrag.exe", "/C /O /U"); log.Linha("defrag: código " + c + "."); return c == 0 ? R(StatusCorrecao.Corrigido, "Unidades otimizadas.") : R(StatusCorrecao.Falhou, "defrag código " + c + "."); }
            });

            var planos = Melhorias.ListarPlanos();
            var ativo = planos.FirstOrDefault(p => p.Item3);
            bool desktop = W.QS(W.Cimv2, "SELECT Name FROM Win32_Battery").Count == 0;
            const string GuidAlto = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", GuidMaximo = "e9a42b02-d5df-448d-aa00-03f14749eb61";
            bool jaAlto = ativo != null && (ativo.Item1 == GuidAlto || ativo.Item1 == GuidMaximo || ativo.Item2.IndexOf("desempenho", StringComparison.OrdinalIgnoreCase) >= 0 || ativo.Item2.IndexOf("performance", StringComparison.OrdinalIgnoreCase) >= 0);
            if (maximo && desktop && !jaAlto)
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Plano de energia \"Alto desempenho\" (PC de mesa)",
                    Detalhe = "Mantém o processador sempre pronto. Para voltar: powercfg /setactive " + (ativo != null ? ativo.Item1 : "381b4222-f694-41f0-9685-ff5bb260df2e"),
                    Executar = log =>
                    {
                        if (!Melhorias.ListarPlanos().Any(p => p.Item1 == GuidAlto)) Console2.Rodar("powercfg", "-duplicatescheme " + GuidAlto);
                        string alvo = Melhorias.ListarPlanos().Where(p => p.Item1 == GuidAlto || p.Item2.IndexOf("Alto desempenho", StringComparison.OrdinalIgnoreCase) >= 0 || p.Item2.IndexOf("High performance", StringComparison.OrdinalIgnoreCase) >= 0).Select(p => p.Item1).FirstOrDefault() ?? GuidAlto;
                        int c = Console2.Rodar("powercfg", "/setactive " + alvo);
                        log.Linha("Plano anterior: " + (ativo != null ? ativo.Item1 : "?") + ". Novo: " + alvo + ". Código " + c + ".");
                        return c == 0 ? R(StatusCorrecao.Corrigido, "Alto desempenho ativo.") : R(StatusCorrecao.Falhou, "powercfg código " + c + ".");
                    }
                });
            else if (ativo != null && (ativo.Item1.StartsWith("a1841308") || ativo.Item2.IndexOf("econom", StringComparison.OrdinalIgnoreCase) >= 0 || ativo.Item2.IndexOf("saver", StringComparison.OrdinalIgnoreCase) >= 0))
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Trocar plano de energia \"" + ativo.Item2 + "\" por \"Equilibrado\"",
                    Detalhe = "O modo economia limita o processador. Para voltar: powercfg /setactive " + ativo.Item1,
                    Executar = log => { int c = Console2.Rodar("powercfg", "/setactive 381b4222-f694-41f0-9685-ff5bb260df2e"); log.Linha("Plano anterior: " + ativo.Item1 + ". powercfg código " + c + "."); return c == 0 ? R(StatusCorrecao.Corrigido, "Plano Equilibrado ativo.") : R(StatusCorrecao.Falhou, "powercfg código " + c + "."); }
                });

            var pesados = ItemInicializacao.Listar().Where(x => x.Ativo && x.Pesado).ToList();
            var desativar = pesados.Where(x => !NaoDesativar.Any(k => (x.Nome + " " + x.Comando).ToLowerInvariant().Contains(k))).ToList();
            foreach (var x in pesados.Except(desativar)) foraDoAutomatico.Add("Inicialização de \"" + x.Nome + "\" (sincronização, segurança ou antitrapaça) — decida no modo de melhorias");
            if (desativar.Count > 0)
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Desativar " + desativar.Count + " programa(s) pesado(s) na inicialização",
                    Detalhe = string.Join(", ", desativar.Select(x => x.Nome)) + ". Não desinstala; reative em Configurações > Aplicativos > Inicialização.",
                    Executar = log => Melhorias.DesativarInicializacao(desativar, log) ? R(StatusCorrecao.Corrigido, "Desativados: " + string.Join(", ", desativar.Select(x => x.Nome)) + ".") : R(StatusCorrecao.Falhou, "Alguns não puderam ser desativados; veja o log.")
                });

            var st = StatusDefender();
            var terceiros = AntivirusAtivos(true);
            string mp = Melhorias.MpCmdRun();
            bool defenderEmUso = st != null && terceiros.Count == 0;
            if (defenderEmUso && !W.B(st, "RealTimeProtectionEnabled"))
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Religar a proteção em tempo real do Defender",
                    Detalhe = "Set-MpPreference -DisableRealtimeMonitoring $false",
                    Executar = log =>
                    {
                        int c = Console2.Rodar("powershell.exe", "-NoProfile -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\"");
                        var s2 = StatusDefender();
                        bool ok = s2 != null && W.B(s2, "RealTimeProtectionEnabled");
                        log.Linha("Proteção em tempo real: " + (ok ? "ligada" : "continua desligada") + " (código " + c + ").");
                        return ok ? R(StatusCorrecao.Corrigido, "Proteção em tempo real ligada.") : R(StatusCorrecao.AcaoManual, "Bloqueado por política ou pela Proteção contra adulteração. Ligue em Segurança do Windows > Proteção contra vírus e ameaças.");
                    }
                });
            if (defenderEmUso && mp != null)
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Atualizar as assinaturas do Defender e rodar a verificação rápida",
                    Detalhe = "MpCmdRun -SignatureUpdate e MpCmdRun -Scan -ScanType 1. Ameaças encontradas são tratadas pelo próprio Defender.",
                    Executar = log =>
                    {
                        int u = Console2.Rodar(mp, "-SignatureUpdate");
                        log.Linha("Atualização de assinaturas: código " + u + ".");
                        int s = Console2.Rodar(mp, "-Scan -ScanType 1");
                        log.Linha("Verificação rápida: código " + s + ".");
                        if (s == 2) return R(StatusCorrecao.AcaoManual, "AMEAÇAS ENCONTRADAS. Abra Segurança do Windows > Proteção contra vírus e ameaças e confira o que foi feito.");
                        if (s != 0) return R(StatusCorrecao.Falhou, "Verificação terminou com código " + s + ".");
                        return R(u == 0 ? StatusCorrecao.Corrigido : StatusCorrecao.AcaoManual, u == 0 ? "Assinaturas atualizadas; nenhuma ameaça encontrada." : "Nenhuma ameaça, mas a atualização de assinaturas falhou (código " + u + "): atualize pelo Windows Update.");
                    }
                });
            else if (terceiros.Count > 0)
                foraDoAutomatico.Add("Verificação de vírus: o antivírus ativo é " + string.Join(", ", terceiros) + " — rode a verificação por ele");

            var fw = FirewallDesligado();
            if (fw.Count > 0)
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Religar o Firewall do Windows (" + string.Join(", ", fw) + ")",
                    Detalhe = "netsh advfirewall set allprofiles state on",
                    Executar = log => { int c = Console2.Rodar("netsh", "advfirewall set allprofiles state on"); log.Linha("Firewall: código " + c + ". Perfis antes desligados: " + string.Join(", ", fw)); return c == 0 ? R(StatusCorrecao.Corrigido, "Firewall ligado em todos os perfis.") : R(StatusCorrecao.Falhou, "netsh código " + c + "."); }
                });

            const string polUac = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            int? lua = Reg.Int(RegistryHive.LocalMachine, polUac, "EnableLUA");
            int? consent = Reg.Int(RegistryHive.LocalMachine, polUac, "ConsentPromptBehaviorAdmin");
            if ((lua.HasValue && lua.Value == 0) || (consent.HasValue && consent.Value == 0))
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Religar o Controle de Conta de Usuário (UAC)",
                    Detalhe = "EnableLUA = 1 e ConsentPromptBehaviorAdmin = 5 (padrão do Windows). Exige reiniciar.",
                    Executar = log =>
                    {
                        if (log.Simulacao) return R(StatusCorrecao.Corrigido, "(simulação)");
                        using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                        using (var k = b.CreateSubKey(polUac))
                        {
                            k.SetValue("EnableLUA", 1, RegistryValueKind.DWord);
                            k.SetValue("ConsentPromptBehaviorAdmin", 5, RegistryValueKind.DWord);
                        }
                        log.Linha("UAC: EnableLUA " + lua + " -> 1, ConsentPromptBehaviorAdmin " + consent + " -> 5.");
                        return R(StatusCorrecao.AcaoManual, "UAC religado; reinicie o PC para valer.");
                    }
                });

            if (Melhorias.Smb1Ativo())
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Desativar o SMBv1",
                    Detalhe = "DISM /Online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart",
                    Executar = log =>
                    {
                        int c = Console2.Rodar("DISM.exe", "/Online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart");
                        log.Linha("SMBv1: código " + c + ". Para voltar: DISM /Online /Enable-Feature /FeatureName:SMB1Protocol");
                        return c == 3010 ? R(StatusCorrecao.AcaoManual, "SMBv1 desativado; reinicie o PC para concluir.") : c == 0 ? R(StatusCorrecao.Corrigido, "SMBv1 desativado.") : R(StatusCorrecao.Falhou, "DISM código " + c + ".");
                    }
                });

            if (maximo)
            {
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Ajustar efeitos visuais para desempenho",
                    Detalhe = "Desliga animações, sombras, fades e transparência (a suavização de fontes continua). Para voltar: SystemPropertiesPerformance.exe.",
                    Executar = log => Melhorias.AjustarEfeitos(log) ? R(StatusCorrecao.Corrigido, "Efeitos visuais ajustados (alguns valem após sair e entrar na conta).") : R(StatusCorrecao.Falhou, "Veja o log.")
                });
                l.Add(new AcaoCorrecao
                {
                    Titulo = "Ligar o Modo de Jogo e desligar a gravação em segundo plano do Xbox",
                    Detalhe = "O Modo de Jogo prioriza o jogo aberto; a gravação em segundo plano (Game DVR) custa FPS. Valores antigos ficam no log.",
                    Executar = log =>
                    {
                        object gm = Reg.Valor(RegistryHive.CurrentUser, @"Software\Microsoft\GameBar", "AutoGameModeEnabled");
                        object dvr = Reg.Valor(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_Enabled");
                        object cap = Reg.Valor(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled");
                        log.Linha("Antes: AutoGameModeEnabled=" + (gm ?? "(padrão)") + ", GameDVR_Enabled=" + (dvr ?? "(padrão)") + ", AppCaptureEnabled=" + (cap ?? "(padrão)") + ".");
                        if (!log.Simulacao)
                        {
                            using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\GameBar")) k.SetValue("AutoGameModeEnabled", 1, RegistryValueKind.DWord);
                            using (var k = Registry.CurrentUser.CreateSubKey(@"System\GameConfigStore")) k.SetValue("GameDVR_Enabled", 0, RegistryValueKind.DWord);
                            using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\GameDVR")) k.SetValue("AppCaptureEnabled", 0, RegistryValueKind.DWord);
                        }
                        return R(StatusCorrecao.Corrigido, "Modo de Jogo ligado; gravação em segundo plano do Xbox desligada (o ReLive/ShadowPlay da placa de vídeo não é afetado).");
                    }
                });
                foraDoAutomatico.Add("Ativar o XMP/EXPO da memória na BIOS (passo a passo na seção de peças)");
            }

            foraDoAutomatico.Add("Esvaziar a Lixeira, apagar arquivos grandes/duplicados ou desinstalar aplicativos (use a opção [8] Desinstalar aplicativos)");
            foraDoAutomatico.Add("Atualizar drivers ou BIOS (veja as recomendações do relatório)");
            foraDoAutomatico.Add("Remover ameaças além do que o Defender faz e revisar itens \"suspeitos\"");
            foraDoAutomatico.Add("Upgrade de peças (apenas recomendação)");
            return l;
        }

        public static void Executar(bool simular, bool maximo = false)
        {
            Console2.Cor(ConsoleColor.Cyan, "\n  " + (maximo ? "OTIMIZAÇÃO MÁXIMA" : "CORREÇÃO AUTOMÁTICA") + (simular ? "  —  SIMULAÇÃO (nada será alterado)" : ""));
            if (maximo) Console.WriteLine("  Tudo da correção automática + Alto desempenho, efeitos visuais, Modo de Jogo e Game DVR desligado.");
            Console.WriteLine("  Aplica de uma vez apenas correções seguras e reversíveis. Antes de qualquer mudança é criado");
            Console.WriteLine("  um ponto de restauração; tudo fica registrado em log.\n");

            if (!simular && !Console2.EhAdmin())
            {
                Console.WriteLine("  A correção automática precisa de administrador (o Windows vai mostrar o aviso do UAC).");
                if (Console2.Confirmar("Abrir como administrador?")) Console2.ReabrirComoAdmin(maximo ? "--otimizar" : "--corrigir");
                return;
            }

            Console.WriteLine("  Verificando o que precisa ser corrigido...");
            List<string> fora;
            var acoes = Montar(out fora, maximo);
            Console.WriteLine("\n  Será feito, nesta ordem:");
            for (int i = 0; i < acoes.Count; i++)
            {
                Console2.Cor(ConsoleColor.White, "   " + (i + 1) + ". " + acoes[i].Titulo);
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("      " + acoes[i].Detalhe);
                Console.ResetColor();
            }
            Console.WriteLine("\n  NÃO será feito automaticamente:");
            foreach (var f in fora) Console.WriteLine("   - " + f);
            Console.WriteLine("\n  Tempo estimado: 15 a 60 minutos (DISM/SFC e a verificação do Defender são os mais demorados).");
            if (!Console2.Confirmar("Criar ponto de restauração e aplicar TODAS as correções acima?")) { Console.WriteLine("  Cancelado. Nada foi alterado."); return; }

            var log = new LogMelhorias(simular);
            log.Linha("=== " + (maximo ? "Otimização máxima" : "Correção automática") + " (" + Environment.UserName + "@" + Environment.MachineName + ") ===");
            Backup.Criar(log);
            if (!Melhorias.CriarPontoRestauracao(log))
            {
                Console2.Cor(ConsoleColor.Yellow, "  Não foi possível criar o ponto de restauração.");
                if (!Console2.Confirmar("Continuar SEM ponto de restauração? (não recomendado)")) { log.Linha("Cancelado: sem ponto de restauração."); return; }
                log.Linha("Usuário optou por continuar sem ponto de restauração.");
            }

            var resultados = new List<Tuple<AcaoCorrecao, StatusCorrecao, string>>();
            foreach (var a in acoes)
            {
                Console2.Cor(ConsoleColor.Cyan, "\n  > " + a.Titulo);
                Tuple<StatusCorrecao, string> r;
                if (simular && !a.Titulo.StartsWith("Limpar arquivos")) { log.Linha("Executaria: " + a.Detalhe); r = R(StatusCorrecao.Corrigido, "(simulação)"); }
                else
                {
                    try { r = a.Executar(log); }
                    catch (Exception ex) { r = R(StatusCorrecao.Falhou, ex.Message); }
                }
                log.Linha("[" + (r.Item1 == StatusCorrecao.Corrigido ? "CORRIGIDO" : r.Item1 == StatusCorrecao.Falhou ? "FALHOU" : "AÇÃO MANUAL") + "] " + a.Titulo + " — " + r.Item2);
                resultados.Add(Tuple.Create(a, r.Item1, r.Item2));
            }

            Console.WriteLine("\n  ─────────────────────── RESULTADO ───────────────────────");
            foreach (var st in new[] { StatusCorrecao.Corrigido, StatusCorrecao.AcaoManual, StatusCorrecao.Falhou })
            {
                var g = resultados.Where(x => x.Item2 == st).ToList();
                if (g.Count == 0) continue;
                var cor = st == StatusCorrecao.Corrigido ? ConsoleColor.Green : st == StatusCorrecao.Falhou ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console2.Cor(cor, "  " + (st == StatusCorrecao.Corrigido ? (simular ? "Seria corrigido (simulação)" : "Corrigido") : st == StatusCorrecao.Falhou ? "Falhou" : "Precisa de ação manual") + " (" + g.Count + "):");
                foreach (var x in g) Console.WriteLine("   - " + x.Item1.Titulo + (x.Item3.Length > 0 ? ": " + x.Item3 : ""));
            }
            Console2.Cor(ConsoleColor.Yellow, "  Precisa de ação manual (fora do automático):");
            foreach (var f in fora) Console.WriteLine("   - " + f);
            log.Linha("Resumo: " + resultados.Count(x => x.Item2 == StatusCorrecao.Corrigido) + " corrigidos, " + resultados.Count(x => x.Item2 == StatusCorrecao.Falhou) + " falharam, " + resultados.Count(x => x.Item2 == StatusCorrecao.AcaoManual) + " precisam de ação manual.");
            log.Linha("=== Fim da correção automática ===");
            Console2.Cor(ConsoleColor.Green, "\n  Log completo: " + log.Arquivo);
            Console.WriteLine("  Para desfazer: Painel de Controle > Recuperação > Abrir Restauração do Sistema.");
            Reinicio.Perguntar(simular, resultados.Where(x => x.Item3.IndexOf("reinicie", StringComparison.OrdinalIgnoreCase) >= 0).Select(x => x.Item1.Titulo + " (" + x.Item3 + ")"));
        }
    }
}
