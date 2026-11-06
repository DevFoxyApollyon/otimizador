using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace PcDiagnostico
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            Func<string, bool> tem = s => args.Any(a => a.Equals(s, StringComparison.OrdinalIgnoreCase));
            bool semPausa = tem("--sem-pausa");
            bool naoAbrir = tem("--nao-abrir");
            bool simular = tem("--simular");
            string pastaSaida = null;
            for (int i = 0; i < args.Length - 1; i++)
                if (args[i].Equals("--saida", StringComparison.OrdinalIgnoreCase)) pastaSaida = args[i + 1];

            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
            Thread.CurrentThread.CurrentCulture = F.BR;
            Thread.CurrentThread.CurrentUICulture = F.BR;
            try { Console.Title = "Diagnóstico do PC"; } catch { }

            if (tem("/?") || tem("-h") || tem("--ajuda"))
            {
                Console.WriteLine("Uso: PCDiagnostico.exe [opções]");
                Console.WriteLine("  (sem opções)          diagnóstico completo + menu de ações no final");
                Console.WriteLine("  --sem-pausa           só o diagnóstico, sem menu nem pausa no final");
                Console.WriteLine("  --nao-abrir           não abre o relatório no navegador");
                Console.WriteLine("  --saida <pasta>       pasta do relatório (padrão: Documentos\\Diagnóstico do PC)");
                Console.WriteLine("  --corrigir            correção automática das falhas seguras (confirmação única, pede administrador)");
                Console.WriteLine("  --otimizar            otimização máxima (correção automática + desempenho; pede administrador)");
                Console.WriteLine("  --desinstalar         desinstalar aplicativos escolhidos (pede administrador)");
                Console.WriteLine("  --travando            mede agora o que está travando o PC e se ele precisa reiniciar");
                Console.WriteLine("  --melhorias           abre direto o modo de melhorias (pede administrador)");
                Console.WriteLine("  --verificacao-rapida  roda a verificação rápida do Microsoft Defender (após confirmar)");
                Console.WriteLine("  --relatorio-energia   gera o relatório powercfg /energy (administrador)");
                Console.WriteLine("  --simular             nos modos de melhorias/correção, só mostra o que seria feito");
                return 0;
            }

            if (tem("--corrigir")) { Correcao.Executar(simular); Pausa(semPausa); return 0; }
            if (tem("--otimizar")) { Correcao.Executar(simular, true); Pausa(semPausa); return 0; }
            if (tem("--desfazer")) { Backup.Desfazer(simular); Pausa(semPausa); return 0; }
            if (tem("--desinstalar")) { Desinstalador.Executar(simular); Pausa(semPausa); return 0; }
            if (tem("--travando")) { Travamento.Imprimir(Travamento.Medir(5)); Reinicio.Perguntar(simular); Pausa(semPausa); return 0; }
            if (tem("--melhorias")) { Melhorias.ModoInterativo(simular); Pausa(semPausa); return 0; }
            if (tem("--verificacao-rapida")) { Melhorias.VerificacaoRapida(simular); Pausa(semPausa); return 0; }
            if (tem("--relatorio-energia")) { Melhorias.RelatoriosWindows(true); Pausa(semPausa); return 0; }

            Console2.Cor(ConsoleColor.Cyan, "\n  DIAGNÓSTICO DO PC\n");
            Console.WriteLine("  O diagnóstico só lê informações: nada no seu sistema será alterado.\n");

            var d = new Diagnostico();
            d.Executar((i, total, nome) =>
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("  [" + i.ToString().PadLeft(2) + "/" + total + "] ");
                Console.ResetColor();
                Console.WriteLine(nome + "...");
            });
            try { d.MelhoriasDisponiveis = Melhorias.Detectar().Where(m => m.Disponivel).ToList(); } catch { }

            string arquivo = null;
            try
            {
                string pasta = pastaSaida ?? Console2.PastaRelatorios();
                Directory.CreateDirectory(pasta);
                arquivo = Path.Combine(pasta, "diagnostico-" + DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss", CultureInfo.InvariantCulture) + ".html");
                File.WriteAllText(arquivo, Relatorio.Gerar(d), new UTF8Encoding(true));
            }
            catch (Exception ex)
            {
                Console2.Cor(ConsoleColor.Red, "\n  Não foi possível salvar o relatório: " + ex.Message);
                arquivo = null;
            }

            int nc = d.Achados.Count(a => a.Gravidade == Gravidade.Critico);
            int na = d.Achados.Count(a => a.Gravidade == Gravidade.Aviso);
            int ni = d.Achados.Count(a => a.Gravidade == Gravidade.Info);
            int no = d.Achados.Count(a => a.Gravidade == Gravidade.Ok);

            Console.WriteLine();
            Console.WriteLine("  ─────────────────────────── RESUMO ───────────────────────────");
            Console2.Cor(ConsoleColor.Red, "    Críticos:     " + nc);
            Console2.Cor(ConsoleColor.Yellow, "    Avisos:       " + na);
            Console2.Cor(ConsoleColor.Cyan, "    Informações:  " + ni);
            Console2.Cor(ConsoleColor.Green, "    Tudo OK:      " + no);
            int remover = d.Apps.Count(a => a.Recomendacao == Recomendacao.Remover), opc = d.Apps.Count(a => a.Recomendacao == Recomendacao.Opcional);
            Console.WriteLine("    Aplicativos:  " + d.Apps.Count + " analisados, " + remover + " recomendados para remover, " + opc + " opcionais");
            Console.WriteLine();

            foreach (var a in d.Achados.Where(x => x.Gravidade <= Gravidade.Aviso).OrderBy(x => x.Gravidade))
            {
                Console.ForegroundColor = a.Gravidade == Gravidade.Critico ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write(a.Gravidade == Gravidade.Critico ? "  [CRÍTICO] " : "  [AVISO]   ");
                Console.ResetColor();
                Console.WriteLine((a.Suspeito ? "(suspeito) " : "") + a.Titulo);
            }
            if (nc + na == 0) Console2.Cor(ConsoleColor.Green, "  Nenhum problema crítico ou aviso encontrado.");

            if (d.Travamento != null) Travamento.Imprimir(d.Travamento);
            Console.WriteLine();
            if (d.MotivosReinicio.Count > 0)
            {
                Console2.Cor(ConsoleColor.Yellow, "  >>> O PC PRECISA REINICIAR:");
                foreach (var m in d.MotivosReinicio) Console.WriteLine("      - " + m);
            }
            else Console2.Cor(ConsoleColor.Green, "  >>> O PC não precisa reiniciar agora.");

            MostrarPassoAPasso(d);
            MostrarPecas(d);

            if (!d.Admin && d.TestesSemPermissao.Count > 0)
            {
                Console.WriteLine();
                Console2.Cor(ConsoleColor.DarkYellow, "  Obs.: " + d.TestesSemPermissao.Count + " verificação(ões) exigem administrador e foram puladas.");
                Console2.Cor(ConsoleColor.DarkYellow, "  Para o diagnóstico completo, use \"Executar como administrador\".");
            }

            if (arquivo != null)
            {
                Console.WriteLine();
                Console.WriteLine("  Relatório completo, com as soluções sugeridas:");
                Console2.Cor(ConsoleColor.White, "  " + arquivo);
                if (!naoAbrir) Abrir(arquivo);
            }

            if (!semPausa) Menu(arquivo, d, simular);
            return nc > 0 ? 2 : na > 0 ? 1 : 0;
        }

        static void Abrir(string arquivo)
        {
            try { Process.Start(new ProcessStartInfo(arquivo) { UseShellExecute = true }); }
            catch (Exception ex) { Console2.Cor(ConsoleColor.Red, "  Não foi possível abrir o navegador: " + ex.Message); }
        }

        static void Menu(string arquivo, Diagnostico d, bool simular)
        {
            while (true)
            {
                Console.WriteLine();
                Console2.Cor(ConsoleColor.Cyan, "  O que deseja fazer agora?");
                Console.WriteLine("   [1] Abrir o relatório novamente");
                Console.WriteLine("   [2] Aplicar melhorias (" + d.MelhoriasDisponiveis.Count + " disponíveis — você escolhe e confirma cada uma)");
                Console.WriteLine("   [3] Rodar verificação rápida do Microsoft Defender");
                Console.WriteLine("   [4] Gerar relatório de bateria / energia do Windows");
                Console.WriteLine("   [5] Corrigir automaticamente (todas as correções seguras, com uma confirmação)");
                Console.WriteLine("   [6] Ver peças para trocar ou melhorar (upgrade)");
                Console.WriteLine("   [7] Ver o passo a passo para corrigir cada problema");
                Console.WriteLine("   [8] Desinstalar aplicativos (" + d.Apps.Count(a => a.Recomendacao != Recomendacao.Manter) + " sugeridos — você escolhe cada um)");
                Console2.Cor(ConsoleColor.Green, "   [9] OTIMIZAÇÃO MÁXIMA (a melhor otimização possível, com uma confirmação)");
                Console.WriteLine("   [10] O que está travando o PC agora (medir de novo)");
                Console.WriteLine("   [11] Reiniciar o PC por completo" + (d.MotivosReinicio.Count > 0 ? " (recomendado)" : ""));
                Console.WriteLine("   [12] Desfazer otimização (restaurar o backup salvo antes)");
                Console.WriteLine("   [13] Desligar o PC por completo (sem Inicialização Rápida)");
                Console.WriteLine("   [0] Sair");
                string r = Console2.Ler("  Opção: ");
                if (r == null || r == "0" || r == "") return;
                if (r == "1" && arquivo != null) Abrir(arquivo);
                else if (r == "2") Melhorias.ModoInterativo(simular);
                else if (r == "3") Melhorias.VerificacaoRapida(simular);
                else if (r == "4") Melhorias.RelatoriosWindows(false);
                else if (r == "5") Correcao.Executar(simular);
                else if (r == "6") MostrarPecas(d);
                else if (r == "7") MostrarPassoAPasso(d);
                else if (r == "8") Desinstalador.Executar(simular);
                else if (r == "9") Correcao.Executar(simular, true);
                else if (r == "10") { Console.WriteLine("  Medindo por 5 segundos..."); Travamento.Imprimir(Travamento.Medir(5)); }
                else if (r == "11") { if (Console2.Confirmar("Reiniciar POR COMPLETO agora? (salve seus arquivos; reinicia em 30 segundos)")) Reinicio.ReiniciarCompleto(simular); }
                else if (r == "12") Backup.Desfazer(simular);
                else if (r == "13") Reinicio.DesligarCompleto(simular);
            }
        }

        /// <summary>Mostra, para cada problema crítico ou aviso, o passo a passo para corrigir.</summary>
        static void MostrarPassoAPasso(Diagnostico d)
        {
            var itens = d.Achados.Where(a => a.Gravidade <= Gravidade.Aviso && a.Impacto == null && (!string.IsNullOrEmpty(a.Solucao) || a.Comandos.Count > 0))
                .OrderBy(a => a.Gravidade).ToList();
            Console.WriteLine();
            Console.WriteLine("  ─────────────── COMO CORRIGIR CADA PROBLEMA (PASSO A PASSO) ───────────────");
            if (itens.Count == 0) { Console2.Cor(ConsoleColor.Green, "  Nenhum problema crítico ou aviso para corrigir."); return; }
            int n = 0;
            foreach (var a in itens)
            {
                n++;
                Console.ForegroundColor = a.Gravidade == Gravidade.Critico ? ConsoleColor.Red : ConsoleColor.Yellow;
                Console.Write("\n  " + n + ") " + (a.Gravidade == Gravidade.Critico ? "[CRÍTICO] " : "[AVISO] ") + (a.Suspeito ? "(suspeito) " : ""));
                Console.ResetColor();
                Console2.Cor(ConsoleColor.White, a.Titulo);
                if (!string.IsNullOrEmpty(a.Descricao)) Console2.Cor(ConsoleColor.Gray, "     O problema: " + a.Descricao);
                var passos = Passos.De(a.Solucao);
                for (int i = 0; i < passos.Count; i++) Console.WriteLine("     Passo " + (i + 1) + ": " + passos[i]);
                foreach (var c in a.Comandos) Console2.Cor(ConsoleColor.Cyan, "     Comando: " + c);
            }
            Console2.Cor(ConsoleColor.DarkGray, "\n  O mesmo passo a passo está no relatório HTML. Para corrigir automaticamente o que for seguro, use a opção [5].");
        }

        static int OrdemImpacto(string i) { return i == "alto" ? 0 : i == "médio" ? 1 : 2; }

        /// <summary>Mostra no console as peças que vale trocar ou melhorar.</summary>
        static void MostrarPecas(Diagnostico d)
        {
            Console.WriteLine();
            Console.WriteLine("  ──────────────── PEÇAS: O QUE TROCAR OU MELHORAR ────────────────");
            var hw = d.Achados.Where(a => a.Categoria == Cat.Upgrade && a.Impacto == null && a.Gravidade == Gravidade.Info).ToList();
            foreach (var a in hw)
            {
                Console2.Cor(ConsoleColor.Gray, "  " + a.Titulo);
                foreach (var x in a.Detalhes.Where(x => x.StartsWith("Se um dia") || x.StartsWith("Não é gargalo")))
                    Console2.Cor(ConsoleColor.DarkGray, "      " + x);
            }
            var recs = d.Achados.Where(a => a.Impacto != null).OrderBy(a => OrdemImpacto(a.Impacto)).ToList();
            if (recs.Count == 0)
            {
                Console2.Cor(ConsoleColor.Green, "\n  Nenhuma peça precisa ser trocada agora: o hardware atende bem ao uso detectado.");
                return;
            }
            Console.WriteLine();
            foreach (var a in recs)
            {
                var cor = a.Impacto == "alto" ? ConsoleColor.Red : a.Impacto == "médio" ? ConsoleColor.Yellow : ConsoleColor.Cyan;
                Console.ForegroundColor = cor;
                Console.Write("  [IMPACTO " + a.Impacto.ToUpperInvariant() + "] ");
                Console.ResetColor();
                Console2.Cor(ConsoleColor.White, a.Titulo);
                Console.WriteLine("      Por quê: " + a.Descricao);
                var passos = Passos.De(a.Solucao);
                if (passos.Count > 0)
                {
                    Console.WriteLine("      Passo a passo:");
                    for (int i = 0; i < passos.Count; i++) Console.WriteLine("        " + (i + 1) + ". " + passos[i]);
                }
                foreach (var p in a.Detalhes.Where(x => x.StartsWith(Diagnostico.PrefixoCompra))) Console2.Cor(ConsoleColor.Green, "      " + p);
                foreach (var p in a.Detalhes.Where(x => x.StartsWith("Preço"))) Console2.Cor(ConsoleColor.DarkGray, "      " + p);
                Console.WriteLine();
            }
            Console2.Cor(ConsoleColor.DarkGray, "  Preços são estimativas. Confirme a compatibilidade no manual da placa-mãe antes de comprar.");
        }

        static void Pausa(bool semPausa)
        {
            if (semPausa) return;
            Console.WriteLine("\n  Pressione Enter para sair...");
            try { Console.ReadLine(); } catch { }
        }
    }
}
