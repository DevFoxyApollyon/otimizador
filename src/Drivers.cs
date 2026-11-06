using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace PcDiagnostico
{
    /// <summary>
    /// Atualização de drivers pelo Windows Update (drivers testados e assinados pela Microsoft).
    /// Fica fora da correção automática: você escolhe e confirma cada driver, com ponto de restauração antes e log.
    /// Não baixa drivers de sites de terceiros.
    /// </summary>
    static class Drivers
    {
        class DriverWu
        {
            public dynamic Update;
            public string Titulo, Classe, Fabricante, Data;
        }

        static List<DriverWu> Buscar(out string erro)
        {
            var lista = new List<DriverWu>();
            string e = null;
            var t = new Thread(() =>
            {
                try
                {
                    dynamic sessao = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session"));
                    sessao.ClientApplicationID = "PC Diagnostico";
                    dynamic busca = sessao.CreateUpdateSearcher();
                    dynamic res = busca.Search("IsInstalled=0 and Type='Driver' and IsHidden=0");
                    int n = res.Updates.Count;
                    for (int i = 0; i < n; i++)
                    {
                        dynamic u = res.Updates.Item(i);
                        var d = new DriverWu { Update = u, Titulo = u.Title };
                        try { d.Classe = u.DriverClass; } catch { }
                        try { d.Fabricante = u.DriverManufacturer; } catch { }
                        try { d.Data = ((DateTime)u.DriverVerDate).ToString("dd/MM/yyyy"); } catch { }
                        lista.Add(d);
                    }
                }
                catch (Exception ex) { e = ex.Message; }
            });
            t.IsBackground = true;
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            if (!t.Join(TimeSpan.FromMinutes(4))) e = "a busca no Windows Update demorou mais de 4 minutos";
            erro = e;
            return lista;
        }

        static string ResultadoTexto(int c)
        {
            switch (c)
            {
                case 2: return "instalado";
                case 3: return "instalado com avisos";
                case 4: return "falhou";
                case 5: return "cancelado";
                default: return "código " + c;
            }
        }

        public static void Executar(bool simular)
        {
            Console2.Cor(ConsoleColor.Cyan, "\n  ATUALIZAR DRIVERS (Windows Update)" + (simular ? "  —  SIMULAÇÃO (nada será instalado)" : ""));
            Console.WriteLine("  Busca drivers novos no Windows Update. Você escolhe e confirma cada um.");
            Console.WriteLine("  Antes de instalar, é criado um ponto de restauração. Nada é baixado de sites de terceiros.\n");

            if (!simular && !Console2.EhAdmin())
            {
                Console.WriteLine("  Instalar drivers exige administrador (o Windows vai mostrar o aviso do UAC).");
                if (Console2.Confirmar("Abrir a atualização de drivers como administrador?")) Console2.ReabrirComoAdmin("--drivers");
                return;
            }

            Console.WriteLine("  Procurando drivers no Windows Update (pode levar alguns minutos)...");
            string erro;
            var lista = Buscar(out erro);
            if (erro != null)
            {
                Console2.Cor(ConsoleColor.Red, "  Não foi possível consultar o Windows Update: " + erro);
                Console.WriteLine("  Abra Configurações > Windows Update > Opções avançadas > Atualizações opcionais > Atualizações de driver.");
                return;
            }
            if (lista.Count == 0)
            {
                Console2.Cor(ConsoleColor.Green, "  Nenhum driver novo disponível no Windows Update.");
                Console.WriteLine("  Para a placa de vídeo, o driver mais recente costuma estar no site do fabricante:");
                Console.WriteLine("  NVIDIA (nvidia.com/drivers), AMD (amd.com/support) ou Intel (intel.com/iDSA).");
                return;
            }

            for (int i = 0; i < lista.Count; i++)
            {
                var d = lista[i];
                Console.Write("  [" + (i + 1).ToString().PadLeft(2) + "] ");
                Console2.Cor(ConsoleColor.White, d.Titulo);
                var info = new[] { d.Classe, d.Fabricante, d.Data != null ? "versão de " + d.Data : null }.Where(x => !string.IsNullOrEmpty(x));
                if (info.Any()) Console2.Cor(ConsoleColor.DarkGray, "       " + string.Join(" · ", info));
            }
            Console2.Cor(ConsoleColor.DarkGray, "\n  Dica: se um driver novo causar problema, use Gerenciador de Dispositivos > Propriedades > Driver > Reverter driver.");

            string r = Console2.Ler("\n  Digite os números para instalar (ex.: 1,3), T para todos, ou Enter para sair: ");
            if (string.IsNullOrEmpty(r)) { Console.WriteLine("  Nada foi instalado."); return; }
            List<int> idx = r.Equals("T", StringComparison.OrdinalIgnoreCase)
                ? Enumerable.Range(1, lista.Count).ToList()
                : r.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => { int k; return int.TryParse(x, out k) ? k : 0; }).Where(k => k >= 1 && k <= lista.Count).Distinct().ToList();

            var escolhidos = new List<DriverWu>();
            foreach (int k in idx)
                if (Console2.Confirmar("Instalar \"" + lista[k - 1].Titulo + "\"?")) escolhidos.Add(lista[k - 1]);
            if (escolhidos.Count == 0) { Console.WriteLine("\n  Nada foi instalado."); return; }
            if (!Console2.Confirmar("Criar ponto de restauração e instalar " + escolhidos.Count + " driver(s) agora?")) { Console.WriteLine("  Cancelado. Nada foi instalado."); return; }

            var log = new LogMelhorias(simular);
            log.Linha("=== Atualização de drivers (Windows Update) ===");
            if (simular)
            {
                foreach (var d in escolhidos) log.Linha("Instalaria: " + d.Titulo);
                Console2.Cor(ConsoleColor.Green, "\n  Log: " + log.Arquivo);
                return;
            }
            if (!Melhorias.CriarPontoRestauracao(log))
            {
                Console2.Cor(ConsoleColor.Yellow, "  Não foi possível criar o ponto de restauração.");
                if (!Console2.Confirmar("Continuar SEM ponto de restauração? (não recomendado)")) { log.Linha("Cancelado: sem ponto de restauração."); return; }
                log.Linha("Usuário optou por continuar sem ponto de restauração.");
            }

            int ok = 0, falha = 0; bool reiniciar = false;
            var t = new Thread(() =>
            {
                try
                {
                    dynamic sessao = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session"));
                    sessao.ClientApplicationID = "PC Diagnostico";
                    foreach (var d in escolhidos)
                    {
                        Console2.Cor(ConsoleColor.Cyan, "\n  > " + d.Titulo);
                        try
                        {
                            dynamic col = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.UpdateColl"));
                            col.Add(d.Update);
                            Console.WriteLine("    Baixando...");
                            dynamic down = sessao.CreateUpdateDownloader();
                            down.Updates = col;
                            down.Download();
                            Console.WriteLine("    Instalando...");
                            dynamic inst = sessao.CreateUpdateInstaller();
                            inst.Updates = col;
                            dynamic res = inst.Install();
                            int c = (int)res.ResultCode;
                            bool rb = false;
                            try { rb = (bool)res.RebootRequired; } catch { }
                            if (rb) reiniciar = true;
                            if (c == 2 || c == 3) ok++; else falha++;
                            log.Linha("[" + (c == 2 || c == 3 ? "INSTALADO" : "FALHOU") + "] " + d.Titulo + " — " + ResultadoTexto(c) + (rb ? " (exige reinicialização)" : "") + ".");
                        }
                        catch (Exception ex) { falha++; log.Linha("[FALHOU] " + d.Titulo + " — " + ex.Message); }
                    }
                }
                catch (Exception ex) { log.Linha("Erro no Windows Update: " + ex.Message); }
            });
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join();

            log.Linha("Resumo: " + ok + " instalados, " + falha + " falharam" + (reiniciar ? "; reinicie o PC para concluir." : "."));
            Console2.Cor(ConsoleColor.Green, "\n  Log: " + log.Arquivo);
            Reinicio.Perguntar(false, reiniciar ? new[] { "drivers instalados pelo Windows Update" } : null);
        }
    }
}
