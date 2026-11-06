using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.VisualBasic.FileIO;

namespace PcDiagnostico
{
    /// <summary>
    /// Depois de desinstalar, procura sobras do programa (pastas e chaves de registro com o nome exato dele)
    /// e remove só com confirmação. Pastas vão para a Lixeira; chaves de registro são exportadas para .reg antes.
    /// </summary>
    static class Sobras
    {
        class Item { public string Tipo, Caminho, App; public long Bytes; public RegistryKey Base; public string SubChave; }

        static string NomeLimpo(string n)
        {
            n = Regex.Replace(n ?? "", @"\s*\((x64|x86|64-bit|32-bit|64 bits|32 bits)\)", "", RegexOptions.IgnoreCase);
            n = Regex.Replace(n, @"\s+v?\d+(\.\d+)+.*$", "");
            return n.Trim();
        }

        static bool NomeSeguro(string n)
        {
            return n.Length >= 3 && n.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 &&
                !Regex.IsMatch(n, @"^(microsoft|windows|common files|intel|amd|nvidia|google|program files|system32)$", RegexOptions.IgnoreCase);
        }

        static long Tamanho(string pasta)
        {
            long t = 0;
            try { foreach (var f in Directory.EnumerateFiles(pasta, "*", System.IO.SearchOption.AllDirectories)) try { t += new FileInfo(f).Length; } catch { } } catch { }
            return t;
        }

        static bool PastaProtegida(string p)
        {
            string full = Path.GetFullPath(p).TrimEnd('\\');
            var proibidas = new[]
            {
                Path.GetPathRoot(full), Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Common Files"),
            }.Where(x => !string.IsNullOrEmpty(x)).Select(x => x.TrimEnd('\\'));
            if (proibidas.Any(x => string.Equals(x, full, StringComparison.OrdinalIgnoreCase))) return true;
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return full.StartsWith(win + "\\", StringComparison.OrdinalIgnoreCase);
        }

        static List<Item> Procurar(List<AppInstalado> removidos, List<AppInstalado> restantes)
        {
            var itens = new List<Item>();
            var pastasOutros = restantes.Select(x => x.PastaInstalacao).Where(x => !string.IsNullOrEmpty(x))
                .Select(x => { try { return Path.GetFullPath(x).TrimEnd('\\'); } catch { return null; } }).Where(x => x != null).ToList();
            var bases = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
            }.Where(x => !string.IsNullOrEmpty(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            foreach (var a in removidos)
            {
                string nome = NomeLimpo(a.Nome), editor = NomeLimpo(a.Editor);
                // Outra versão do mesmo programa continua instalada: as pastas e o registro ainda são dela.
                if (restantes.Any(o => string.Equals(NomeLimpo(o.Nome), nome, StringComparison.OrdinalIgnoreCase))) continue;
                var candidatos = new List<string>();
                if (!string.IsNullOrEmpty(a.PastaInstalacao)) candidatos.Add(a.PastaInstalacao);
                if (NomeSeguro(nome))
                    foreach (var b in bases)
                    {
                        candidatos.Add(Path.Combine(b, nome));
                        if (NomeSeguro(editor)) candidatos.Add(Path.Combine(b, editor, nome));
                    }
                foreach (var c in candidatos)
                {
                    string full;
                    try { full = Path.GetFullPath(c).TrimEnd('\\'); } catch { continue; }
                    if (!Directory.Exists(full) || PastaProtegida(full)) continue;
                    // Nunca apaga pasta usada por outro programa instalado (nem pasta que contenha a de outro).
                    if (pastasOutros.Any(o => string.Equals(o, full, StringComparison.OrdinalIgnoreCase) ||
                        o.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase) || full.StartsWith(o + "\\", StringComparison.OrdinalIgnoreCase))) continue;
                    if (itens.Any(i => string.Equals(i.Caminho, full, StringComparison.OrdinalIgnoreCase))) continue;
                    itens.Add(new Item { Tipo = "Pasta", Caminho = full, App = a.Nome, Bytes = Tamanho(full) });
                }

                if (!NomeSeguro(nome)) continue;
                var chaves = new List<string> { @"SOFTWARE\" + nome };
                if (NomeSeguro(editor)) chaves.Add(@"SOFTWARE\" + editor + @"\" + nome);
                foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
                    foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                        foreach (var sub in chaves)
                        {
                            try
                            {
                                var b = RegistryKey.OpenBaseKey(hive, view);
                                using (var k = b.OpenSubKey(sub))
                                {
                                    if (k == null) continue;
                                    string nomeExib = (hive == RegistryHive.CurrentUser ? "HKCU\\" : "HKLM\\") + (view == RegistryView.Registry32 && hive == RegistryHive.LocalMachine ? sub.Replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\") : sub);
                                    if (itens.Any(i => string.Equals(i.Caminho, nomeExib, StringComparison.OrdinalIgnoreCase))) continue;
                                    itens.Add(new Item { Tipo = "Registro", Caminho = nomeExib, App = a.Nome, Base = b, SubChave = sub });
                                }
                            }
                            catch { }
                        }
            }
            return itens;
        }

        public static void Limpar(List<AppInstalado> removidos, List<AppInstalado> restantes, LogMelhorias log)
        {
            if (removidos.Count == 0) return;
            Console.WriteLine("\n  Procurando sobras (pastas e registro) dos programas removidos...");
            var itens = Procurar(removidos, restantes);
            if (itens.Count == 0) { Console2.Cor(ConsoleColor.Green, "  Nenhuma sobra encontrada."); return; }

            for (int i = 0; i < itens.Count; i++)
                Console.WriteLine("  [" + (i + 1).ToString().PadLeft(2) + "] " + itens[i].Tipo + ": " + itens[i].Caminho +
                    (itens[i].Bytes > 0 ? " (" + F.Bytes(itens[i].Bytes) + ")" : "") + "  — de " + itens[i].App);
            Console2.Cor(ConsoleColor.DarkGray, "  Pastas vão para a Lixeira. Chaves de registro são salvas em .reg antes (dá para restaurar com dois cliques).");
            string r = Console2.Ler("\n  Digite os números para remover (ex.: 1,3), T para todas, ou Enter para manter: ");
            if (string.IsNullOrEmpty(r)) { log.Linha("Sobras mantidas."); return; }
            var idx = r.Equals("T", StringComparison.OrdinalIgnoreCase) ? Enumerable.Range(1, itens.Count).ToList()
                : r.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => { int k; return int.TryParse(x, out k) ? k : 0; }).Where(k => k >= 1 && k <= itens.Count).Distinct().ToList();
            var escolhidos = idx.Select(k => itens[k - 1]).ToList();
            if (escolhidos.Count == 0 || !Console2.Confirmar("Remover " + escolhidos.Count + " sobra(s)?")) { log.Linha("Sobras mantidas."); return; }

            string pastaReg = Path.Combine(Console2.PastaRelatorios(), "backup-registro");
            foreach (var it in escolhidos)
            {
                if (log.Simulacao) { log.Linha("Removeria: " + it.Caminho); continue; }
                try
                {
                    if (it.Tipo == "Pasta")
                    {
                        FileSystem.DeleteDirectory(it.Caminho, UIOption.OnlyErrorDialogs, RecycleOption.SendToRecycleBin);
                        log.Linha("[SOBRA REMOVIDA] " + it.Caminho + " (na Lixeira).");
                    }
                    else
                    {
                        Directory.CreateDirectory(pastaReg);
                        string arq = Path.Combine(pastaReg, DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Regex.Replace(it.Caminho, @"[\\/:*?""<>|]", "_") + ".reg");
                        int c = Console2.RodarSilencioso("reg.exe", "export \"" + it.Caminho + "\" \"" + arq + "\" /y");
                        if (c != 0) { log.Linha("[SOBRA MANTIDA] " + it.Caminho + ": não foi possível salvar o backup (reg export código " + c + ")."); continue; }
                        it.Base.DeleteSubKeyTree(it.SubChave, false);
                        log.Linha("[SOBRA REMOVIDA] " + it.Caminho + ". Backup: " + arq);
                    }
                }
                catch (Exception ex) { log.Linha("[SOBRA MANTIDA] " + it.Caminho + ": " + ex.Message); }
            }
        }
    }
}
