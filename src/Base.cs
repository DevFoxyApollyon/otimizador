using System;
using System.Collections.Generic;
using System.Globalization;
using System.Management;
using Microsoft.Win32;

namespace PcDiagnostico
{
    enum Gravidade { Critico = 0, Aviso = 1, Info = 2, Ok = 3 }

    class Achado
    {
        public string Categoria;
        public Gravidade Gravidade;
        public string Titulo;
        public string Descricao;
        public string Solucao;
        public List<string> Detalhes = new List<string>();
        public List<string> Comandos = new List<string>();
        /// <summary>Item heurístico: indica suspeita, nunca uma infecção confirmada.</summary>
        public bool Suspeito;
        /// <summary>Recomendação de upgrade: "alto", "médio" ou "baixo" impacto (null nos demais itens).</summary>
        public string Impacto;
        /// <summary>Link externo opcional (ex.: busca do manual da placa-mãe).</summary>
        public string Link, TextoLink;
    }

    /// <summary>Transforma o texto de solução em passos numerados (uma frase por passo).</summary>
    static class Passos
    {
        static readonly System.Text.RegularExpressions.Regex Separador =
            new System.Text.RegularExpressions.Regex(@"(?<=[\.!])\s+(?=[A-ZÁÉÍÓÚÂÊÔÃÕÇ""(])");

        public static List<string> De(string solucao)
        {
            var l = new List<string>();
            if (string.IsNullOrWhiteSpace(solucao)) return l;
            foreach (var p in Separador.Split(solucao.Trim()))
                if (p.Trim().Length > 0) l.Add(p.Trim());
            return l;
        }
    }

    static class Cat
    {
        public const string Ameacas = "Ameaças e itens suspeitos";
        public const string Drivers = "Drivers e dispositivos";
        public const string Eventos = "Erros recentes do sistema (últimos 7 dias)";
        public const string Discos = "Discos e armazenamento";
        public const string Atualizacoes = "Windows Update";
        public const string Seguranca = "Segurança";
        public const string Desempenho = "Desempenho e inicialização";
        public const string Energia = "Energia, bateria e temperatura";
        public const string Integridade = "Integridade do Windows";
        public const string Rede = "Contas, acesso remoto e portas abertas";
        public const string Apps = "Aplicativos instalados";
        public const string Arquivos = "Arquivos grandes, duplicados e Lixeira";
        public const string Upgrade = "Upgrade de peças";

        public static readonly string[] Ordem = { Ameacas, Seguranca, Rede, Upgrade, Apps, Drivers, Eventos, Discos, Arquivos, Atualizacoes, Desempenho, Energia, Integridade };
    }

    /// <summary>Exceção usada quando uma consulta exige privilégios de administrador.</summary>
    class SemPermissaoException : Exception
    {
        public SemPermissaoException(string msg) : base(msg) { }
    }

    /// <summary>Consultas WMI somente leitura.</summary>
    static class W
    {
        public const string Cimv2 = @"root\cimv2";

        public static List<ManagementBaseObject> Q(string ns, string wql)
        {
            var lista = new List<ManagementBaseObject>();
            var escopo = new ManagementScope(ns);
            escopo.Options.Timeout = TimeSpan.FromSeconds(20);
            var op = new EnumerationOptions();
            op.Timeout = TimeSpan.FromSeconds(90);
            op.ReturnImmediately = true;
            op.Rewindable = false;
            try
            {
                using (var s = new ManagementObjectSearcher(escopo, new ObjectQuery(wql), op))
                {
                    foreach (ManagementBaseObject o in s.Get()) lista.Add(o);
                }
            }
            catch (ManagementException ex)
            {
                if (ex.ErrorCode == ManagementStatus.AccessDenied) throw new SemPermissaoException(ex.Message);
                throw;
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new SemPermissaoException(ex.Message);
            }
            return lista;
        }

        /// <summary>Igual a Q, mas devolve lista vazia em caso de erro (exceto falta de permissão, que é repassada).</summary>
        public static List<ManagementBaseObject> QS(string ns, string wql)
        {
            try { return Q(ns, wql); }
            catch (SemPermissaoException) { throw; }
            catch { return new List<ManagementBaseObject>(); }
        }

        public static object V(ManagementBaseObject o, string p)
        {
            try { return o[p]; } catch { return null; }
        }

        public static string S(ManagementBaseObject o, string p)
        {
            object v = V(o, p);
            return v == null ? null : v.ToString().Trim();
        }

        public static long L(ManagementBaseObject o, string p)
        {
            object v = V(o, p);
            if (v == null) return 0;
            try { return Convert.ToInt64(v); } catch { return 0; }
        }

        public static bool B(ManagementBaseObject o, string p)
        {
            object v = V(o, p);
            if (v == null) return false;
            try { return Convert.ToBoolean(v); } catch { return false; }
        }

        public static DateTime? D(ManagementBaseObject o, string p)
        {
            string s = S(o, p);
            if (string.IsNullOrEmpty(s)) return null;
            try { return ManagementDateTimeConverter.ToDateTime(s); } catch { return null; }
        }
    }

    /// <summary>Leitura do registro (somente leitura).</summary>
    static class Reg
    {
        public static object Valor(RegistryHive hive, string caminho, string nome)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (var k = b.OpenSubKey(caminho))
                {
                    return k == null ? null : k.GetValue(nome);
                }
            }
            catch { return null; }
        }

        public static bool Existe(RegistryHive hive, string caminho)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (var k = b.OpenSubKey(caminho))
                {
                    return k != null;
                }
            }
            catch { return false; }
        }

        public static int? Int(RegistryHive hive, string caminho, string nome)
        {
            object v = Valor(hive, caminho, nome);
            if (v == null) return null;
            try { return Convert.ToInt32(v); } catch { return null; }
        }
    }

    static class F
    {
        public static readonly CultureInfo BR = CultureInfo.GetCultureInfo("pt-BR");

        public static string Bytes(double b)
        {
            string[] u = { "B", "KB", "MB", "GB", "TB" };
            int i = 0;
            while (b >= 1024 && i < u.Length - 1) { b /= 1024; i++; }
            return b.ToString(i >= 3 ? "0.0" : "0", BR) + " " + u[i];
        }

        public static string Data(DateTime d) { return d.ToString("dd/MM/yyyy HH:mm", BR); }
        public static string Dia(DateTime d) { return d.ToString("dd/MM/yyyy", BR); }

        public static string Duracao(TimeSpan t)
        {
            if (t.TotalDays >= 1) return ((int)t.TotalDays) + (((int)t.TotalDays) == 1 ? " dia" : " dias") + " e " + t.Hours + " h";
            if (t.TotalHours >= 1) return ((int)t.TotalHours) + " h e " + t.Minutes + " min";
            return t.Minutes + " min";
        }

        public static string Corta(string s, int n)
        {
            if (s == null) return "";
            s = s.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
            while (s.Contains("  ")) s = s.Replace("  ", " ");
            return s.Length <= n ? s : s.Substring(0, n) + "…";
        }

        public static string Pct(double v) { return v.ToString("0", BR) + "%"; }
    }
}
