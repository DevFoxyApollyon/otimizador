using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using Microsoft.Win32;

namespace PcDiagnostico
{
    /// <summary>
    /// Ameaças e itens suspeitos. A detecção real de malware é do Microsoft Defender;
    /// aqui só lemos o histórico dele e aplicamos heurísticas marcadas como "suspeito".
    /// </summary>
    partial class Diagnostico
    {
        const string NsDefender = @"root\Microsoft\Windows\Defender";
        public bool DefenderAtivo;
        List<ItemInicializacao> inicializacao;

        public List<ItemInicializacao> Inicializacao
        {
            get { if (inicializacao == null) inicializacao = ItemInicializacao.Listar(); return inicializacao; }
        }

        static string StatusAmeaca(long s)
        {
            switch (s)
            {
                case 1: return "detectada (ação pendente)";
                case 2: return "limpa";
                case 3: return "em quarentena";
                case 4: return "removida";
                case 5: return "permitida pelo usuário";
                case 6: return "bloqueada";
                case 102: return "falha ao colocar em quarentena";
                case 103: return "falha ao remover";
                case 104: return "falha ao permitir";
                case 105: return "abandonada";
                case 107: return "falha ao bloquear";
                default: return "estado " + s;
            }
        }

        static bool AmeacaAtiva(long s) { return s == 1 || s == 5 || s == 102 || s == 103 || s == 105 || s == 107; }

        static string Severidade(long s)
        {
            switch (s) { case 1: return "Baixa"; case 2: return "Moderada"; case 4: return "Alta"; case 5: return "Grave"; default: return "Desconhecida"; }
        }

        void VerificarAmeacasDefender()
        {
            ManagementBaseObject st = null;
            try { st = W.QS(NsDefender, "SELECT * FROM MSFT_MpComputerStatus").FirstOrDefault(); }
            catch (SemPermissaoException) { SemPermissao("Status do Microsoft Defender"); }

            bool emModoPassivo = false;
            if (st != null)
            {
                DefenderAtivo = W.B(st, "AntivirusEnabled");
                emModoPassivo = W.S(st, "AMRunningMode") != null && W.S(st, "AMRunningMode").IndexOf("Passive", StringComparison.OrdinalIgnoreCase) >= 0;
                var a = Add(Cat.Ameacas, Gravidade.Info, "Status do Microsoft Defender",
                    DefenderAtivo && !emModoPassivo ? "O Defender é o antivírus ativo deste PC." : "O Defender não é o antivírus principal (desativado ou em modo passivo por causa de outro antivírus).",
                    null);
                a.Detalhes.Add("Proteção em tempo real: " + (W.B(st, "RealTimeProtectionEnabled") ? "ligada" : "DESLIGADA"));
                DateTime? ass = W.D(st, "AntivirusSignatureLastUpdated");
                if (ass.HasValue) a.Detalhes.Add("Assinaturas atualizadas em: " + F.Data(ass.Value) + " (versão " + W.S(st, "AntivirusSignatureVersion") + ")");
                DateTime? qs = W.D(st, "QuickScanEndTime"), fs = W.D(st, "FullScanEndTime");
                a.Detalhes.Add("Última verificação rápida: " + (qs.HasValue && qs.Value.Year > 2000 ? F.Data(qs.Value) : "nunca"));
                a.Detalhes.Add("Última verificação completa: " + (fs.HasValue && fs.Value.Year > 2000 ? F.Data(fs.Value) : "nunca"));
                if (W.V(st, "AMRunningMode") != null) a.Detalhes.Add("Modo: " + W.S(st, "AMRunningMode"));

                long idadeQs = W.L(st, "QuickScanAge");
                if (DefenderAtivo && (!qs.HasValue || qs.Value.Year < 2000 || idadeQs > 14))
                {
                    a.Gravidade = Gravidade.Aviso;
                    a.Titulo = "Defender sem verificação recente";
                    a.Descricao = "Nenhuma verificação rápida foi concluída nos últimos 14 dias.";
                }
                if (DefenderAtivo)
                {
                    a.Solucao = "Para rodar uma verificação rápida agora, abra o PCDiagnostico e escolha \"Rodar verificação rápida do Defender\" no menu final (ou use o comando abaixo). O programa só roda a verificação se você escolher.";
                    a.Comandos.Add("PCDiagnostico.exe --verificacao-rapida");
                }
            }

            // Histórico de detecções
            List<ManagementBaseObject> deteccoes = null, ameacas = null;
            try
            {
                deteccoes = W.Q(NsDefender, "SELECT ThreatID, InitialDetectionTime, LastThreatStatusChangeTime, ThreatStatusID, Resources, ProcessName, ActionSuccess FROM MSFT_MpThreatDetection");
                ameacas = W.QS(NsDefender, "SELECT ThreatID, ThreatName, SeverityID, IsActive FROM MSFT_MpThreat");
            }
            catch (SemPermissaoException) { SemPermissao("Histórico de ameaças do Defender"); return; }
            catch { deteccoes = new List<ManagementBaseObject>(); ameacas = new List<ManagementBaseObject>(); }

            var nomes = new Dictionary<long, ManagementBaseObject>();
            foreach (var t in ameacas) nomes[W.L(t, "ThreatID")] = t;

            if (deteccoes.Count == 0)
            {
                if (st != null)
                    Add(Cat.Ameacas, Gravidade.Ok, "Nenhuma ameaça no histórico do Defender",
                        "O Microsoft Defender não registrou ameaças (trojans, vírus, PUPs) neste PC" + (Admin ? "." : ". Como o programa rodou sem administrador, o histórico pode estar incompleto."), null);
                return;
            }

            foreach (var d in deteccoes.OrderByDescending(x => W.D(x, "InitialDetectionTime") ?? DateTime.MinValue).Take(30))
            {
                long id = W.L(d, "ThreatID");
                long status = W.L(d, "ThreatStatusID");
                ManagementBaseObject t;
                nomes.TryGetValue(id, out t);
                string nome = t != null ? W.S(t, "ThreatName") : "Ameaça " + id;
                string sev = t != null ? Severidade(W.L(t, "SeverityID")) : "Desconhecida";
                DateTime? quando = W.D(d, "InitialDetectionTime");
                bool ativa = AmeacaAtiva(status);
                bool recente = quando.HasValue && (DateTime.Now - quando.Value).TotalDays <= 30;
                Gravidade g = ativa ? Gravidade.Critico : recente ? Gravidade.Aviso : Gravidade.Info;

                var a = Add(Cat.Ameacas, g, (ativa ? "Ameaça ativa: " : "Ameaça detectada: ") + nome,
                    "Detectada pelo Microsoft Defender" + (quando.HasValue ? " em " + F.Data(quando.Value) : "") + ". Situação: " + StatusAmeaca(status) + ". Gravidade: " + sev + ".",
                    ativa
                        ? "Abra Segurança do Windows > Proteção contra vírus e ameaças > Ameaças atuais e escolha \"Remover\". Depois rode uma verificação completa e, se possível, a verificação do Microsoft Defender Offline. Troque senhas importantes usando outro dispositivo."
                        : "O Defender já tratou esta ameaça. Rode uma verificação rápida para confirmar que não sobrou nada.",
                    "start windowsdefender://threat");
                var rec = W.V(d, "Resources") as string[];
                if (rec != null) foreach (var r in rec.Take(5)) a.Detalhes.Add("Arquivo/recurso: " + r);
                string proc = W.S(d, "ProcessName");
                if (!string.IsNullOrEmpty(proc) && proc != "Unknown") a.Detalhes.Add("Processo: " + proc);
            }
        }

        // ------------------------------------------------------------------ Heurísticas

        Achado Suspeito(Gravidade g, string titulo, string desc, string sol, params string[] cmds)
        {
            var a = Add(Cat.Ameacas, g, titulo, desc, sol, cmds);
            a.Suspeito = true;
            return a;
        }

        void VerificarItensSuspeitos()
        {
            // 1) Inicialização a partir de TEMP/AppData
            foreach (var it in Inicializacao.Where(x => x.Ativo))
            {
                string exe = it.Exe;
                if (exe == null) continue;
                bool temp = Caminho.EmTemp(exe);
                bool appdata = Caminho.EmAppData(exe);
                if (!temp && !appdata) continue;
                bool existe = File.Exists(exe);
                var ass = existe ? Assinatura.Verificar(exe) : EstadoAssinatura.Desconhecido;
                if (!temp && ass == EstadoAssinatura.Assinado) continue; // apps comuns (Discord, Spotify...) assinados ficam em AppData
                var a = Suspeito(temp ? Gravidade.Aviso : (ass == EstadoAssinatura.Assinado ? Gravidade.Info : Gravidade.Aviso),
                    "Inicia com o Windows a partir de " + (temp ? "pasta temporária" : "AppData") + ": " + it.Nome,
                    "Malwares costumam se instalar em pastas temporárias ou em AppData e se registrar para iniciar com o Windows. Isto é apenas um indício: verifique se você reconhece o programa.",
                    "Se não reconhecer, envie o arquivo para análise em virustotal.com, desative o item no Gerenciador de Tarefas > Aplicativos de inicialização e rode uma verificação do Defender.",
                    "start ms-settings:startupapps");
                a.Detalhes.Add("Arquivo: " + exe + (existe ? "" : " (arquivo não existe mais)"));
                a.Detalhes.Add("Assinatura: " + Assinatura.Texto(ass) + (ass == EstadoAssinatura.Assinado ? " por " + Assinatura.Signatario(exe) : ""));
                a.Detalhes.Add("Origem: " + it.Origem);
            }

            // 2) Tarefas agendadas em pastas de usuário
            VerificarTarefasAgendadas();

            // 3) Arquivo hosts
            VerificarHosts();

            // 4) Proxy
            object pe = Reg.Valor(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable");
            string ps = Reg.Valor(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer") as string;
            string pac = Reg.Valor(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "AutoConfigURL") as string;
            bool proxyLigado = pe != null && Convert.ToInt32(pe) == 1 && !string.IsNullOrEmpty(ps);
            if (proxyLigado || !string.IsNullOrEmpty(pac))
            {
                var a = Suspeito(Gravidade.Aviso, "Proxy configurado no sistema",
                    "Todo o tráfego da internet passa por um proxy. Empresas e alguns programas (VPN, antivírus) usam isso, mas malwares também configuram proxy para espionar ou alterar páginas.",
                    "Se você não configurou isso, abra Configurações > Rede e Internet > Proxy e desative \"Usar um servidor proxy\" e \"Usar script de instalação\". Depois rode uma verificação do Defender.",
                    "start ms-settings:network-proxy");
                if (proxyLigado) a.Detalhes.Add("Servidor proxy: " + ps);
                if (!string.IsNullOrEmpty(pac)) a.Detalhes.Add("Script de configuração (PAC): " + pac);
            }
            else Add(Cat.Ameacas, Gravidade.Ok, "Nenhum proxy configurado", "A conexão com a internet é direta.", null);

            // 5) Exclusões do Defender
            VerificarExclusoesDefender();
        }

        void VerificarTarefasAgendadas()
        {
            var suspeitas = new List<string>();
            var assinadasUsuario = 0;
            int lidas = 0;
            try
            {
                dynamic svc = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
                svc.Connect();
                var pilha = new Stack<object>();
                pilha.Push(svc.GetFolder("\\"));
                while (pilha.Count > 0)
                {
                    dynamic pasta = pilha.Pop();
                    try
                    {
                        dynamic tarefas = pasta.GetTasks(1); // inclui ocultas
                        int n = tarefas.Count;
                        for (int i = 1; i <= n; i++)
                        {
                            try
                            {
                                dynamic t = tarefas.Item(i);
                                lidas++;
                                if (!(bool)t.Enabled) continue;
                                dynamic acoes = t.Definition.Actions;
                                int na = acoes.Count;
                                for (int j = 1; j <= na; j++)
                                {
                                    dynamic ac = acoes.Item(j);
                                    if ((int)ac.Type != 0) continue; // só ações "executar programa"
                                    string caminho = Environment.ExpandEnvironmentVariables(((string)ac.Path ?? "").Trim('"'));
                                    string args = ac.Arguments ?? "";
                                    if (!Caminho.EmPastaDeUsuario(caminho)) continue;
                                    bool existe = File.Exists(caminho);
                                    var ass = existe ? Assinatura.Verificar(caminho) : EstadoAssinatura.Desconhecido;
                                    if (ass == EstadoAssinatura.Assinado && !Caminho.EmTemp(caminho)) { assinadasUsuario++; continue; }
                                    suspeitas.Add((string)t.Path + " → " + caminho + (args.Length > 0 ? " " + F.Corta(args, 80) : "") + "  [" + (existe ? Assinatura.Texto(ass) : "arquivo não existe") + "]");
                                }
                            }
                            catch { }
                        }
                        dynamic sub = pasta.GetFolders(0);
                        int ns = sub.Count;
                        for (int i = 1; i <= ns; i++) pilha.Push(sub.Item(i));
                    }
                    catch { }
                }
            }
            catch { return; }

            if (suspeitas.Count > 0)
            {
                var a = Suspeito(Gravidade.Aviso, suspeitas.Count + (suspeitas.Count == 1 ? " tarefa agendada suspeita" : " tarefas agendadas suspeitas"),
                    "Tarefas agendadas que executam programas sem assinatura (ou inexistentes) a partir de pastas de usuário são uma forma comum de malware se manter no PC. Muitos programas legítimos também fazem isso: analise a lista.",
                    "Abra o Agendador de Tarefas, localize cada tarefa pelo caminho mostrado e desative as que você não reconhece. Envie o arquivo para análise em virustotal.com se tiver dúvida.",
                    "taskschd.msc");
                a.Detalhes.AddRange(suspeitas);
            }
            else if (lidas > 0)
            {
                Add(Cat.Ameacas, Gravidade.Ok, "Nenhuma tarefa agendada suspeita",
                    lidas + " tarefas analisadas" + (assinadasUsuario > 0 ? " (" + assinadasUsuario + " em pastas de usuário, todas assinadas)" : "") + (Admin ? "." : ". Sem administrador, algumas tarefas do sistema não puderam ser lidas."), null);
            }
        }

        static readonly string[] DominiosSensiveis =
        {
            "google", "microsoft", "windowsupdate", "live.com", "outlook", "office", "facebook", "instagram", "whatsapp",
            "youtube", "paypal", "mercadopago", "mercadolivre", "nubank", "itau", "bradesco", "santander", "caixa", "bb.com.br",
            "bancodobrasil", "inter.co", "c6bank", "picpay", "gov.br", "receita", "apple", "amazon", "steam", "discord",
            "virustotal", "malwarebytes", "kaspersky", "avast", "eset", "bitdefender", "norton", "mcafee"
        };

        void VerificarHosts()
        {
            string hosts = Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");
            if (!File.Exists(hosts)) return;
            var redir = new List<string>();
            var bloqueios = new List<string>();
            foreach (var bruta in File.ReadAllLines(hosts))
            {
                string l = bruta;
                int c = l.IndexOf('#');
                if (c >= 0) l = l.Substring(0, c);
                l = l.Trim();
                if (l.Length == 0) continue;
                var partes = l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (partes.Length < 2) continue;
                string ip = partes[0];
                bool loop = ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip == "::";
                for (int i = 1; i < partes.Length; i++)
                {
                    string h = partes[i].ToLowerInvariant();
                    if (h == "localhost" || h.EndsWith(".localhost") || h == "localhost.localdomain") continue;
                    bool sensivel = DominiosSensiveis.Any(x => h.Contains(x));
                    if (!loop) redir.Add(h + " → " + ip + (sensivel ? "  (site importante redirecionado!)" : ""));
                    else bloqueios.Add(h + " → " + ip + (sensivel ? "  (bloqueado)" : ""));
                }
            }
            bool redirSensivel = redir.Any(x => x.Contains("importante"));
            bool bloqueioSeguranca = bloqueios.Any(x => x.Contains("windowsupdate") || x.Contains("virustotal") || x.Contains("malwarebytes") || x.Contains("kaspersky") || x.Contains("avast") || x.Contains("eset") || x.Contains("bitdefender"));
            if (redir.Count + bloqueios.Count == 0)
            {
                Add(Cat.Ameacas, Gravidade.Ok, "Arquivo hosts original", "O arquivo hosts não tem redirecionamentos.", null);
                return;
            }
            Gravidade g = redirSensivel || bloqueioSeguranca ? Gravidade.Critico : redir.Count > 0 ? Gravidade.Aviso : Gravidade.Info;
            var a = Suspeito(g, "Arquivo hosts alterado (" + (redir.Count + bloqueios.Count) + " entradas)",
                (redirSensivel ? "Sites importantes estão sendo redirecionados para outro endereço — técnica usada por malwares para roubar senhas (phishing). "
                 : bloqueioSeguranca ? "Sites de segurança ou atualização estão bloqueados — técnica usada por malwares para impedir a própria remoção. "
                 : "O arquivo hosts tem entradas personalizadas. Bloqueadores de anúncios e alguns programas fazem isso. ") +
                "Arquivo: " + hosts,
                "Se você não fez essas alterações, abra o Bloco de Notas como administrador, abra o arquivo hosts e apague as linhas listadas (mantenha as linhas que começam com #). Depois rode uma verificação completa do Defender.",
                "notepad " + hosts);
            a.Detalhes.AddRange(redir.Concat(bloqueios).Take(40));
            if (redir.Count + bloqueios.Count > 40) a.Detalhes.Add("... e mais " + (redir.Count + bloqueios.Count - 40) + " entradas");
        }

        void VerificarExclusoesDefender()
        {
            ManagementBaseObject pref = null;
            try { pref = W.QS(NsDefender, "SELECT ExclusionPath, ExclusionProcess, ExclusionExtension FROM MSFT_MpPreference").FirstOrDefault(); }
            catch (SemPermissaoException) { }
            if (pref == null) return;

            var todas = new List<string>();
            var suspeitas = new List<string>();
            Action<string, string> analisar = (prop, rotulo) =>
            {
                var v = W.V(pref, prop) as string[];
                if (v == null) return;
                foreach (var x in v)
                {
                    if (string.IsNullOrEmpty(x)) continue;
                    if (x.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)) { SemPermissao("Exclusões do Microsoft Defender"); return; }
                    string l = x.ToLowerInvariant().TrimEnd('\\');
                    bool s = false;
                    if (prop == "ExclusionPath")
                        s = l.Length <= 3 || l == @"c:\users" || l == @"c:\windows" || l == @"c:\windows\system32" || l == @"c:\program files" || l == @"c:\programdata"
                            || l.EndsWith(@"\appdata") || l.EndsWith(@"\appdata\local") || l.EndsWith(@"\appdata\roaming") || l.Contains(@"\temp") || l.EndsWith(@"\downloads") || l.EndsWith(@"\desktop")
                            || l.Contains("%temp%") || l.Contains("%appdata%") || l.Contains("%userprofile%");
                    else if (prop == "ExclusionExtension")
                        s = new[] { "exe", ".exe", "dll", ".dll", "ps1", ".ps1", "bat", ".bat", "cmd", ".cmd", "vbs", ".vbs", "js", ".js", "scr", ".scr", "msi", ".msi" }.Contains(l);
                    else
                        s = new[] { "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "explorer.exe", "svchost.exe" }.Contains(Path.GetFileName(l));
                    string linha = rotulo + ": " + x;
                    todas.Add(linha);
                    if (s) suspeitas.Add(linha);
                }
            };
            analisar("ExclusionPath", "Pasta");
            analisar("ExclusionProcess", "Processo");
            analisar("ExclusionExtension", "Extensão");

            if (suspeitas.Count > 0)
            {
                var a = Suspeito(Gravidade.Critico, "Exclusões perigosas no Microsoft Defender",
                    "O Defender foi configurado para ignorar locais, extensões ou processos amplos demais. Malwares fazem isso para não serem detectados.",
                    "Se você não adicionou essas exclusões, remova-as em Segurança do Windows > Proteção contra vírus e ameaças > Gerenciar configurações > Exclusões, e rode uma verificação completa.",
                    "start windowsdefender://exclusions");
                a.Detalhes.AddRange(suspeitas);
            }
            else if (todas.Count > 0)
            {
                var a = Add(Cat.Ameacas, Gravidade.Info, todas.Count + " exclusões no Microsoft Defender",
                    "Itens que o Defender não verifica. Nenhuma parece perigosa, mas confira se você reconhece todas.",
                    "Para revisar: Segurança do Windows > Proteção contra vírus e ameaças > Gerenciar configurações > Exclusões.", "start windowsdefender://exclusions");
                a.Detalhes.AddRange(todas);
            }
        }

        void VerificarProcessosSemAssinatura()
        {
            var porCaminho = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == Process.GetCurrentProcess().Id) continue;
                    string c = Nativo.CaminhoProcesso(p.Id);
                    if (string.IsNullOrEmpty(c)) continue;
                    List<string> l;
                    if (!porCaminho.TryGetValue(c, out l)) { l = new List<string>(); porCaminho[c] = l; }
                    l.Add(p.ProcessName + " (PID " + p.Id + ")");
                }
                catch { }
                finally { p.Dispose(); }
            }

            var semAss = new List<string>();
            var emTemp = new List<string>();
            foreach (var kv in porCaminho)
            {
                var e = Assinatura.Verificar(kv.Key);
                if (e == EstadoAssinatura.Assinado || e == EstadoAssinatura.Desconhecido) continue;
                string linha = kv.Key + "  [" + Assinatura.Texto(e) + "] — " + string.Join(", ", kv.Value.Take(3));
                if (Caminho.EmTemp(kv.Key)) emTemp.Add(linha); else semAss.Add(linha);
            }

            if (emTemp.Count > 0)
            {
                var a = Suspeito(Gravidade.Aviso, emTemp.Count + " programa(s) sem assinatura rodando de pasta temporária",
                    "Programas sem assinatura executando a partir de pastas temporárias são um indício comum de malware (ou de instaladores em andamento).",
                    "Se não estiver instalando nada agora, verifique o arquivo em virustotal.com e rode uma verificação do Defender.", "taskmgr");
                a.Detalhes.AddRange(emTemp);
            }
            if (semAss.Count > 0)
            {
                var a = Suspeito(Gravidade.Info, semAss.Count + " programa(s) em execução sem assinatura digital",
                    "A assinatura digital identifica quem publicou o programa. Muitos programas legítimos (ferramentas de desenvolvimento, jogos antigos, mods, utilitários pequenos) não são assinados; isto não indica vírus por si só.",
                    "Confira se você reconhece cada programa. Em caso de dúvida, envie o arquivo para análise em virustotal.com.", "taskmgr");
                a.Detalhes.AddRange(semAss.OrderBy(x => x));
            }
            if (emTemp.Count + semAss.Count == 0)
                Add(Cat.Ameacas, Gravidade.Ok, "Todos os processos acessíveis são assinados",
                    porCaminho.Count + " programas em execução verificados" + (Admin ? "." : " (processos de outros usuários e protegidos não são acessíveis sem administrador)."), null);
        }
    }
}
