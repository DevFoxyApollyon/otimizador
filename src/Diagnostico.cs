using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

namespace PcDiagnostico
{
    /// <summary>
    /// Executa todas as verificações. Nada aqui altera o sistema: apenas leitura
    /// de WMI, registro, Visualizador de Eventos e sistema de arquivos.
    /// </summary>
    partial class Diagnostico
    {
        public readonly List<Achado> Achados = new List<Achado>();
        public readonly List<KeyValuePair<string, string>> InfoSistema = new List<KeyValuePair<string, string>>();
        public readonly List<string> TestesSemPermissao = new List<string>();
        public bool Admin;
        public DateTime Inicio = DateTime.Now;
        public TimeSpan Duracao;
        public List<Melhoria> MelhoriasDisponiveis = new List<Melhoria>();

        // Dados reaproveitados entre verificações
        bool notebook;
        bool temBateria;
        DateTime? ultimoBoot;
        long memTotalKB, memLivreKB;
        bool houveTelaAzul, houveErroDisco, houveErroHardware;

        Achado Add(string cat, Gravidade g, string titulo, string desc, string sol, params string[] cmds)
        {
            var a = new Achado { Categoria = cat, Gravidade = g, Titulo = titulo, Descricao = desc, Solucao = sol };
            if (cmds != null) a.Comandos.AddRange(cmds);
            Achados.Add(a);
            return a;
        }

        void Info(string chave, string valor)
        {
            if (!string.IsNullOrEmpty(valor)) InfoSistema.Add(new KeyValuePair<string, string>(chave, valor));
        }

        void SemPermissao(string teste)
        {
            if (!TestesSemPermissao.Contains(teste)) TestesSemPermissao.Add(teste);
        }

        public void Executar(Action<int, int, string> progresso)
        {
            try { Admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { }

            var etapas = new List<Tuple<string, string, Action>>
            {
                Tuple.Create("Coletando informações do sistema", "Informações do sistema", (Action)ColetarSistema),
                Tuple.Create("Verificando dispositivos e drivers", Cat.Drivers, (Action)VerificarDispositivos),
                Tuple.Create("Procurando drivers desatualizados", Cat.Drivers, (Action)VerificarDriversAntigos),
                Tuple.Create("Lendo o Visualizador de Eventos", Cat.Eventos, (Action)VerificarEventos),
                Tuple.Create("Verificando saúde e espaço dos discos", Cat.Discos, (Action)VerificarDiscos),
                Tuple.Create("Consultando o Windows Update (pode demorar)", Cat.Atualizacoes, (Action)VerificarWindowsUpdate),
                Tuple.Create("Verificando antivírus, firewall e proteções", Cat.Seguranca, (Action)VerificarSeguranca),
                Tuple.Create("Analisando memória e programas de inicialização", Cat.Desempenho, (Action)VerificarDesempenho),
                Tuple.Create("Verificando energia, bateria e temperatura", Cat.Energia, (Action)VerificarEnergia),
                Tuple.Create("Lendo histórico de ameaças do Microsoft Defender", Cat.Ameacas, (Action)VerificarAmeacasDefender),
                Tuple.Create("Procurando itens suspeitos (inicialização, tarefas, hosts, proxy)", Cat.Ameacas, (Action)VerificarItensSuspeitos),
                Tuple.Create("Verificando assinatura dos processos em execução", Cat.Ameacas, (Action)VerificarProcessosSemAssinatura),
                Tuple.Create("Verificando BitLocker, TPM, contas, SMBv1 e RDP", Cat.Rede, (Action)VerificarContasEAcesso),
                Tuple.Create("Listando programas que aceitam conexões de rede", Cat.Rede, (Action)VerificarPortas),
                Tuple.Create("Analisando aplicativos instalados", Cat.Apps, (Action)VerificarApps),
                Tuple.Create("Procurando arquivos grandes e duplicados", Cat.Arquivos, (Action)VerificarArquivos),
                Tuple.Create("Verificando arquivo de paginação, BIOS e telas azuis", Cat.Integridade, (Action)VerificarExtrasSistema),
                Tuple.Create("Verificando integridade do Windows", Cat.Integridade, (Action)VerificarIntegridade),
                Tuple.Create("Avaliando peças e possíveis upgrades", Cat.Upgrade, (Action)VerificarUpgrade),
                Tuple.Create("Medindo o que está travando o PC e se precisa reiniciar", Cat.Desempenho, (Action)VerificarTravamento),
            };

            for (int i = 0; i < etapas.Count; i++)
            {
                progresso(i + 1, etapas.Count, etapas[i].Item1);
                try
                {
                    etapas[i].Item3();
                }
                catch (SemPermissaoException)
                {
                    SemPermissao(etapas[i].Item1);
                }
                catch (Exception ex)
                {
                    string cat = etapas[i].Item2 == "Informações do sistema" ? Cat.Integridade : etapas[i].Item2;
                    Add(cat, Gravidade.Info, "Não foi possível concluir: " + etapas[i].Item1.ToLowerInvariant(),
                        "Esta verificação falhou e foi ignorada. Erro: " + F.Corta(ex.Message, 300),
                        "Tente executar novamente como administrador.");
                }
            }
            Duracao = DateTime.Now - Inicio;
        }

        // ------------------------------------------------------------------ Sistema

        void ColetarSistema()
        {
            Info("Computador", Environment.MachineName);

            string displayVersion = Reg.Valor(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") as string;
            int? ubr = Reg.Int(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");

            foreach (var o in W.QS(W.Cimv2, "SELECT Caption, BuildNumber, InstallDate, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory, OSArchitecture FROM Win32_OperatingSystem"))
            {
                string build = W.S(o, "BuildNumber") + (ubr.HasValue ? "." + ubr.Value : "");
                Info("Sistema", W.S(o, "Caption") + (displayVersion != null ? " " + displayVersion : "") + " (build " + build + ", " + W.S(o, "OSArchitecture") + ")");
                memTotalKB = W.L(o, "TotalVisibleMemorySize");
                memLivreKB = W.L(o, "FreePhysicalMemory");
                ultimoBoot = W.D(o, "LastBootUpTime");
                DateTime? inst = W.D(o, "InstallDate");
                if (inst.HasValue) Info("Windows instalado em", F.Dia(inst.Value));
            }

            foreach (var o in W.QS(W.Cimv2, "SELECT Manufacturer, Model, PCSystemType FROM Win32_ComputerSystem"))
            {
                Info("Fabricante / modelo", (W.S(o, "Manufacturer") + " " + W.S(o, "Model")).Trim());
                notebook = W.L(o, "PCSystemType") == 2;
            }

            foreach (var o in W.QS(W.Cimv2, "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"))
                Info("Processador", W.S(o, "Name") + " (" + W.L(o, "NumberOfCores") + " núcleos / " + W.L(o, "NumberOfLogicalProcessors") + " threads)");

            if (memTotalKB > 0) Info("Memória RAM", F.Bytes(memTotalKB * 1024.0));

            var gpus = new List<string>();
            foreach (var o in W.QS(W.Cimv2, "SELECT Name, DriverVersion, DriverDate FROM Win32_VideoController"))
            {
                string nome = W.S(o, "Name") ?? "Placa de vídeo";
                if (!gpus.Contains(nome)) gpus.Add(nome);
                VerificarDriverVideo(nome, W.S(o, "DriverVersion"), W.D(o, "DriverDate"));
            }
            if (gpus.Count > 0) Info("Placa de vídeo", string.Join(" · ", gpus));

            foreach (var o in W.QS(W.Cimv2, "SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS"))
            {
                DateTime? d = W.D(o, "ReleaseDate");
                Info("BIOS / UEFI", W.S(o, "SMBIOSBIOSVersion") + (d.HasValue ? " (" + F.Dia(d.Value) + ")" : ""));
            }

            if (ultimoBoot.HasValue) Info("Ligado há", F.Duracao(DateTime.Now - ultimoBoot.Value));
            Info("Executado como", Admin ? "Administrador" : "Usuário padrão (sem elevação)");
        }

        void VerificarDriverVideo(string nome, string versao, DateTime? data)
        {
            string n = nome.ToLowerInvariant();
            if (n.Contains("basic display") || n.Contains("vídeo básico") || n.Contains("video basico") || n.Contains("basic render"))
            {
                Add(Cat.Drivers, Gravidade.Aviso, "Placa de vídeo sem driver do fabricante",
                    "O Windows está usando o driver genérico \"" + nome + "\". Isso limita desempenho, resolução e jogos.",
                    "Instale o driver oficial da sua placa de vídeo pelo site da NVIDIA, AMD ou Intel, ou do fabricante do notebook.");
                return;
            }
            bool fisica = n.Contains("nvidia") || n.Contains("geforce") || n.Contains("radeon") || n.Contains("amd") || n.Contains("intel") || n.Contains("arc");
            if (!fisica || !data.HasValue) return;
            double dias = (DateTime.Now - data.Value).TotalDays;
            if (dias > 365)
            {
                var a = Add(Cat.Drivers, Gravidade.Info, "Driver de vídeo com mais de 1 ano",
                    nome + " usa um driver de " + F.Dia(data.Value) + " (versão " + versao + "). Drivers de vídeo novos costumam trazer correções de travamentos e ganhos de desempenho em jogos.",
                    "Baixe o driver mais recente pelo app ou site do fabricante (NVIDIA App, AMD Software: Adrenalin ou Intel Driver & Support Assistant).");
                a.Detalhes.Add("Idade do driver: " + (int)(dias / 30) + " meses");
            }
        }

        // ------------------------------------------------------------------ Dispositivos

        static string DescricaoCodigo(long c)
        {
            switch (c)
            {
                case 1: return "O dispositivo não está configurado corretamente (código 1).";
                case 3: return "O driver pode estar corrompido ou o sistema está com pouca memória (código 3).";
                case 10: return "O dispositivo não pode ser iniciado (código 10).";
                case 12: return "Não há recursos livres suficientes para o dispositivo (código 12).";
                case 14: return "O dispositivo só funcionará após reiniciar o computador (código 14).";
                case 18: return "Os drivers do dispositivo precisam ser reinstalados (código 18).";
                case 19: return "As informações de configuração no registro estão incompletas ou danificadas (código 19).";
                case 21: return "O Windows está removendo este dispositivo (código 21).";
                case 22: return "O dispositivo está desativado (código 22).";
                case 24: return "O dispositivo não está presente ou não tem todos os drivers instalados (código 24).";
                case 28: return "Os drivers deste dispositivo não estão instalados (código 28).";
                case 29: return "O dispositivo foi desativado pelo firmware (código 29).";
                case 31: return "O Windows não consegue carregar os drivers deste dispositivo (código 31).";
                case 32: return "O serviço do driver deste dispositivo está desativado (código 32).";
                case 37: return "O driver do dispositivo retornou uma falha (código 37).";
                case 39: return "O driver está corrompido ou ausente (código 39).";
                case 41: return "O hardware não foi encontrado após o driver ser carregado (código 41).";
                case 43: return "O Windows parou o dispositivo porque ele relatou problemas (código 43).";
                case 47: return "O dispositivo foi preparado para remoção segura (código 47).";
                case 48: return "O driver foi bloqueado por problemas de compatibilidade (código 48).";
                case 52: return "A assinatura digital do driver não pôde ser verificada (código 52).";
                default: return "O dispositivo relatou o código de erro " + c + ".";
            }
        }

        static string SolucaoCodigo(long c)
        {
            switch (c)
            {
                case 22:
                    return "Se você não usa este dispositivo, pode ignorar. Para reativar: Gerenciador de Dispositivos > clique com o botão direito no dispositivo > Habilitar dispositivo.";
                case 14:
                    return "Reinicie o computador.";
                case 10:
                case 43:
                    return "Desconecte e reconecte o dispositivo (se for USB, teste outra porta). Depois, no Gerenciador de Dispositivos, desinstale o dispositivo e reinicie para o Windows reinstalar o driver. Se continuar, instale o driver do site do fabricante; o código 43 também pode indicar defeito no hardware.";
                case 12:
                    return "Remova dispositivos desnecessários e atualize a BIOS/UEFI e o driver do chipset. Em casos persistentes, desative no Gerenciador de Dispositivos um dispositivo que não usa.";
                case 52:
                case 48:
                    return "Baixe uma versão atual e assinada do driver no site do fabricante. Evite drivers de fontes desconhecidas.";
                default:
                    return "Instale ou atualize o driver: Configurações > Windows Update > Opções avançadas > Atualizações opcionais, ou baixe-o no site do fabricante do dispositivo/placa-mãe/notebook. No Gerenciador de Dispositivos, clique com o botão direito > Atualizar driver.";
            }
        }

        void VerificarDispositivos()
        {
            var lista = W.Q(W.Cimv2, "SELECT Name, DeviceID, ConfigManagerErrorCode, PNPClass, Manufacturer FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0");
            var desativados = new List<string>();
            int problemas = 0;
            foreach (var o in lista)
            {
                long cod = W.L(o, "ConfigManagerErrorCode");
                if (cod == 45) continue; // dispositivo desconectado (não presente) - normal
                string nome = W.S(o, "Name");
                string id = W.S(o, "DeviceID") ?? "";
                string classe = W.S(o, "PNPClass");
                if (string.IsNullOrEmpty(nome)) nome = "Dispositivo desconhecido";

                if (cod == 22)
                {
                    desativados.Add(nome + (classe != null ? " [" + classe + "]" : ""));
                    continue;
                }
                problemas++;
                var a = Add(Cat.Drivers, cod == 28 || cod == 14 ? Gravidade.Aviso : Gravidade.Critico,
                    "Dispositivo com problema: " + nome,
                    DescricaoCodigo(cod),
                    SolucaoCodigo(cod), "devmgmt.msc");
                if (classe != null) a.Detalhes.Add("Classe: " + classe);
                string fab = W.S(o, "Manufacturer");
                if (!string.IsNullOrEmpty(fab)) a.Detalhes.Add("Fabricante: " + fab);
                a.Detalhes.Add("ID do hardware: " + id + "  (pesquise este ID para achar o driver certo)");
            }

            if (desativados.Count > 0)
            {
                var a = Add(Cat.Drivers, Gravidade.Info, desativados.Count + (desativados.Count == 1 ? " dispositivo desativado" : " dispositivos desativados"),
                    "Estes dispositivos foram desativados manualmente ou por um programa. Normalmente não é um problema.",
                    SolucaoCodigo(22), "devmgmt.msc");
                a.Detalhes.AddRange(desativados);
            }
            if (problemas == 0)
                Add(Cat.Drivers, Gravidade.Ok, "Todos os dispositivos estão funcionando",
                    "Nenhum dispositivo com erro ou sem driver foi encontrado no Gerenciador de Dispositivos.", null);
        }

        void VerificarDriversAntigos()
        {
            var lista = W.Q(W.Cimv2, "SELECT DeviceName, DriverProviderName, DriverVersion, DriverDate, DeviceClass FROM Win32_PnPSignedDriver");
            var antigos = new List<Tuple<DateTime, string>>();
            var vistos = new HashSet<string>();
            foreach (var o in lista)
            {
                string nome = W.S(o, "DeviceName");
                string prov = W.S(o, "DriverProviderName") ?? "";
                DateTime? data = W.D(o, "DriverDate");
                if (string.IsNullOrEmpty(nome) || !data.HasValue) continue;
                if (prov.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) continue; // drivers nativos do Windows
                if (data.Value.Year < 2006) continue; // datas fictícias usadas por alguns INF (ex.: 1968)
                if ((DateTime.Now - data.Value).TotalDays < 365 * 5) continue;
                string chave = nome + "|" + W.S(o, "DriverVersion");
                if (!vistos.Add(chave)) continue;
                antigos.Add(Tuple.Create(data.Value, nome + " — " + prov + ", versão " + W.S(o, "DriverVersion") + ", de " + F.Dia(data.Value)));
            }

            if (antigos.Count > 0)
            {
                var a = Add(Cat.Drivers, Gravidade.Info, antigos.Count + " drivers de terceiros com mais de 5 anos",
                    "Drivers antigos nem sempre são um problema (alguns dispositivos não recebem mais atualizações), mas podem causar instabilidade, telas azuis ou baixo desempenho.",
                    "Verifique se há versões mais novas no site do fabricante do PC/placa-mãe ou em Configurações > Windows Update > Opções avançadas > Atualizações opcionais. Priorize chipset, rede, áudio e armazenamento. Não use \"atualizadores de driver\" de terceiros.",
                    "start ms-settings:windowsupdate-optionalupdates");
                foreach (var t in antigos.OrderBy(x => x.Item1)) a.Detalhes.Add(t.Item2);
            }
            else
            {
                Add(Cat.Drivers, Gravidade.Ok, "Nenhum driver de terceiros muito antigo",
                    "Não foram encontrados drivers de terceiros com mais de 5 anos.", null);
            }
        }

        // ------------------------------------------------------------------ Eventos

        class Dica
        {
            public Gravidade? G;
            public string Explicacao;
            public string Solucao;
            public string[] Comandos;
        }

        class GrupoEvento
        {
            public string Log;
            public string Origem;
            public int Total;
            public int MenorNivel = 99;
            public DateTime Ultimo = DateTime.MinValue;
            public Dictionary<long, int> PorId = new Dictionary<long, int>();
            public Dictionary<long, List<string>> Amostras = new Dictionary<long, List<string>>();
            public Dictionary<long, int> Tentativas = new Dictionary<long, int>();
        }

        Dica DicaEvento(string origem, ICollection<long> ids)
        {
            string p = origem.ToLowerInvariant();
            if (p == "microsoft-windows-kernel-power" && ids.Contains(41))
            {
                houveTelaAzul = true;
                return new Dica
                {
                    G = Gravidade.Critico,
                    Explicacao = "O PC desligou ou reiniciou sem um desligamento correto (queda de energia, travamento total ou tela azul).",
                    Solucao = "Verifique a fonte e a estabilidade da energia (use um filtro de linha/nobreak), as temperaturas e remova overclock. Se houver telas azuis, atualize os drivers de vídeo, chipset e armazenamento e a BIOS."
                };
            }
            if (p.Contains("wer-systemerrorreporting") || p == "bugcheck")
            {
                houveTelaAzul = true;
                return new Dica
                {
                    G = Gravidade.Critico,
                    Explicacao = "O Windows sofreu uma tela azul (BSOD). O código de parada aparece nos detalhes.",
                    Solucao = "Pesquise o código de parada mostrado, analise os arquivos em C:\\Windows\\Minidump (por exemplo com WinDbg ou BlueScreenView) para ver o driver culpado e atualize-o. Teste a memória RAM com o Diagnóstico de Memória do Windows.",
                    Comandos = new[] { "mdsched.exe" }
                };
            }
            if (p.Contains("whea"))
            {
                houveErroHardware = true;
                return new Dica
                {
                    G = Gravidade.Critico,
                    Explicacao = "Erros de hardware relatados pelo processador, memória ou barramento PCIe.",
                    Solucao = "Remova overclock e perfis XMP/EXPO instáveis, verifique as temperaturas, atualize a BIOS e o driver do chipset e teste a memória RAM.",
                    Comandos = new[] { "mdsched.exe" }
                };
            }
            if (p == "disk" || p == "ntfs" || p.Contains("storport") || p == "stornvme" || p == "storahci" || p == "volmgr" || p.StartsWith("iastor") || p == "microsoft-windows-ntfs")
            {
                houveErroDisco = true;
                return new Dica
                {
                    G = Gravidade.Critico,
                    Explicacao = "Erros de leitura/gravação ou do sistema de arquivos no disco.",
                    Solucao = "Faça backup dos arquivos importantes agora. Verifique cabos e conectores, confira a saúde do disco (seção Discos) e faça uma verificação do sistema de arquivos com o comando abaixo (somente leitura).",
                    Comandos = new[] { "chkdsk C: /scan" }
                };
            }
            if (p == "eventlog" && ids.Contains(6008))
                return new Dica
                {
                    G = Gravidade.Aviso,
                    Explicacao = "O desligamento anterior do computador foi inesperado.",
                    Solucao = "Evite desligar pelo botão de energia. Se acontecer sozinho, verifique fonte, temperatura e telas azuis."
                };
            if (p == "service control manager")
                return new Dica
                {
                    Explicacao = "Um ou mais serviços falharam ao iniciar ou pararam inesperadamente. O nome do serviço aparece nos detalhes.",
                    Solucao = "Abra Serviços (services.msc), localize o serviço citado e confira se o programa dono dele ainda está instalado. Atualize ou reinstale esse programa; desinstale-o se não usa mais.",
                    Comandos = new[] { "services.msc" }
                };
            if (p == "microsoft-windows-distributedcom" || p == "dcom")
                return new Dica
                {
                    G = Gravidade.Info,
                    Explicacao = "Avisos de permissão DCOM (como o 10016) são comuns no Windows e quase sempre inofensivos.",
                    Solucao = "Nenhuma ação necessária na maioria dos casos."
                };
            if (p == "application error" || p == "application hang" || p == "windows error reporting")
                return new Dica
                {
                    Explicacao = "Programas travaram ou fecharam inesperadamente. O nome do programa aparece nos detalhes.",
                    Solucao = "Atualize ou reinstale o programa citado. Se for um jogo, verifique a integridade dos arquivos pela loja (Steam, Epic etc.) e atualize o driver de vídeo."
                };
            if (p == "display" || p.Contains("nvlddmkm") || p.Contains("amdkmdag") || p.Contains("amdwddmg") || p.Contains("igfx") || p.Contains("dxgkrnl"))
                return new Dica
                {
                    G = Gravidade.Aviso,
                    Explicacao = "O driver de vídeo parou de responder ou apresentou erro.",
                    Solucao = "Instale o driver de vídeo mais recente da NVIDIA, AMD ou Intel (com a opção de instalação limpa). Verifique a temperatura da placa de vídeo e remova overclock."
                };
            if (p.Contains("dns-client"))
                return new Dica
                {
                    G = Gravidade.Info,
                    Explicacao = "Falhas ao resolver nomes de sites (DNS).",
                    Solucao = "Se a internet estiver lenta ou falhando, reinicie o roteador ou configure um DNS público (ex.: 1.1.1.1 ou 8.8.8.8) nas configurações de rede.",
                    Comandos = new[] { "ipconfig /flushdns" }
                };
            if (p.Contains("windowsupdateclient"))
                return new Dica
                {
                    G = Gravidade.Aviso,
                    Explicacao = "Uma atualização do Windows falhou ao instalar.",
                    Solucao = "Abra o Windows Update e tente novamente. Se falhar de novo, use Configurações > Sistema > Solução de problemas > Outros solucionadores de problemas > Windows Update.",
                    Comandos = new[] { "start ms-settings:windowsupdate" }
                };
            if (p == ".net runtime")
                return new Dica
                {
                    Explicacao = "Um programa feito em .NET fechou por erro.",
                    Solucao = "Atualize ou reinstale o programa citado nos detalhes e mantenha o .NET atualizado pelo Windows Update."
                };
            if (p.Contains("netwtw") || p.StartsWith("e1") || p.StartsWith("rt6") || p.Contains("rtwlan") || p.Contains("tcpip") || p.Contains("netbt") || p.Contains("wlan") || p.Contains("ndis"))
                return new Dica
                {
                    G = Gravidade.Aviso,
                    Explicacao = "Problemas no adaptador ou na pilha de rede (Wi-Fi/Ethernet).",
                    Solucao = "Atualize o driver de rede pelo site do fabricante do notebook/placa-mãe (Intel, Realtek, MediaTek etc.).",
                    Comandos = new[] { "ncpa.cpl" }
                };
            if (p.Contains("defender"))
                return new Dica
                {
                    G = Gravidade.Aviso,
                    Explicacao = "O Microsoft Defender registrou erros.",
                    Solucao = "Abra Segurança do Windows, confira o histórico de proteção e atualize as definições de vírus.",
                    Comandos = new[] { "start windowsdefender:" }
                };
            if (p.Contains("time-service"))
                return new Dica
                {
                    G = Gravidade.Info,
                    Explicacao = "Falha ao sincronizar o relógio do Windows.",
                    Solucao = "Em Configurações > Hora e idioma > Data e hora, clique em \"Sincronizar agora\"."
                };
            if (p.Contains("volsnap"))
                return new Dica
                {
                    G = Gravidade.Info,
                    Explicacao = "Problemas com cópias de sombra (pontos de restauração/backup).",
                    Solucao = "Verifique se há espaço livre suficiente no disco e se a Proteção do Sistema está configurada corretamente."
                };
            if (p.Contains("user profile") || p.Contains("winlogon"))
                return new Dica
                {
                    Explicacao = "Problemas ao carregar o perfil do usuário ou durante o logon.",
                    Solucao = "Se o logon estiver lento ou com erros, verifique antivírus de terceiros e programas de inicialização. Rode a verificação de integridade (SFC/DISM) indicada no fim do relatório."
                };
            if (p == "tpm" || p.Contains("tpm-wmi"))
                return new Dica
                {
                    G = Gravidade.Aviso,
                    Explicacao = "O chip de segurança TPM (ou fTPM do processador) relatou erros. Ele é usado pelo BitLocker, Windows Hello e por antitrapaças de jogos.",
                    Solucao = "Atualize a BIOS/UEFI da placa-mãe (em AMD, versões novas corrigem problemas do fTPM) e o driver do chipset. Confira o estado do TPM com o comando abaixo. Se usa BitLocker, guarde a chave de recuperação antes de mexer na BIOS.",
                    Comandos = new[] { "tpm.msc" }
                };
            if (p == "microsoft-windows-kernel-boot" && ids.Contains(29))
                return new Dica
                {
                    G = Gravidade.Info,
                    Explicacao = "A Inicialização Rápida do Windows falhou e o PC iniciou do zero. Costuma vir junto com desligamentos inesperados.",
                    Solucao = "Normalmente não exige ação. Se o PC demora para ligar ou trava ao iniciar, desative a Inicialização Rápida em Painel de Controle > Opções de Energia > Escolher a função dos botões de energia.",
                    Comandos = new[] { "control /name Microsoft.PowerOptions" }
                };
            if (p.StartsWith("vbox"))
                return new Dica
                {
                    G = Gravidade.Info,
                    Explicacao = "Erros dos drivers de rede do VirtualBox.",
                    Solucao = "Atualize o VirtualBox para a versão mais recente. Se não usa mais o VirtualBox, desinstale-o."
                };
            return null;
        }

        void VerificarEventos()
        {
            var grupos = new Dictionary<string, GrupoEvento>(StringComparer.OrdinalIgnoreCase);
            string[] logs = { "System", "Application" };
            bool algumLido = false;
            foreach (string log in logs)
            {
                string nomeLog = log == "System" ? "Sistema" : "Aplicativo";
                var consulta = new EventLogQuery(log, PathType.LogName,
                    "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 604800000]]]");
                consulta.ReverseDirection = true; // mais recentes primeiro
                try
                {
                    using (var leitor = new EventLogReader(consulta))
                    {
                        algumLido = true;
                        int lidos = 0;
                        EventRecord e;
                        while (lidos < 4000 && (e = leitor.ReadEvent()) != null)
                        {
                            using (e)
                            {
                                lidos++;
                                string origem = e.ProviderName ?? "Desconhecida";
                                string chave = log + "|" + origem;
                                GrupoEvento g;
                                if (!grupos.TryGetValue(chave, out g))
                                {
                                    g = new GrupoEvento { Log = nomeLog, Origem = origem };
                                    grupos[chave] = g;
                                }
                                g.Total++;
                                int nivel = e.Level.HasValue ? e.Level.Value : 2;
                                if (nivel < g.MenorNivel) g.MenorNivel = nivel;
                                if (e.TimeCreated.HasValue && e.TimeCreated.Value > g.Ultimo) g.Ultimo = e.TimeCreated.Value;
                                long id = e.Id;
                                int c;
                                g.PorId.TryGetValue(id, out c);
                                g.PorId[id] = c + 1;

                                List<string> am;
                                if (!g.Amostras.TryGetValue(id, out am)) { am = new List<string>(); g.Amostras[id] = am; }
                                int tent;
                                g.Tentativas.TryGetValue(id, out tent);
                                if (am.Count < 3 && tent < 8)
                                {
                                    g.Tentativas[id] = tent + 1;
                                    string msg = null;
                                    try { msg = e.FormatDescription(); } catch { }
                                    if (string.IsNullOrWhiteSpace(msg))
                                    {
                                        try { msg = string.Join(" | ", e.Properties.Select(x => Convert.ToString(x.Value)).Where(x => !string.IsNullOrWhiteSpace(x)).Take(6)); } catch { }
                                    }
                                    msg = F.Corta(msg, 260);
                                    if (msg.Length > 0 && !am.Contains(msg)) am.Add(msg);
                                }
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { SemPermissao("Leitura do log " + nomeLog); }
                catch (EventLogException) { }
            }

            if (!algumLido) throw new SemPermissaoException("Visualizador de Eventos");

            if (grupos.Count == 0)
            {
                Add(Cat.Eventos, Gravidade.Ok, "Nenhum erro registrado nos últimos 7 dias",
                    "Os logs Sistema e Aplicativo não têm eventos de erro ou críticos na última semana.", null);
                return;
            }

            foreach (var g in grupos.Values.OrderBy(x => x.MenorNivel).ThenByDescending(x => x.Total))
            {
                Dica dica = DicaEvento(g.Origem, g.PorId.Keys);
                Gravidade grav;
                if (g.MenorNivel == 1) grav = Gravidade.Critico;
                else if (dica != null && dica.G.HasValue) grav = dica.G.Value;
                else grav = g.Total >= 10 ? Gravidade.Aviso : Gravidade.Info;

                string titulo = "\"" + g.Origem + "\" — " + g.Total + (g.Total == 1 ? " erro" : " erros");
                string desc = (dica != null ? dica.Explicacao + " " : "") +
                              "Log: " + g.Log + ". Última ocorrência: " + F.Data(g.Ultimo) + ".";
                string sol = dica != null ? dica.Solucao
                    : "Pesquise na internet a origem e o ID do evento mostrados (ex.: \"" + g.Origem + " evento " + g.PorId.Keys.First() + "\"). Se for de um programa específico, atualize ou reinstale esse programa. Para ver todos os detalhes, abra o Visualizador de Eventos.";
                var a = Add(Cat.Eventos, grav, titulo, desc, sol, dica != null && dica.Comandos != null ? dica.Comandos : new[] { "eventvwr.msc" });

                foreach (var kv in g.PorId.OrderByDescending(x => x.Value).Take(6))
                {
                    string linha = "ID " + kv.Key + " — " + kv.Value + "×";
                    List<string> am;
                    if (g.Amostras.TryGetValue(kv.Key, out am) && am.Count > 0)
                    {
                        for (int k = 0; k < am.Count; k++)
                            a.Detalhes.Add((k == 0 ? linha : "ID " + kv.Key + " (outro exemplo)") + ": " + am[k]);
                    }
                    else a.Detalhes.Add(linha);
                }
            }
        }

        // ------------------------------------------------------------------ Discos

        static string TipoMidia(long m, long bus)
        {
            string tipo = m == 3 ? "HDD" : m == 4 ? "SSD" : m == 5 ? "SCM" : "Disco";
            string b = bus == 17 ? "NVMe" : bus == 11 ? "SATA" : bus == 7 ? "USB" : bus == 8 ? "RAID" : bus == 10 ? "SAS" : bus == 3 ? "ATA" : bus == 6 ? "Fibre Channel" : bus == 9 ? "iSCSI" : bus == 12 ? "SD" : bus == 15 ? "Virtual" : null;
            return b != null ? tipo + " " + b : tipo;
        }

        void VerificarDiscos()
        {
            const string nsStorage = @"root\Microsoft\Windows\Storage";

            // Contadores de confiabilidade (exigem administrador)
            var confiab = new Dictionary<string, ManagementBaseObject>();
            try
            {
                foreach (var o in W.QS(nsStorage, "SELECT DeviceId, Temperature, TemperatureMax, Wear, ReadErrorsUncorrected, WriteErrorsUncorrected, PowerOnHours FROM MSFT_StorageReliabilityCounter"))
                {
                    string id = W.S(o, "DeviceId");
                    if (id != null) confiab[id] = o;
                }
            }
            catch (SemPermissaoException) { SemPermissao("Contadores SMART (temperatura, desgaste e erros dos discos)"); }

            // Previsão de falha SMART (exige administrador)
            int smartFalha = 0;
            try
            {
                foreach (var o in W.QS(@"root\wmi", "SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus"))
                {
                    if (W.B(o, "PredictFailure"))
                    {
                        smartFalha++;
                        Add(Cat.Discos, Gravidade.Critico, "SMART prevê falha de disco",
                            "O próprio disco está avisando que pode falhar em breve (" + W.S(o, "InstanceName") + ").",
                            "Faça backup de tudo imediatamente e planeje a troca do disco.");
                    }
                }
            }
            catch (SemPermissaoException) { SemPermissao("Previsão de falha SMART"); }

            var discos = W.QS(nsStorage, "SELECT DeviceId, FriendlyName, MediaType, BusType, HealthStatus, Size FROM MSFT_PhysicalDisk");
            foreach (var o in discos)
            {
                string nome = W.S(o, "FriendlyName") ?? "Disco";
                string id = W.S(o, "DeviceId");
                long saude = W.L(o, "HealthStatus");
                string tipo = TipoMidia(W.L(o, "MediaType"), W.L(o, "BusType"));
                string rotulo = nome + " (" + tipo + ", " + F.Bytes(W.L(o, "Size")) + ")";

                var detalhes = new List<string>();
                Gravidade grav = saude == 0 ? Gravidade.Ok : saude == 1 ? Gravidade.Aviso : Gravidade.Critico;
                ManagementBaseObject rc;
                if (id != null && confiab.TryGetValue(id, out rc))
                {
                    long temp = W.L(rc, "Temperature"), wear = W.L(rc, "Wear");
                    long errLeit = W.L(rc, "ReadErrorsUncorrected"), errEsc = W.L(rc, "WriteErrorsUncorrected");
                    long horas = W.L(rc, "PowerOnHours");
                    if (temp > 0) detalhes.Add("Temperatura: " + temp + " °C");
                    if (wear > 0) detalhes.Add("Desgaste (vida útil usada): " + wear + "%");
                    if (horas > 0) detalhes.Add("Horas ligado: " + horas.ToString("N0", F.BR));
                    if (errLeit + errEsc > 0) detalhes.Add("Erros não corrigidos: " + errLeit + " de leitura, " + errEsc + " de gravação");
                    if (wear >= 90 || errLeit + errEsc > 0) grav = Gravidade.Critico;
                    else if ((wear >= 70 || temp >= 65) && grav == Gravidade.Ok) grav = Gravidade.Aviso;
                }

                if (grav == Gravidade.Ok)
                {
                    var a = Add(Cat.Discos, Gravidade.Ok, "Disco saudável: " + rotulo, "O Windows informa que este disco está íntegro.", null);
                    a.Detalhes.AddRange(detalhes);
                }
                else
                {
                    var a = Add(Cat.Discos, grav, (grav == Gravidade.Critico ? "Disco com falha: " : "Disco com alerta: ") + rotulo,
                        "O estado de saúde informado é \"" + (saude == 0 ? "Íntegro" : saude == 1 ? "Aviso" : saude == 2 ? "Não íntegro" : "Desconhecido") + "\" ou os contadores SMART indicam desgaste/erros.",
                        "Faça backup dos dados importantes o quanto antes. Verifique o disco com a ferramenta do fabricante (ex.: Samsung Magician, WD Dashboard, Crucial Storage Executive) ou CrystalDiskInfo e planeje a substituição.",
                        "chkdsk C: /scan");
                    a.Detalhes.AddRange(detalhes);
                }
            }

            // Espaço livre
            foreach (var o in W.QS(W.Cimv2, "SELECT DeviceID, VolumeName, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3"))
            {
                double tam = W.L(o, "Size"), livre = W.L(o, "FreeSpace");
                if (tam < 2.0 * 1073741824) continue; // ignora partições pequenas (sistema/recuperação)
                string letra = W.S(o, "DeviceID");
                string vol = W.S(o, "VolumeName");
                double pct = livre / tam * 100;
                double livreGB = livre / 1073741824.0;
                string rotulo = letra + (string.IsNullOrEmpty(vol) ? "" : " (" + vol + ")");
                string resumo = F.Bytes(livre) + " livres de " + F.Bytes(tam) + " (" + F.Pct(pct) + ")";
                bool sistema = string.Equals(letra, Path.GetPathRoot(Environment.SystemDirectory).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

                Gravidade g;
                if (pct < 5 || livreGB < 5) g = Gravidade.Critico;
                else if (pct < 10 || livreGB < 15) g = Gravidade.Aviso;
                else g = Gravidade.Ok;

                if (g == Gravidade.Ok)
                {
                    Add(Cat.Discos, Gravidade.Ok, "Espaço livre adequado em " + rotulo, resumo + ".", null);
                }
                else
                {
                    string sol = sistema
                        ? "Libere espaço: ative o Sensor de Armazenamento (Configurações > Sistema > Armazenamento), use a Limpeza de Disco com \"Limpar arquivos do sistema\", esvazie a Lixeira e a pasta Downloads e desinstale programas e jogos que não usa. Pouco espaço no disco do Windows deixa o PC lento e impede atualizações."
                        : "Mova ou apague arquivos grandes que não usa, esvazie a Lixeira e desinstale jogos/programas desnecessários desta unidade.";
                    Add(Cat.Discos, g, "Pouco espaço livre em " + rotulo, resumo + ".", sol,
                        sistema ? new[] { "start ms-settings:storagesense", "cleanmgr /d " + letra.TrimEnd(':') } : new string[0]);
                }
            }

            if (discos.Count == 0 && smartFalha == 0)
                Add(Cat.Discos, Gravidade.Info, "Saúde dos discos não disponível",
                    "Não foi possível ler o estado de saúde dos discos físicos.", "Execute como administrador ou use CrystalDiskInfo para conferir o SMART.");
        }

        // ------------------------------------------------------------------ Windows Update

        void VerificarWindowsUpdate()
        {
            bool reinicio = Reg.Existe(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
                         || Reg.Existe(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
            // A reinicialização pendente é informada em "O PC precisa reiniciar" (Desempenho), com todos os motivos.

            foreach (var o in W.QS(W.Cimv2, "SELECT StartMode, State FROM Win32_Service WHERE Name = 'wuauserv'"))
            {
                if (string.Equals(W.S(o, "StartMode"), "Disabled", StringComparison.OrdinalIgnoreCase))
                    Add(Cat.Atualizacoes, Gravidade.Critico, "Serviço do Windows Update desativado",
                        "O serviço \"Windows Update\" (wuauserv) está desativado, então o PC não recebe correções de segurança.",
                        "Abra services.msc, localize \"Windows Update\" e mude o tipo de inicialização para \"Manual\". Se um programa \"bloqueador de updates\" fez isso, desinstale-o.",
                        "services.msc");
            }

            // Data da última atualização instalada
            DateTime? ultima = null;
            var us = CultureInfo.GetCultureInfo("en-US");
            foreach (var o in W.QS(W.Cimv2, "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"))
            {
                string s = W.S(o, "InstalledOn");
                DateTime d;
                if (!string.IsNullOrEmpty(s) && DateTime.TryParse(s, us, DateTimeStyles.None, out d) && d <= DateTime.Now.AddDays(1))
                    if (!ultima.HasValue || d > ultima.Value) ultima = d;
            }

            // Busca de atualizações pendentes pela API do Windows Update (somente consulta)
            var titulos = new List<string>();
            int criticas = 0, drivers = 0, total = 0;
            string erro = null;
            var t = new Thread(() =>
            {
                try
                {
                    Type tipo = Type.GetTypeFromProgID("Microsoft.Update.Session");
                    dynamic sessao = Activator.CreateInstance(tipo);
                    sessao.ClientApplicationID = "PC Diagnostico";
                    dynamic busca = sessao.CreateUpdateSearcher();
                    dynamic res = busca.Search("IsInstalled=0 and IsHidden=0");
                    int n = res.Updates.Count;
                    for (int i = 0; i < n; i++)
                    {
                        dynamic u = res.Updates.Item(i);
                        string titulo = u.Title;
                        string sev = null;
                        try { sev = u.MsrcSeverity; } catch { }
                        int tipoU = 1;
                        try { tipoU = (int)u.Type; } catch { }
                        if (tipoU == 2) drivers++;
                        if (string.Equals(sev, "Critical", StringComparison.OrdinalIgnoreCase) || string.Equals(sev, "Important", StringComparison.OrdinalIgnoreCase)) criticas++;
                        titulos.Add(titulo + (sev != null ? "  [" + (sev == "Critical" ? "Crítica" : sev == "Important" ? "Importante" : sev == "Moderate" ? "Moderada" : sev == "Low" ? "Baixa" : sev) + "]" : "") + (tipoU == 2 ? "  [Driver]" : ""));
                    }
                    total = n;
                }
                catch (Exception ex) { erro = ex.Message; }
            });
            t.IsBackground = true;
            t.Start();
            bool terminou = t.Join(TimeSpan.FromSeconds(150));

            if (!terminou)
            {
                Add(Cat.Atualizacoes, Gravidade.Info, "A busca por atualizações demorou demais",
                    "O Windows Update não respondeu em 2 minutos e meio (pode estar sem internet ou ocupado).",
                    "Abra o Windows Update e clique em \"Verificar se há atualizações\".", "start ms-settings:windowsupdate");
            }
            else if (erro != null)
            {
                Add(Cat.Atualizacoes, Gravidade.Info, "Não foi possível consultar o Windows Update",
                    "Erro: " + F.Corta(erro, 200),
                    "Verifique a conexão com a internet e abra o Windows Update manualmente.", "start ms-settings:windowsupdate");
            }
            else if (total > 0)
            {
                var a = Add(Cat.Atualizacoes, criticas > 0 ? Gravidade.Critico : Gravidade.Aviso,
                    total + (total == 1 ? " atualização pendente" : " atualizações pendentes"),
                    (criticas > 0 ? criticas + " delas são de segurança críticas ou importantes. " : "") +
                    (drivers > 0 ? drivers + " são de drivers. " : "") +
                    "Atualizações corrigem falhas de segurança e bugs.",
                    "Abra Configurações > Windows Update e instale as atualizações. As de driver ficam em Opções avançadas > Atualizações opcionais.",
                    "start ms-settings:windowsupdate");
                a.Detalhes.AddRange(titulos);
            }
            else
            {
                Add(Cat.Atualizacoes, Gravidade.Ok, "Windows atualizado", "Nenhuma atualização pendente foi encontrada.", null);
            }

            if (ultima.HasValue)
            {
                double dias = (DateTime.Now - ultima.Value).TotalDays;
                if (dias > 60)
                    Add(Cat.Atualizacoes, Gravidade.Aviso, "Nenhuma atualização instalada há " + (int)dias + " dias",
                        "A última atualização do Windows foi instalada em " + F.Dia(ultima.Value) + ". O Windows recebe correções de segurança todo mês.",
                        "Abra o Windows Update, verifique se as atualizações não estão pausadas e instale as pendentes.", "start ms-settings:windowsupdate");
                else
                    Add(Cat.Atualizacoes, Gravidade.Ok, "Atualizações recentes instaladas", "Última atualização instalada em " + F.Dia(ultima.Value) + ".", null);
            }
        }

        // ------------------------------------------------------------------ Segurança

        void VerificarSeguranca()
        {
            // Antivírus via Central de Segurança
            var avsAtivos = new List<string>();
            var avsDesatualizados = new List<string>();
            var avsInativos = new List<string>();
            bool scLido = false;
            try
            {
                foreach (var o in W.Q(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
                {
                    scLido = true;
                    long st = W.L(o, "productState");
                    string nome = W.S(o, "displayName") ?? "Antivírus";
                    bool ativo = ((st >> 12) & 0xF) == 1;
                    bool atualizado = ((st >> 4) & 0xF) == 0;
                    if (ativo) avsAtivos.Add(nome); else avsInativos.Add(nome);
                    if (ativo && !atualizado) avsDesatualizados.Add(nome);
                }
            }
            catch (SemPermissaoException) { SemPermissao("Central de Segurança (antivírus)"); }
            catch { }

            // Microsoft Defender
            ManagementBaseObject mp = null;
            try { mp = W.QS(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus").FirstOrDefault(); }
            catch (SemPermissaoException) { }

            bool defenderAtivo = avsAtivos.Any(x => x.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) >= 0);
            if (mp != null && !scLido && W.B(mp, "AntivirusEnabled")) { defenderAtivo = true; avsAtivos.Add("Microsoft Defender Antivirus"); }

            if (avsAtivos.Count == 0 && (scLido || mp != null))
            {
                var a = Add(Cat.Seguranca, Gravidade.Critico, "Nenhum antivírus ativo",
                    "O PC está sem proteção contra vírus e malware em tempo real.",
                    "Abra Segurança do Windows > Proteção contra vírus e ameaças e ative a proteção em tempo real, ou reative/reinstale seu antivírus.",
                    "start windowsdefender:");
                foreach (var n in avsInativos) a.Detalhes.Add("Instalado, mas desativado: " + n);
            }
            else if (avsAtivos.Count > 0)
            {
                Add(Cat.Seguranca, Gravidade.Ok, "Antivírus ativo: " + string.Join(", ", avsAtivos), "A proteção contra vírus está ligada.", null);
            }

            foreach (var n in avsDesatualizados)
                Add(Cat.Seguranca, Gravidade.Aviso, "Antivírus desatualizado: " + n, "As definições de vírus estão desatualizadas.",
                    "Abra o antivírus e atualize as definições (no Defender: Segurança do Windows > Proteção contra vírus e ameaças > Atualizações de proteção).",
                    "start windowsdefender:");

            if (mp != null && defenderAtivo)
            {
                if (!W.B(mp, "RealTimeProtectionEnabled"))
                    Add(Cat.Seguranca, Gravidade.Critico, "Proteção em tempo real do Defender desligada",
                        "O Microsoft Defender está instalado, mas não verifica arquivos em tempo real.",
                        "Abra Segurança do Windows > Proteção contra vírus e ameaças > Gerenciar configurações e ative a \"Proteção em tempo real\".",
                        "start windowsdefender:");
                long idade = W.L(mp, "AntivirusSignatureAge");
                if (idade > 7 && idade < 60000)
                    Add(Cat.Seguranca, Gravidade.Aviso, "Definições do Defender com " + idade + " dias",
                        "As definições de vírus não são atualizadas há mais de uma semana.",
                        "Abra Segurança do Windows > Proteção contra vírus e ameaças > Atualizações de proteção > Verificar atualizações.",
                        "start windowsdefender:");
                object tamper = W.V(mp, "IsTamperProtected");
                if (tamper is bool && !(bool)tamper)
                    Add(Cat.Seguranca, Gravidade.Info, "Proteção contra adulteração desligada",
                        "Sem ela, programas maliciosos podem desativar o Defender.",
                        "Segurança do Windows > Proteção contra vírus e ameaças > Gerenciar configurações > ative \"Proteção contra adulteração\".",
                        "start windowsdefender:");
            }

            // Firewall
            var fwTerceiros = new List<string>();
            try
            {
                foreach (var o in W.QS(@"root\SecurityCenter2", "SELECT displayName, productState FROM FirewallProduct"))
                    if (((W.L(o, "productState") >> 12) & 0xF) == 1) fwTerceiros.Add(W.S(o, "displayName"));
            }
            catch (SemPermissaoException) { }

            var perfisDesligados = new List<string>();
            var perfisLidos = 0;
            try
            {
                foreach (var o in W.QS(@"root\StandardCimv2", "SELECT Name, Enabled FROM MSFT_NetFirewallProfile"))
                {
                    perfisLidos++;
                    if (W.L(o, "Enabled") == 0) perfisDesligados.Add(NomePerfil(W.S(o, "Name")));
                }
            }
            catch (SemPermissaoException) { }
            if (perfisLidos == 0)
            {
                string[,] perfis = { { "DomainProfile", "Domain" }, { "StandardProfile", "Private" }, { "PublicProfile", "Public" } };
                for (int i = 0; i < perfis.GetLength(0); i++)
                {
                    int? v = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + perfis[i, 0], "EnableFirewall");
                    if (v.HasValue) { perfisLidos++; if (v.Value == 0) perfisDesligados.Add(NomePerfil(perfis[i, 1])); }
                }
            }
            if (perfisDesligados.Count > 0 && fwTerceiros.Count == 0)
            {
                var a = Add(Cat.Seguranca, Gravidade.Critico, "Firewall do Windows desligado",
                    "O firewall está desligado em: " + string.Join(", ", perfisDesligados) + ". Sem firewall, o PC fica exposto a ataques pela rede.",
                    "Abra Segurança do Windows > Firewall e proteção de rede e ative o firewall em todos os perfis.",
                    "start windowsdefender://network");
            }
            else if (perfisLidos > 0 || fwTerceiros.Count > 0)
            {
                Add(Cat.Seguranca, Gravidade.Ok, "Firewall ativo" + (fwTerceiros.Count > 0 ? ": " + string.Join(", ", fwTerceiros) : ""),
                    "O PC está protegido por firewall.", null);
            }

            // UAC
            int? lua = Reg.Int(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
            int? consent = Reg.Int(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
            if (lua.HasValue && lua.Value == 0)
                Add(Cat.Seguranca, Gravidade.Aviso, "Controle de Conta de Usuário (UAC) desativado",
                    "Programas podem obter privilégios de administrador sem pedir permissão.",
                    "Abra \"Alterar configurações de Controle de Conta de Usuário\" e coloque o controle em um nível acima de \"Nunca notificar\". Requer reiniciar.",
                    "UserAccountControlSettings.exe");
            else if (consent.HasValue && consent.Value == 0)
                Add(Cat.Seguranca, Gravidade.Aviso, "UAC configurado para nunca notificar",
                    "Programas de administrador são elevados sem nenhum aviso.",
                    "Abra as configurações do UAC e escolha o nível padrão (\"Notificar somente quando aplicativos tentarem fazer alterações\").",
                    "UserAccountControlSettings.exe");
            else if (lua.HasValue)
                Add(Cat.Seguranca, Gravidade.Ok, "Controle de Conta de Usuário (UAC) ativo", "Elevações de privilégio pedem confirmação.", null);

            // Secure Boot
            int? sb = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            if (sb.HasValue && sb.Value == 0)
                Add(Cat.Seguranca, Gravidade.Info, "Inicialização Segura (Secure Boot) desligada",
                    "O Secure Boot impede que malwares de inicialização (bootkits) sejam carregados. Alguns jogos com antitrapaça exigem que ele esteja ativo.",
                    "Ative o Secure Boot na configuração da UEFI/BIOS do PC (consulte o manual da placa-mãe). Não mude se você usa sistemas que dependem dele desligado.",
                    "msinfo32");
            else if (sb.HasValue)
                Add(Cat.Seguranca, Gravidade.Ok, "Inicialização Segura (Secure Boot) ativa", "O PC inicia apenas com carregadores assinados.", null);
        }

        static string NomePerfil(string n)
        {
            if (n == null) return "?";
            if (n.Equals("Domain", StringComparison.OrdinalIgnoreCase)) return "Domínio";
            if (n.Equals("Private", StringComparison.OrdinalIgnoreCase)) return "Privada";
            if (n.Equals("Public", StringComparison.OrdinalIgnoreCase)) return "Pública";
            return n;
        }

        // ------------------------------------------------------------------ Desempenho

        static readonly string[] AppsPesados =
        {
            "teams", "discord", "steam", "epicgames", "epic games", "spotify", "adobe", "creative cloud", "battle.net",
            "ubisoft", "eadesktop", "ea app", "origin", "opera", "skype", "zoom", "dropbox", "googledrive", "google drive",
            "razer", "icue", "armoury", "wallpaper", "riot", "whatsapp", "telegram", "utorrent", "bittorrent", "qbittorrent",
            "overwolf", "gog galaxy", "ccleaner", "logi", "lghub", "msi center", "dragon center", "nahimic", "corsair",
            "steelseries", "medal", "outplayed", "parsec", "anydesk", "teamviewer", "onedrive", "icloud", "hp smart", "mcafee", "norton", "avast", "avg"
        };

        HashSet<string> InicializacaoDesativada()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] subs = { "Run", "Run32", "StartupFolder" };
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                foreach (var s in subs)
                {
                    try
                    {
                        using (var b = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                        using (var k = b.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\" + s))
                        {
                            if (k == null) continue;
                            foreach (var nome in k.GetValueNames())
                            {
                                var v = k.GetValue(nome) as byte[];
                                if (v != null && v.Length > 0 && (v[0] & 1) == 1) set.Add(nome);
                            }
                        }
                    }
                    catch { }
                }
            }
            return set;
        }

        void VerificarDesempenho()
        {
            // Memória
            if (memTotalKB > 0)
            {
                double usado = 100.0 * (memTotalKB - memLivreKB) / memTotalKB;
                double totalGB = memTotalKB / 1048576.0;
                var top = new List<string>();
                try
                {
                    var procs = Process.GetProcesses();
                    top = procs.GroupBy(p => p.ProcessName)
                        .Select(gp => new { Nome = gp.Key, Mem = gp.Sum(p => { try { return p.WorkingSet64; } catch { return 0L; } }), Qtd = gp.Count() })
                        .OrderByDescending(x => x.Mem).Take(8)
                        .Select(x => x.Nome + (x.Qtd > 1 ? " (" + x.Qtd + " processos)" : "") + ": " + F.Bytes(x.Mem)).ToList();
                    foreach (var p in procs) p.Dispose();
                }
                catch { }

                Gravidade g = usado >= 95 ? Gravidade.Critico : usado >= 85 ? Gravidade.Aviso : Gravidade.Ok;
                string desc = "Em uso agora: " + F.Pct(usado) + " de " + F.Bytes(memTotalKB * 1024.0) + " (" + F.Bytes(memLivreKB * 1024.0) + " livres).";
                Achado a;
                if (g == Gravidade.Ok)
                    a = Add(Cat.Desempenho, Gravidade.Ok, "Uso de memória RAM normal", desc, null);
                else
                    a = Add(Cat.Desempenho, g, "Uso de memória RAM alto (" + F.Pct(usado) + ")", desc + " Com a memória cheia, o Windows usa o disco como memória e fica lento.",
                        "Feche programas e abas do navegador que não está usando. Veja abaixo quem mais consome e reduza os programas que iniciam com o Windows. Se acontecer sempre, considere aumentar a RAM.",
                        "taskmgr");
                if (top.Count > 0) { a.Detalhes.Add("Programas que mais usam memória agora:"); a.Detalhes.AddRange(top); }

                if (totalGB < 7.5)
                    Add(Cat.Desempenho, Gravidade.Aviso, "Pouca memória RAM instalada (" + F.Bytes(memTotalKB * 1024.0) + ")",
                        "O Windows 11 funciona melhor com pelo menos 8 GB; para jogos e muitos programas abertos, 16 GB.",
                        "Considere um upgrade de memória. Verifique no manual do PC/placa-mãe o tipo (DDR4/DDR5) e quantos slots estão livres.");
            }

            // Programas de inicialização
            var ativos = new List<string>();
            int pesados = 0;
            foreach (var it in Inicializacao.Where(x => x.Ativo))
            {
                if (it.Pesado) pesados++;
                ativos.Add(it.Nome + (it.Pesado ? "  — costuma pesar na inicialização" : "") + "  (" + F.Corta(it.Comando, 120) + ")");
            }
            if (ativos.Count > 0)
            {
                Gravidade g = ativos.Count >= 12 || pesados >= 5 ? Gravidade.Aviso : Gravidade.Info;
                var a = Add(Cat.Desempenho, g, ativos.Count + " programas iniciam com o Windows" + (pesados > 0 ? " (" + pesados + " pesados)" : ""),
                    "Cada programa que inicia junto com o Windows deixa a inicialização mais lenta e consome memória o tempo todo.",
                    "Desative os que você não precisa logo ao ligar o PC: Gerenciador de Tarefas > Aplicativos de inicialização (ou Configurações > Aplicativos > Inicialização). Desativar não desinstala o programa.",
                    "start ms-settings:startupapps");
                a.Detalhes.AddRange(ativos.OrderByDescending(x => x.Contains("costuma pesar")).ThenBy(x => x));
            }

            // Tempo ligado
            if (ultimoBoot.HasValue)
            {
                var up = DateTime.Now - ultimoBoot.Value;
                if (up.TotalDays >= 7)
                    Add(Cat.Desempenho, Gravidade.Info, "PC ligado há " + F.Duracao(up) + " sem reiniciar",
                        "O Inicializador Rápido faz o \"Desligar\" não reiniciar o Windows de verdade. Reiniciar de vez em quando libera memória e conclui atualizações.",
                        "Use \"Reiniciar\" (e não \"Desligar\") pelo menos uma vez por semana.");
            }
        }

        // ------------------------------------------------------------------ Energia / bateria / temperatura

        void VerificarEnergia()
        {
            // Bateria
            var baterias = W.QS(W.Cimv2, "SELECT Name, EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery");
            temBateria = baterias.Count > 0;
            if (temBateria)
            {
                long projetada = 0, cheia = 0;
                try { foreach (var o in W.QS(@"root\wmi", "SELECT DesignedCapacity FROM BatteryStaticData")) projetada += W.L(o, "DesignedCapacity"); } catch (SemPermissaoException) { }
                try { foreach (var o in W.QS(@"root\wmi", "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity")) cheia += W.L(o, "FullChargedCapacity"); } catch (SemPermissaoException) { }
                long carga = W.L(baterias[0], "EstimatedChargeRemaining");
                if (projetada > 0 && cheia > 0)
                {
                    double saude = Math.Min(100.0, 100.0 * cheia / projetada);
                    saudeBateria = saude;
                    Gravidade g = saude < 50 ? Gravidade.Critico : saude < 70 ? Gravidade.Aviso : Gravidade.Ok;
                    var a = g == Gravidade.Ok
                        ? Add(Cat.Energia, Gravidade.Ok, "Bateria saudável (" + F.Pct(saude) + " da capacidade original)", "Carga atual: " + carga + "%.", null)
                        : Add(Cat.Energia, g, "Bateria desgastada (" + F.Pct(saude) + " da capacidade original)",
                            "A bateria segura bem menos carga do que quando era nova. Carga atual: " + carga + "%.",
                            "Gere o relatório de bateria do Windows com o comando abaixo para ver o histórico. Se a autonomia estiver ruim, considere trocar a bateria (assistência autorizada). Evite deixar o notebook sempre a 100% no calor.",
                            "powercfg /batteryreport");
                    a.Detalhes.Add("Capacidade original: " + projetada.ToString("N0", F.BR) + " mWh");
                    a.Detalhes.Add("Capacidade atual (carga completa): " + cheia.ToString("N0", F.BR) + " mWh");
                }
                else
                {
                    Add(Cat.Energia, Gravidade.Info, "Bateria detectada (carga " + carga + "%)",
                        "Não foi possível ler a capacidade original da bateria para calcular o desgaste.",
                        "Gere o relatório de bateria do Windows para ver capacidade e histórico.", "powercfg /batteryreport");
                }
            }

            // Plano de energia
            string plano = null;
            foreach (var o in W.QS(@"root\cimv2\power", "SELECT ElementName FROM Win32_PowerPlan WHERE IsActive = TRUE"))
                plano = W.S(o, "ElementName");
            string sobreposicao = null;
            string ov = Reg.Valor(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes", "ActiveOverlayAcPowerScheme") as string;
            if (ov != null)
            {
                ov = ov.ToLowerInvariant();
                if (ov.StartsWith("961cc777")) sobreposicao = "Melhor eficiência de energia";
                else if (ov.StartsWith("ded574b5")) sobreposicao = "Melhor desempenho";
                else if (ov.StartsWith("00000000")) sobreposicao = "Equilibrado";
            }
            if (plano != null)
            {
                string p = plano.ToLowerInvariant();
                bool economia = p.Contains("economia") || p.Contains("power saver") || (sobreposicao != null && sobreposicao.Contains("eficiência"));
                string desc = "Plano ativo: \"" + plano + "\"" + (sobreposicao != null ? ", modo de energia (na tomada): \"" + sobreposicao + "\"" : "") + ".";
                if (economia && !temBateria)
                    Add(Cat.Energia, Gravidade.Aviso, "PC de mesa em modo de economia de energia", desc + " Isso reduz o desempenho do processador sem necessidade em um PC de mesa.",
                        "Em Configurações > Sistema > Energia, mude o \"Modo de energia\" para \"Equilibrado\" ou \"Melhor desempenho\".", "start ms-settings:powersleep");
                else
                    Add(Cat.Energia, Gravidade.Info, "Plano de energia: " + plano, desc + (temBateria
                            ? " Em notebooks, \"Equilibrado\" é o melhor meio-termo; use \"Melhor desempenho\" na tomada para jogos."
                            : " Para jogos ou trabalho pesado, \"Melhor desempenho\" pode ajudar um pouco."),
                        "Ajuste em Configurações > Sistema > Energia > Modo de energia.", "start ms-settings:powersleep");
            }

            // Temperatura (zonas térmicas ACPI)
            var temps = new List<Tuple<string, double>>();
            foreach (var o in W.QS(W.Cimv2, "SELECT Name, Temperature, HighPrecisionTemperature FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation"))
            {
                double k = W.L(o, "HighPrecisionTemperature") > 0 ? W.L(o, "HighPrecisionTemperature") / 10.0 : W.L(o, "Temperature");
                if (k > 200) temps.Add(Tuple.Create(W.S(o, "Name"), k - 273.15));
            }
            if (temps.Count == 0)
            {
                try
                {
                    foreach (var o in W.QS(@"root\wmi", "SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"))
                    {
                        double k = W.L(o, "CurrentTemperature") / 10.0;
                        if (k > 200) temps.Add(Tuple.Create(W.S(o, "InstanceName"), k - 273.15));
                    }
                }
                catch (SemPermissaoException) { SemPermissao("Temperatura (zonas térmicas ACPI)"); }
            }
            // Ignora leituras absurdas (sensores fictícios)
            temps = temps.Where(x => x.Item2 >= 25 && x.Item2 < 125).ToList(); // abaixo de 25 °C costuma ser valor fixo de BIOS, não leitura real
            if (temps.Count > 0)
            {
                double max = temps.Max(x => x.Item2);
                tempMax = max;
                Gravidade g = max >= 90 ? Gravidade.Critico : max >= 80 ? Gravidade.Aviso : Gravidade.Ok;
                var a = g == Gravidade.Ok
                    ? Add(Cat.Energia, Gravidade.Ok, "Temperatura normal (" + max.ToString("0", F.BR) + " °C)", "Leitura dos sensores térmicos da placa (ACPI) no momento do diagnóstico.", null)
                    : Add(Cat.Energia, g, "Temperatura alta (" + max.ToString("0", F.BR) + " °C)",
                        "Os sensores térmicos indicam aquecimento acima do ideal. Calor excessivo causa lentidão (throttling), travamentos e desligamentos.",
                        "Limpe a poeira de ventoinhas e dissipadores, garanta boa ventilação (não use o notebook sobre cama/almofada), verifique se as ventoinhas giram e, em PCs com alguns anos, troque a pasta térmica.");
                foreach (var t in temps) a.Detalhes.Add((t.Item1 ?? "Zona") + ": " + t.Item2.ToString("0.0", F.BR) + " °C");
                a.Detalhes.Add("Obs.: zonas ACPI não são exatamente a temperatura do processador. Para leituras precisas use HWiNFO ou o app do fabricante.");
            }
            else
            {
                Add(Cat.Energia, Gravidade.Info, "Temperatura não disponível",
                    "Este PC não expõe sensores de temperatura pelo Windows (comum em PCs de mesa).",
                    "Para monitorar CPU e GPU, use um programa como HWiNFO, o app do fabricante da placa-mãe ou o painel da placa de vídeo.");
            }
        }

        // ------------------------------------------------------------------ Integridade

        void VerificarIntegridade()
        {
            int dumps = 0;
            DateTime? ultimoDump = null;
            try
            {
                string dir = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "Minidump");
                if (Directory.Exists(dir))
                {
                    foreach (var f in new DirectoryInfo(dir).GetFiles("*.dmp"))
                    {
                        if ((DateTime.Now - f.LastWriteTime).TotalDays <= 30)
                        {
                            dumps++;
                            if (!ultimoDump.HasValue || f.LastWriteTime > ultimoDump.Value) ultimoDump = f.LastWriteTime;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { SemPermissao("Arquivos de tela azul (C:\\Windows\\Minidump)"); }
            catch { }

            if (dumps > 0)
            {
                houveTelaAzul = true;
                Add(Cat.Integridade, Gravidade.Critico, dumps + (dumps == 1 ? " tela azul" : " telas azuis") + " nos últimos 30 dias",
                    "Foram encontrados arquivos de despejo de memória em C:\\Windows\\Minidump. Última em " + F.Data(ultimoDump.Value) + ".",
                    "Analise os arquivos com WinDbg (Microsoft Store) ou BlueScreenView para descobrir o driver responsável e atualize-o. Teste também a RAM.",
                    "mdsched.exe");
            }

            bool suspeita = houveTelaAzul || houveErroDisco || houveErroHardware;
            var a = Add(Cat.Integridade, suspeita ? Gravidade.Aviso : Gravidade.Info,
                suspeita ? "Recomendado verificar a integridade dos arquivos do Windows" : "Verificação de integridade do Windows (opcional)",
                (suspeita ? "Foram encontrados sinais de instabilidade (telas azuis, erros de disco ou de hardware). " : "Nenhum sinal forte de corrupção foi encontrado. ") +
                "O SFC e o DISM verificam e reparam arquivos de sistema corrompidos. Este programa não os executa: rode-os você mesmo, se quiser.",
                "Abra o Terminal como administrador (clique com o botão direito no Iniciar > Terminal (Admin)) e execute os comandos abaixo, nesta ordem. Cada um pode levar de 5 a 20 minutos. O primeiro só verifica; o segundo repara a imagem do Windows (precisa de internet); o terceiro repara os arquivos de sistema.",
                "DISM /Online /Cleanup-Image /CheckHealth",
                "DISM /Online /Cleanup-Image /RestoreHealth",
                "sfc /scannow");
            if (houveErroDisco) a.Comandos.Add("chkdsk C: /scan");
        }
    }
}
