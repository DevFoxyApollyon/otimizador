using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PcDiagnostico
{
    partial class Diagnostico
    {
        // ------------------------------------------------------------------ Contas, BitLocker, TPM, SMBv1, RDP

        void VerificarContasEAcesso()
        {
            VerificarBitLocker();
            VerificarTpm();
            VerificarContas();

            // SMBv1
            bool smb1 = false; string origemSmb = null;
            try
            {
                foreach (var o in W.QS(W.Cimv2, "SELECT Name, InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol' OR Name = 'SMB1Protocol-Server' OR Name = 'SMB1Protocol-Client'"))
                    if (W.L(o, "InstallState") == 1) { smb1 = true; origemSmb = "Recurso do Windows \"" + W.S(o, "Name") + "\" instalado"; }
            }
            catch (SemPermissaoException) { }
            int? smbSrv = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
            if (smbSrv.HasValue && smbSrv.Value == 1) { smb1 = true; origemSmb = "SMB1=1 no servidor de arquivos"; }
            int? mrx = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start");
            if (mrx.HasValue && mrx.Value != 4) { smb1 = true; origemSmb = origemSmb ?? "Driver cliente SMBv1 (mrxsmb10) ativo"; }
            if (smb1)
                Add(Cat.Rede, Gravidade.Aviso, "SMBv1 ativado",
                    "O SMBv1 é um protocolo de compartilhamento antigo e inseguro, explorado por ransomwares como o WannaCry. " + origemSmb + ".",
                    "Desative em \"Ativar ou desativar recursos do Windows\" > desmarque \"Suporte para Compartilhamento de Arquivos SMB 1.0/CIFS\" (ou use o modo de melhorias do PCDiagnostico). Só mantenha se usar um aparelho muito antigo que exige SMBv1.",
                    "optionalfeatures.exe");
            else
                Add(Cat.Rede, Gravidade.Ok, "SMBv1 desativado", "O protocolo antigo e inseguro SMBv1 não está ativo.", null);

            // RDP
            int? deny = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
            if (deny.HasValue && deny.Value == 0)
            {
                int? nla = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
                int? porta = Reg.Int(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber");
                bool semNla = nla.HasValue && nla.Value == 0;
                Add(Cat.Rede, semNla ? Gravidade.Critico : Gravidade.Aviso, "Área de Trabalho Remota (RDP) ativada",
                    "Outras pessoas podem tentar acessar este PC pela rede na porta " + (porta ?? 3389) + "." + (semNla ? " A Autenticação no Nível da Rede (NLA) está DESLIGADA, o que facilita ataques." : ""),
                    "Se você não usa acesso remoto, desative em Configurações > Sistema > Área de Trabalho Remota. Se usa, mantenha a NLA ligada, use senha forte e nunca exponha a porta 3389 na internet (prefira VPN).",
                    "start ms-settings:remotedesktop");
            }
            else if (deny.HasValue)
                Add(Cat.Rede, Gravidade.Ok, "Área de Trabalho Remota (RDP) desativada", "O PC não aceita conexões de área de trabalho remota.", null);
        }

        void VerificarBitLocker()
        {
            string sistema = Path.GetPathRoot(Environment.SystemDirectory).TrimEnd('\\');
            int? prot = null; string metodo = null;
            try
            {
                foreach (var o in W.Q(@"root\cimv2\Security\MicrosoftVolumeEncryption", "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume"))
                    if (string.Equals(W.S(o, "DriveLetter"), sistema, StringComparison.OrdinalIgnoreCase)) { prot = (int)W.L(o, "ProtectionStatus"); metodo = "WMI"; }
            }
            catch { }
            if (!prot.HasValue)
            {
                // Sem administrador: propriedade do Shell (1 = ligado, 2 = desligado, 3 = criptografando, 4 = descriptografando, 5 = suspenso, 6 = ligado/bloqueado)
                try
                {
                    dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application"));
                    object v = sh.NameSpace(sistema + "\\").Self.ExtendedProperty("System.Volume.BitLockerProtection");
                    if (v != null)
                    {
                        int s = Convert.ToInt32(v);
                        prot = s == 1 || s == 3 || s == 6 ? 1 : s == 5 ? 2 : 0;
                        metodo = "Shell";
                    }
                }
                catch { }
            }
            if (!prot.HasValue)
            {
                Add(Cat.Seguranca, Gravidade.Info, "Estado do BitLocker não disponível",
                    "Não foi possível ler o estado da criptografia do disco " + sistema + ".", "Execute como administrador ou confira em Configurações > Privacidade e segurança > Criptografia do dispositivo.");
                return;
            }
            if (prot.Value == 1)
                Add(Cat.Seguranca, Gravidade.Ok, "Disco do sistema criptografado (BitLocker)",
                    "Se o PC for roubado, os dados de " + sistema + " ficam protegidos. Guarde a chave de recuperação em local seguro (conta Microsoft ou papel).", null);
            else
                Add(Cat.Seguranca, prot.Value == 2 ? Gravidade.Aviso : Gravidade.Info, prot.Value == 2 ? "BitLocker suspenso" : "Disco do sistema sem criptografia (BitLocker desligado)",
                    prot.Value == 2 ? "A criptografia existe, mas a proteção está suspensa (comum durante atualizações de BIOS)." :
                    "Sem criptografia, quem tiver acesso físico ao disco consegue ler seus arquivos. Mais importante em notebooks.",
                    prot.Value == 2 ? "Retome a proteção no Painel de Controle > Criptografia de Unidade de Disco BitLocker." :
                    "Se quiser proteger os dados, ative a Criptografia do dispositivo (Windows Home) ou o BitLocker (Windows Pro). Antes, salve a chave de recuperação.",
                    "control /name Microsoft.BitLockerDriveEncryption");
        }

        void VerificarTpm()
        {
            try
            {
                var l = W.Q(@"root\cimv2\Security\MicrosoftTpm", "SELECT IsEnabled_InitialValue, IsActivated_InitialValue, SpecVersion, ManufacturerVersion FROM Win32_Tpm");
                if (l.Count == 0)
                {
                    Add(Cat.Seguranca, Gravidade.Aviso, "TPM não encontrado",
                        "O Windows 11 exige TPM 2.0. Sem ele, BitLocker e Windows Hello ficam limitados e alguns jogos com antitrapaça não funcionam.",
                        "Ative o TPM na UEFI/BIOS (opção \"fTPM\" em AMD ou \"PTT\" em Intel).", "tpm.msc");
                    return;
                }
                var t = l[0];
                string spec = (W.S(t, "SpecVersion") ?? "").Split(',')[0].Trim();
                bool ok = W.B(t, "IsEnabled_InitialValue") && W.B(t, "IsActivated_InitialValue");
                Add(Cat.Seguranca, ok ? Gravidade.Ok : Gravidade.Aviso, ok ? "TPM " + spec + " ativo" : "TPM presente mas desativado",
                    "Versão do firmware do TPM: " + W.S(t, "ManufacturerVersion") + ".",
                    ok ? null : "Ative o TPM na UEFI/BIOS.", ok ? new string[0] : new[] { "tpm.msc" });
                return;
            }
            catch (SemPermissaoException) { }
            catch { }
            // Sem administrador: procura o dispositivo TPM no Gerenciador de Dispositivos
            var dev = W.QS(W.Cimv2, "SELECT Name, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPClass = 'SecurityDevices'")
                .FirstOrDefault(o => (W.S(o, "Name") ?? "").IndexOf("Trusted Platform", StringComparison.OrdinalIgnoreCase) >= 0 || (W.S(o, "Name") ?? "").Contains("TPM"));
            if (dev != null)
                Add(Cat.Seguranca, W.L(dev, "ConfigManagerErrorCode") == 0 ? Gravidade.Ok : Gravidade.Aviso, "TPM presente: " + W.S(dev, "Name"),
                    "Detalhes completos do TPM exigem administrador.", null);
            else
                Add(Cat.Seguranca, Gravidade.Aviso, "TPM não encontrado",
                    "Nenhum dispositivo TPM aparece no Gerenciador de Dispositivos. O Windows 11 exige TPM 2.0.",
                    "Ative o TPM na UEFI/BIOS (\"fTPM\" em AMD ou \"PTT\" em Intel).", "tpm.msc");
        }

        void VerificarContas()
        {
            var admins = new List<string>();
            try
            {
                using (var ctx = new PrincipalContext(ContextType.Machine))
                using (var g = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, "S-1-5-32-544"))
                {
                    if (g != null)
                        foreach (var m in g.GetMembers())
                            using (m) admins.Add(m.SamAccountName ?? m.Name);
                }
            }
            catch { }

            var semSenha = new List<string>();
            foreach (var o in W.QS(W.Cimv2, "SELECT Name, SID, Disabled, PasswordRequired, LocalAccount FROM Win32_UserAccount WHERE LocalAccount = TRUE"))
            {
                string nome = W.S(o, "Name");
                string sid = W.S(o, "SID") ?? "";
                bool desativada = W.B(o, "Disabled");
                if (desativada) continue;
                if (sid.EndsWith("-500"))
                    Add(Cat.Rede, Gravidade.Aviso, "Conta \"Administrador\" interna ativada",
                        "A conta de administrador interna (" + nome + ") está ativa. Ela é alvo comum de ataques por ter nome conhecido.",
                        "Se não usa, desative: em um Terminal (Admin), execute o comando abaixo.", "net user \"" + nome + "\" /active:no");
                if (sid.EndsWith("-501"))
                    Add(Cat.Rede, Gravidade.Aviso, "Conta \"Convidado\" ativada", "Qualquer pessoa pode entrar no PC com a conta de convidado.",
                        "Desative a conta de convidado.", "net user \"" + nome + "\" /active:no");
                if (!W.B(o, "PasswordRequired") && admins.Any(a => string.Equals(a, nome, StringComparison.OrdinalIgnoreCase)))
                    semSenha.Add(nome);
            }
            if (semSenha.Count > 0)
            {
                var a = Add(Cat.Rede, Gravidade.Critico, "Administrador sem exigência de senha",
                    "Estas contas de administrador estão configuradas para não exigir senha, então podem estar sem senha. Qualquer pessoa com acesso ao PC teria controle total.",
                    "Defina uma senha (ou PIN/Windows Hello vinculado a senha) em Configurações > Contas > Opções de entrada. Para exigir senha na conta, use o comando abaixo em um Terminal (Admin).",
                    "start ms-settings:signinoptions");
                foreach (var n in semSenha) { a.Detalhes.Add("Conta: " + n); a.Comandos.Add("net user \"" + n + "\" /passwordreq:yes"); }
            }
            if (admins.Count > 0)
            {
                var a = Add(Cat.Rede, admins.Count > 3 ? Gravidade.Aviso : Gravidade.Info, admins.Count + " conta(s) com privilégio de administrador",
                    "Use uma conta padrão no dia a dia e a de administrador só quando necessário, para limitar o estrago de um malware.",
                    "Revise em Configurações > Contas > Outros usuários.", "lusrmgr.msc");
                a.Detalhes.AddRange(admins);
            }
        }

        // ------------------------------------------------------------------ Portas

        static readonly Dictionary<int, string> PortasRisco = new Dictionary<int, string>
        {
            { 21, "FTP" }, { 22, "SSH" }, { 23, "Telnet" }, { 3389, "Área de Trabalho Remota" }, { 5900, "VNC" }, { 5901, "VNC" },
            { 5938, "TeamViewer" }, { 7070, "AnyDesk" }, { 1433, "SQL Server" }, { 3306, "MySQL" }, { 5432, "PostgreSQL" }, { 27017, "MongoDB" }, { 6379, "Redis" }
        };

        void VerificarPortas()
        {
            var lista = W.QS(@"root\StandardCimv2", "SELECT LocalAddress, LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2");
            var porProc = new Dictionary<string, SortedSet<int>>(StringComparer.OrdinalIgnoreCase);
            var caminhos = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var riscos = new List<string>();
            foreach (var o in lista)
            {
                string end = W.S(o, "LocalAddress") ?? "";
                if (end == "127.0.0.1" || end == "::1" || end.StartsWith("127.")) continue;
                int porta = (int)W.L(o, "LocalPort");
                int pid = (int)W.L(o, "OwningProcess");
                string nome = "PID " + pid; string caminho = null;
                try { using (var p = Process.GetProcessById(pid)) nome = p.ProcessName; } catch { }
                if (pid == 4) nome = "System";
                caminho = Nativo.CaminhoProcesso(pid);
                SortedSet<int> s;
                if (!porProc.TryGetValue(nome, out s)) { s = new SortedSet<int>(); porProc[nome] = s; }
                s.Add(porta);
                if (caminho != null) caminhos[nome] = caminho;
                string r;
                if (PortasRisco.TryGetValue(porta, out r) && !riscos.Any(x => x.StartsWith(porta + " ")))
                    riscos.Add(porta + " (" + r + ") — " + nome);
            }
            if (porProc.Count == 0) return;

            var semAss = new List<string>();
            var linhas = new List<string>();
            foreach (var kv in porProc.OrderBy(x => x.Key))
            {
                string c; caminhos.TryGetValue(kv.Key, out c);
                var e = c != null ? Assinatura.Verificar(c) : EstadoAssinatura.Desconhecido;
                string linha = kv.Key + ": porta(s) " + string.Join(", ", kv.Value.Take(12)) + (kv.Value.Count > 12 ? "…" : "") + (c != null && !Assinatura.ConfiavelPorLocal(c) ? "  (" + c + ")" : "");
                linhas.Add(linha);
                if (e == EstadoAssinatura.SemAssinatura || e == EstadoAssinatura.Invalida) semAss.Add(linha + "  [" + Assinatura.Texto(e) + "]");
            }

            var a = Add(Cat.Rede, riscos.Count > 0 ? Gravidade.Aviso : Gravidade.Info, porProc.Count + " programas aceitam conexões de rede",
                "Programas que \"escutam\" portas podem ser acessados por outros dispositivos da rede (se o firewall permitir). Serviços do Windows (svchost, System, lsass) são normais." +
                (riscos.Count > 0 ? " Há serviços de acesso remoto ou bancos de dados expostos: confira se você os usa." : ""),
                "Feche ou desinstale programas que você não reconhece. No firewall, bloqueie o acesso de rede de programas que não precisam dele. Nunca abra essas portas no roteador sem necessidade.",
                "wf.msc");
            foreach (var r in riscos) a.Detalhes.Add("Atenção — " + r);
            a.Detalhes.AddRange(linhas);

            if (semAss.Count > 0)
            {
                var s = Suspeito(Gravidade.Aviso, "Programa sem assinatura aceitando conexões de rede",
                    "Um programa sem assinatura digital está escutando conexões. Backdoors e trojans de acesso remoto (RAT) funcionam assim, mas ferramentas de desenvolvimento e servidores de jogos também.",
                    "Se não reconhecer o programa, finalize-o, envie o arquivo para virustotal.com e rode uma verificação do Defender.", "taskmgr");
                s.Detalhes.AddRange(semAss);
            }
        }

        // ------------------------------------------------------------------ Arquivos grandes, duplicados e Lixeira

        void VerificarArquivos()
        {
            long lixBytes, lixItens;
            if (Nativo.ConsultarLixeira(out lixBytes, out lixItens))
            {
                if (lixBytes > 1L << 30)
                    Add(Cat.Arquivos, Gravidade.Aviso, "Lixeira ocupando " + F.Bytes(lixBytes),
                        lixItens + " itens na Lixeira ainda ocupam espaço no disco.",
                        "Confira se não há nada importante e esvazie a Lixeira (clique com o botão direito no ícone > Esvaziar Lixeira) ou use o modo de melhorias.");
                else
                    Add(Cat.Arquivos, Gravidade.Ok, "Lixeira: " + F.Bytes(lixBytes) + " (" + lixItens + " itens)", "A Lixeira não está ocupando espaço relevante.", null);
            }

            string perfil = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var pastas = new List<string>();
            foreach (var p in new[] { "Desktop", "Documents", "Downloads", "Videos", "Pictures", "Music", "OneDrive" })
            {
                string c = Path.Combine(perfil, p);
                if (Directory.Exists(c)) pastas.Add(c);
            }
            foreach (var sf in new[] { Environment.SpecialFolder.Desktop, Environment.SpecialFolder.MyDocuments, Environment.SpecialFolder.MyVideos, Environment.SpecialFolder.MyPictures, Environment.SpecialFolder.MyMusic })
            {
                string c = Environment.GetFolderPath(sf);
                if (!string.IsNullOrEmpty(c) && Directory.Exists(c) && !pastas.Any(x => c.StartsWith(x, StringComparison.OrdinalIgnoreCase))) pastas.Add(c);
            }

            var limite = DateTime.Now.AddSeconds(25);
            var arquivos = new List<FileInfo>();
            var pilha = new Stack<string>(pastas);
            var visitadas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool cortado = false;
            while (pilha.Count > 0)
            {
                if (DateTime.Now > limite) { cortado = true; break; }
                string d = pilha.Pop();
                if (!visitadas.Add(d)) continue;
                try
                {
                    foreach (var f in new DirectoryInfo(d).EnumerateFileSystemInfos())
                    {
                        if ((f.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if ((f.Attributes & FileAttributes.Offline) != 0 || ((int)f.Attributes & 0x400000) != 0) continue; // arquivos só na nuvem (OneDrive)
                        if ((f.Attributes & FileAttributes.Directory) != 0)
                        {
                            string n = f.Name.ToLowerInvariant();
                            if (n == "node_modules" || n == ".git" || n.StartsWith("$")) continue;
                            pilha.Push(f.FullName);
                        }
                        else
                        {
                            var fi = (FileInfo)f;
                            if (fi.Length >= 20L << 20) arquivos.Add(fi);
                        }
                    }
                }
                catch { }
            }

            var grandes = arquivos.Where(x => x.Length >= 500L << 20).OrderByDescending(x => x.Length).Take(20).ToList();
            if (grandes.Count > 0)
            {
                long tot = arquivos.Where(x => x.Length >= 500L << 20).Sum(x => x.Length);
                var a = Add(Cat.Arquivos, Gravidade.Info, "Arquivos grandes nas suas pastas (" + F.Bytes(tot) + ")",
                    "Arquivos com mais de 500 MB em Área de Trabalho, Documentos, Downloads, Vídeos, Imagens e Músicas. Instaladores antigos e vídeos costumam ocupar muito espaço.",
                    "Apague o que não precisa mais ou mova para um HD externo/nuvem. Instaladores (.exe, .msi, .iso) já usados podem ser apagados.");
                foreach (var f in grandes) a.Detalhes.Add(F.Bytes(f.Length) + " — " + f.FullName + " (modificado em " + F.Dia(f.LastWriteTime) + ")");
            }

            // Duplicados: mesmo tamanho + mesmo hash do início e do fim
            var dup = new List<List<FileInfo>>();
            foreach (var grupo in arquivos.GroupBy(x => x.Length).Where(g => g.Count() > 1))
            {
                if (DateTime.Now > limite.AddSeconds(15)) { cortado = true; break; }
                foreach (var h in grupo.GroupBy(x => HashParcial(x)).Where(g => g.Key != null && g.Count() > 1))
                    dup.Add(h.ToList());
            }
            if (dup.Count > 0)
            {
                long desperdicio = dup.Sum(g => g[0].Length * (g.Count - 1));
                var a = Add(Cat.Arquivos, desperdicio > 1L << 30 ? Gravidade.Aviso : Gravidade.Info, dup.Count + " grupo(s) de arquivos duplicados (" + F.Bytes(desperdicio) + " desperdiçados)",
                    "Arquivos com mais de 20 MB que têm o mesmo tamanho e conteúdo (comparação do início e do fim do arquivo). Confira antes de apagar.",
                    "Mantenha uma cópia de cada e apague as outras. O programa não apaga nada.");
                foreach (var g in dup.OrderByDescending(x => x[0].Length * (x.Count - 1)).Take(15))
                    a.Detalhes.Add(F.Bytes(g[0].Length) + " × " + g.Count + ": " + string.Join("  |  ", g.Select(x => x.FullName)));
            }
            if (cortado)
                Add(Cat.Arquivos, Gravidade.Info, "Busca por arquivos interrompida pelo tempo", "Há muitos arquivos nas suas pastas; a busca parou após 25 segundos e pode estar incompleta.", null);
        }

        static string HashParcial(FileInfo f)
        {
            try
            {
                using (var md5 = MD5.Create())
                using (var s = new FileStream(f.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var buf = new byte[1 << 20];
                    int n = s.Read(buf, 0, buf.Length);
                    md5.TransformBlock(buf, 0, n, null, 0);
                    if (s.Length > buf.Length * 2) s.Seek(-buf.Length, SeekOrigin.End);
                    n = s.Read(buf, 0, buf.Length);
                    md5.TransformFinalBlock(buf, 0, n);
                    return BitConverter.ToString(md5.Hash);
                }
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------ Paginação, BIOS, telas azuis

        static readonly Dictionary<long, string[]> CodigosBsod = new Dictionary<long, string[]>
        {
            { 0x0A, new[] { "IRQL_NOT_LESS_OR_EQUAL", "Driver com defeito ou RAM instável." } },
            { 0x1A, new[] { "MEMORY_MANAGEMENT", "Problema de memória RAM ou driver." } },
            { 0x1E, new[] { "KMODE_EXCEPTION_NOT_HANDLED", "Driver com defeito." } },
            { 0x3B, new[] { "SYSTEM_SERVICE_EXCEPTION", "Driver (frequentemente vídeo ou antivírus)." } },
            { 0x50, new[] { "PAGE_FAULT_IN_NONPAGED_AREA", "RAM, disco ou driver." } },
            { 0x7E, new[] { "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Driver com defeito." } },
            { 0x7F, new[] { "UNEXPECTED_KERNEL_MODE_TRAP", "Hardware (RAM, superaquecimento, overclock)." } },
            { 0x9F, new[] { "DRIVER_POWER_STATE_FAILURE", "Driver falhou ao suspender/retomar (energia)." } },
            { 0xA0, new[] { "INTERNAL_POWER_ERROR", "Gerenciamento de energia / driver." } },
            { 0xC2, new[] { "BAD_POOL_CALLER", "Driver com defeito." } },
            { 0x19, new[] { "BAD_POOL_HEADER", "Driver ou RAM." } },
            { 0xD1, new[] { "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Driver com defeito (muito comum em rede/Wi-Fi)." } },
            { 0xEF, new[] { "CRITICAL_PROCESS_DIED", "Arquivos do sistema corrompidos ou disco com falha." } },
            { 0x101, new[] { "CLOCK_WATCHDOG_TIMEOUT", "Processador instável (overclock, BIOS, temperatura)." } },
            { 0x116, new[] { "VIDEO_TDR_FAILURE", "Driver ou placa de vídeo." } },
            { 0x117, new[] { "VIDEO_TDR_TIMEOUT_DETECTED", "Driver ou placa de vídeo." } },
            { 0x124, new[] { "WHEA_UNCORRECTABLE_ERROR", "Erro de hardware (CPU, RAM, overclock, fonte)." } },
            { 0x133, new[] { "DPC_WATCHDOG_VIOLATION", "Driver de armazenamento/SSD ou firmware." } },
            { 0x139, new[] { "KERNEL_SECURITY_CHECK_FAILURE", "Driver incompatível ou RAM." } },
            { 0x154, new[] { "UNEXPECTED_STORE_EXCEPTION", "Disco/SSD ou antivírus." } },
            { 0x1000007E, new[] { "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M", "Driver com defeito." } },
            { 0x1000008E, new[] { "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M", "Driver ou RAM." } },
        };

        void VerificarExtrasSistema()
        {
            // Arquivo de paginação
            bool auto = W.QS(W.Cimv2, "SELECT AutomaticManagedPagefile FROM Win32_ComputerSystem").Select(o => W.B(o, "AutomaticManagedPagefile")).FirstOrDefault();
            var pf = W.QS(W.Cimv2, "SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage FROM Win32_PageFileUsage");
            if (pf.Count == 0)
                Add(Cat.Desempenho, Gravidade.Aviso, "Sem arquivo de paginação",
                    "O Windows está sem memória virtual. Programas e jogos podem fechar sozinhos quando a RAM enche, e não é possível salvar o despejo de telas azuis.",
                    "Em Configurações avançadas do sistema > Desempenho > Avançado > Memória virtual, marque \"Gerenciar automaticamente\".", "SystemPropertiesPerformance.exe");
            else
            {
                long aloc = pf.Sum(o => W.L(o, "AllocatedBaseSize")), pico = pf.Max(o => W.L(o, "PeakUsage")), uso = pf.Sum(o => W.L(o, "CurrentUsage"));
                bool apertado = aloc > 0 && pico >= aloc * 0.9 && !auto;
                var a = Add(Cat.Desempenho, apertado ? Gravidade.Aviso : Gravidade.Info, "Arquivo de paginação: " + F.Bytes(aloc * 1048576.0) + (auto ? " (automático)" : " (manual)"),
                    "Uso atual: " + F.Bytes(uso * 1048576.0) + ", pico desde que ligou: " + F.Bytes(pico * 1048576.0) + "." + (apertado ? " O pico chegou perto do limite configurado." : ""),
                    apertado ? "Aumente o tamanho ou volte para \"Gerenciar automaticamente\" em Desempenho > Avançado > Memória virtual." : null,
                    apertado ? new[] { "SystemPropertiesPerformance.exe" } : new string[0]);
                foreach (var o in pf) a.Detalhes.Add(W.S(o, "Name"));
            }

            // BIOS
            foreach (var o in W.QS(W.Cimv2, "SELECT SMBIOSBIOSVersion, ReleaseDate, Manufacturer FROM Win32_BIOS"))
            {
                DateTime? d = W.D(o, "ReleaseDate");
                if (!d.HasValue) continue;
                double anos = (DateTime.Now - d.Value).TotalDays / 365.25;
                Add(Cat.Integridade, anos >= 2 ? Gravidade.Info : Gravidade.Ok, "BIOS/UEFI versão " + W.S(o, "SMBIOSBIOSVersion") + " de " + F.Dia(d.Value),
                    anos >= 2 ? "A BIOS tem mais de " + (int)anos + " anos. Versões novas corrigem falhas de segurança, problemas de TPM/fTPM, memória e compatibilidade." : "A BIOS é relativamente recente.",
                    anos >= 2 ? "Veja no site do fabricante da placa-mãe/notebook se há versão nova e siga exatamente as instruções dele. Atualizar BIOS tem risco: não desligue o PC durante o processo e, se usar BitLocker, salve a chave de recuperação antes." : null,
                    anos >= 2 ? new[] { "msinfo32" } : new string[0]);
            }

            // Tempo desde a última reinicialização
            if (ultimoBoot.HasValue && (DateTime.Now - ultimoBoot.Value).TotalDays < 7)
                Add(Cat.Desempenho, Gravidade.Ok, "Reiniciado recentemente", "Última inicialização há " + F.Duracao(DateTime.Now - ultimoBoot.Value) + ".", null);

            // Telas azuis: eventos BugCheck dos últimos 90 dias
            var bsods = new List<Tuple<DateTime, string>>();
            try
            {
                var q = new EventLogQuery("System", PathType.LogName,
                    "*[System[(Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] or Provider[@Name='BugCheck']) and (EventID=1001) and TimeCreated[timediff(@SystemTime) <= 7776000000]]]");
                q.ReverseDirection = true;
                using (var r = new EventLogReader(q))
                {
                    EventRecord e;
                    while ((e = r.ReadEvent()) != null && bsods.Count < 30)
                        using (e)
                        {
                            string msg = null;
                            try { msg = e.FormatDescription(); } catch { }
                            if (msg == null) try { msg = string.Join(" ", e.Properties.Select(p => Convert.ToString(p.Value))); } catch { }
                            bsods.Add(Tuple.Create(e.TimeCreated ?? DateTime.MinValue, msg ?? ""));
                        }
                }
            }
            catch { }
            if (bsods.Count > 0)
            {
                houveTelaAzul = true;
                var a = Add(Cat.Integridade, Gravidade.Critico, bsods.Count + (bsods.Count == 1 ? " tela azul" : " telas azuis") + " nos últimos 90 dias",
                    "Telas azuis (BSOD) registradas pelo Windows. O código de parada indica a causa provável.",
                    "Pesquise o código mostrado. Atualize o driver citado (vídeo, rede, chipset, armazenamento), remova overclock e teste a RAM. Para descobrir o driver exato, abra os arquivos de C:\\Windows\\Minidump no WinDbg ou BlueScreenView.",
                    "mdsched.exe");
                var rx = new Regex(@"0x[0-9a-fA-F]{8}");
                foreach (var b in bsods.Take(10))
                {
                    var m = rx.Match(b.Item2);
                    string desc = "código não identificado";
                    if (m.Success)
                    {
                        long cod = Convert.ToInt64(m.Value, 16);
                        string[] info;
                        desc = m.Value + (CodigosBsod.TryGetValue(cod, out info) ? " " + info[0] + " — " + info[1] : "");
                    }
                    a.Detalhes.Add(F.Data(b.Item1) + ": " + desc);
                }
            }
            else
            {
                Add(Cat.Integridade, Gravidade.Ok, "Nenhuma tela azul nos últimos 90 dias", "O Windows não registrou travamentos com tela azul.", null);
            }
        }
    }
}
