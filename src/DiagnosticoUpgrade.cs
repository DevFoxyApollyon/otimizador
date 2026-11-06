using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace PcDiagnostico
{
    /// <summary>
    /// Recomendações de upgrade de hardware. Só lê informações; preços são estimativas
    /// e compatibilidade nunca é presumida: quando não dá para detectar, mandamos conferir o manual.
    /// </summary>
    partial class Diagnostico
    {
        double? saudeBateria, tempMax;
        string manualPlaca = "manual da placa-mãe";

        const string AvisoPreco = "Preço estimado (varia muito; pesquise antes de comprar): ";

        public const string PrefixoCompra = "Troque por / compre (exemplos): ";

        Achado Upg(string impacto, string titulo, string motivo, string solucao, string preco, string exemplos = null)
        {
            Gravidade g = impacto == "alto" ? Gravidade.Aviso : Gravidade.Info;
            var a = Add(Cat.Upgrade, g, titulo, motivo, solucao);
            a.Impacto = impacto;
            if (exemplos != null) a.Detalhes.Add(PrefixoCompra + exemplos + " — verifique disponibilidade e compatibilidade antes de comprar.");
            if (preco != null) a.Detalhes.Add(AvisoPreco + preco);
            return a;
        }

        static string ExemploRam(string tipo, string kit)
        {
            if (tipo == "DDR5") return kit + " DDR5 6000 MT/s CL30–36 (ex.: Kingston Fury Beast, Corsair Vengeance, XPG Lancer)";
            if (tipo == "DDR3") return kit + " DDR3 1600 MT/s igual ao atual (geralmente só no mercado de usados)";
            return kit + " DDR4 3200 MT/s CL16 (ex.: Kingston Fury Beast, Corsair Vengeance LPX, XPG Gammix D10)";
        }

        const string ExemploSsd = "NVMe 1 TB: Kingston NV3, WD Blue SN5000, Crucial P3 Plus ou Samsung 990 EVO · SATA 2,5\" (se não houver M.2): Crucial MX500, Kingston A400 ou Crucial BX500";
        const string ExemploGpu = "entrada (1080p): Radeon RX 7600, GeForce RTX 4060 ou Intel Arc B580 · intermediária (1080p alto/1440p): Radeon RX 9060 XT 16 GB ou GeForce RTX 5060 Ti 16 GB · e uma fonte de qualidade de 550–650 W (80 Plus Bronze ou melhor) se a atual for fraca";

        /// <summary>Processadores mais fortes do mesmo soquete (sem trocar placa-mãe), quando conhecido.</summary>
        static string UpgradeMesmoSoquete(string soquete, string nome)
        {
            string s = (soquete ?? "").ToUpperInvariant();
            if (s.Contains("AM4")) return "Ryzen 7 5700X3D ou 5800X3D (melhores para jogos) ou Ryzen 7 5700X — placas AM4 podem exigir BIOS atualizada para Ryzen 5000";
            if (s.Contains("AM5")) return "Ryzen 7 7800X3D ou 9800X3D (jogos) ou Ryzen 7 9700X";
            if (s.Contains("1700")) return "Core i5-14400F ou Core i7-14700F (placas B660/H610 podem exigir BIOS atualizada)";
            if (s.Contains("1200")) return "Core i5-11400F ou Core i7-11700F (placas H410/B460 não aceitam 11ª geração)";
            if (s.Contains("1151")) return "limitado à 6ª–9ª geração conforme o chipset (ex.: Core i7-9700 em placas B360/B365/Z390)";
            return null;
        }

        static string TipoRam(long smbios, long antigo)
        {
            switch (smbios)
            {
                case 20: return "DDR"; case 21: return "DDR2"; case 24: return "DDR3"; case 26: return "DDR4";
                case 34: return "DDR5"; case 27: return "LPDDR"; case 28: return "LPDDR2"; case 29: return "LPDDR3";
                case 30: return "LPDDR4"; case 35: return "LPDDR5";
            }
            switch (antigo) { case 20: return "DDR"; case 21: return "DDR2"; case 24: return "DDR3"; }
            return null;
        }

        void VerificarUpgrade()
        {
            // Placa-mãe e link do manual
            foreach (var o in W.QS(W.Cimv2, "SELECT Manufacturer, Product, Version FROM Win32_BaseBoard"))
            {
                string fab = W.S(o, "Manufacturer") ?? "", prod = W.S(o, "Product") ?? "";
                string nome = (fab + " " + prod).Trim();
                if (nome.Length == 0) continue;
                manualPlaca = "manual da placa-mãe " + nome;
                var a = Add(Cat.Upgrade, Gravidade.Info, "Placa-mãe: " + nome,
                    "Antes de comprar qualquer peça, confirme no manual ou no site do fabricante: tipo e velocidade de memória suportados, capacidade máxima, slots M.2 e a lista de processadores compatíveis (CPU support list).",
                    null);
                if (!string.IsNullOrEmpty(W.S(o, "Version")) && W.S(o, "Version") != "Default string" && W.S(o, "Version") != "x.x") a.Detalhes.Add("Revisão: " + W.S(o, "Version"));
                a.Link = "https://www.google.com/search?q=" + Uri.EscapeDataString(nome + " manual specifications");
                a.TextoLink = "Buscar manual e especificações de " + nome;
            }

            VerificarUpgradeRam();
            VerificarUpgradeDisco();
            VerificarUpgradeCpu();
            VerificarUpgradeGpu();
            VerificarUpgradeOutros();

            if (!Achados.Any(x => x.Categoria == Cat.Upgrade && x.Impacto != null))
                Add(Cat.Upgrade, Gravidade.Ok, "Nenhum upgrade necessário", "As peças atuais atendem bem ao uso detectado. Nenhuma troca é recomendada agora.", null);
        }

        void VerificarUpgradeRam()
        {
            var pentes = W.QS(W.Cimv2, "SELECT Capacity, SMBIOSMemoryType, MemoryType, Speed, ConfiguredClockSpeed, DeviceLocator, BankLabel, Manufacturer, PartNumber FROM Win32_PhysicalMemory");
            if (pentes.Count == 0) return;
            long total = pentes.Sum(p => W.L(p, "Capacity"));
            double totalGB = total / 1073741824.0;
            string tipo = pentes.Select(p => TipoRam(W.L(p, "SMBIOSMemoryType"), W.L(p, "MemoryType"))).FirstOrDefault(t => t != null);
            long velMax = pentes.Max(p => W.L(p, "Speed"));
            long velAtual = pentes.Select(p => W.L(p, "ConfiguredClockSpeed")).Where(v => v > 0).DefaultIfEmpty(0).Min();
            // O WMI informa a velocidade JEDEC; a velocidade de XMP/EXPO costuma estar no código do pente (ex.: "...U3000...", "DDR4 3200")
            long velNominal = 0;
            var rxVel = new Regex(@"(?<!\d)(2666|2933|3000|3200|3333|3466|3600|3733|3800|4000|4133|4266|4400|4800|5200|5600|6000|6200|6400|6800|7200|7600|8000)(?!\d)");
            var nominais = pentes.Select(p => rxVel.Match(W.S(p, "PartNumber") ?? "")).Where(m => m.Success).Select(m => long.Parse(m.Value)).ToList();
            if (nominais.Count == pentes.Count) velNominal = nominais.Min();
            if (velNominal > velMax) velMax = velNominal;

            int slots = 0; long maxKB = 0;
            foreach (var o in W.QS(W.Cimv2, "SELECT MemoryDevices, MaxCapacity, MaxCapacityEx, Use FROM Win32_PhysicalMemoryArray"))
            {
                if (W.L(o, "Use") != 3 && W.L(o, "Use") != 0) continue; // 3 = memória do sistema
                slots += (int)W.L(o, "MemoryDevices");
                maxKB += Math.Max(W.L(o, "MaxCapacityEx"), W.L(o, "MaxCapacity"));
            }
            int livres = slots > 0 ? slots - pentes.Count : -1;
            bool soldada = tipo != null && tipo.StartsWith("LP");

            var info = Add(Cat.Upgrade, Gravidade.Info, "Memória RAM: " + F.Bytes(total) + (tipo != null ? " " + tipo : "") + (velAtual > 0 ? " a " + velAtual + " MT/s" : ""),
                pentes.Count + (pentes.Count == 1 ? " pente instalado" : " pentes instalados") +
                (slots > 0 ? " em " + slots + " slots (" + livres + (livres == 1 ? " livre" : " livres") + ")." : "; número de slots não informado — verifique no " + manualPlaca + ".") +
                (maxKB > 0 ? " A BIOS informa suporte a até " + F.Bytes(maxKB * 1024.0) + " (confirme no manual)." : ""), null);
            foreach (var p in pentes)
                info.Detalhes.Add(((W.S(p, "BankLabel") ?? "") + " " + (W.S(p, "DeviceLocator") ?? "Slot")).Trim() + ": " + F.Bytes(W.L(p, "Capacity")) + ", padrão " + W.L(p, "Speed") + " MT/s" +
                    (W.L(p, "ConfiguredClockSpeed") > 0 ? " (rodando a " + W.L(p, "ConfiguredClockSpeed") + ")" : "") +
                    (string.IsNullOrEmpty(W.S(p, "PartNumber")) ? "" : " — " + W.S(p, "PartNumber")));
            if (soldada) info.Detalhes.Add("Memória LPDDR costuma ser soldada na placa e não pode ser ampliada.");

            string tipoTxt = tipo ?? "do mesmo tipo";
            string velTxt = velMax > 0 ? " " + velMax : "";
            string preco8 = tipo == "DDR5" ? "R$ 250 a R$ 450 por 8 GB / R$ 400 a R$ 700 por 16 GB" : tipo == "DDR3" ? "R$ 80 a R$ 150 por 8 GB (usado/seminovo)" : "R$ 130 a R$ 250 por 8 GB / R$ 250 a R$ 450 por 16 GB";
            double usoPct = memTotalKB > 0 ? 100.0 * (memTotalKB - memLivreKB) / memTotalKB : 0;

            // Dual channel
            bool singleChannel = pentes.Count == 1;
            if (soldada) { }
            else if (totalGB < 7.5)
            {
                Upg("alto", "Aumentar a RAM para 16 GB",
                    "Com " + F.Bytes(total) + ", o Windows 11 usa o disco como memória o tempo todo, deixando tudo lento.",
                    (livres > 0 ? "Adicione um pente " + tipoTxt + velTxt + " igual ao atual no slot livre (fica em dual channel). " : "Troque por um kit de 2 × 8 GB " + tipoTxt + velTxt + ". ") +
                    "Confirme o tipo e a velocidade no " + manualPlaca + ".", preco8, ExemploRam(tipo, livres > 0 ? "1 pente de 8 GB" : "Kit 2 × 8 GB"));
            }
            else if (singleChannel && livres > 0)
            {
                Upg(totalGB < 12 ? "alto" : "médio", "Adicionar um segundo pente de " + F.Bytes(total) + " (ativa dual channel)",
                    "Com apenas 1 pente a memória funciona em single channel, com metade da largura de banda. Isso reduz bastante o desempenho em jogos e em placas de vídeo integradas.",
                    "Compre um pente " + tipoTxt + velTxt + " de " + F.Bytes(total) + " (de preferência o mesmo modelo: " + (W.S(pentes[0], "PartNumber") ?? "veja a etiqueta do pente") + ") e instale no slot indicado no " + manualPlaca + " para dual channel (geralmente A2/B2).",
                    preco8, ExemploRam(tipo, "1 pente de " + F.Bytes(total) + " (ou, melhor ainda, um kit 2 × " + F.Bytes(total) + " novo)"));
            }
            else if (singleChannel && livres == 0)
            {
                Upg("médio", "Memória em single channel sem slot livre",
                    "Há só 1 pente e nenhum slot livre (comum em notebooks), então a memória roda com metade da largura de banda.",
                    "Se o notebook tiver um segundo slot sob uma tampa ou atrás da placa, confira no manual do fabricante. Caso contrário, não há upgrade simples.", null);
            }
            else if (pentes.Count >= 2)
            {
                var caps = pentes.Select(p => W.L(p, "Capacity")).Distinct().Count();
                info.Detalhes.Add(caps == 1 ? "Pentes de mesmo tamanho: provavelmente em dual channel (se estiverem nos slots recomendados pelo manual)." : "Pentes de tamanhos diferentes: o dual channel pode ficar parcial (modo flex).");
                if (pentes.Select(p => (W.S(p, "PartNumber") ?? "").Trim()).Distinct().Count() > 1)
                    info.Detalhes.Add("Pentes de modelos diferentes: funcionam juntos, mas ao ativar XMP/EXPO use a velocidade do mais lento e teste a estabilidade.");
            }

            if (!soldada && totalGB >= 7.5 && totalGB < 15 && !singleChannel)
                Upg(usoPct >= 80 ? "alto" : "médio", "Ampliar a RAM para 16 GB",
                    F.Bytes(total) + " é pouco para jogos atuais, navegador com muitas abas e programas abertos ao mesmo tempo" + (usoPct > 0 ? " (uso agora: " + F.Pct(usoPct) + ")" : "") + ".",
                    (livres > 0 ? "Adicione pentes " + tipoTxt + velTxt + " nos slots livres, mantendo pares iguais. " : "Troque por um kit 2 × 8 GB " + tipoTxt + velTxt + ". ") + "Confirme no " + manualPlaca + ".", preco8, ExemploRam(tipo, "Kit 2 × 8 GB"));
            else if (!soldada && totalGB >= 15 && totalGB < 31 && usoPct >= 85)
                Upg(usoPct >= 90 ? "médio" : "baixo", "Considerar 32 GB de RAM",
                    "A memória está quase cheia (" + F.Pct(usoPct) + " em uso). Útil para edição de vídeo, Unreal/Blender, máquinas virtuais ou jogo + navegador ao mesmo tempo.",
                    "A opção mais estável é trocar os pentes atuais por um kit 2 × 16 GB (2 pentes iguais rodam o XMP com mais facilidade do que 4 pentes misturados). " + (livres >= 2 ? "Outra opção é adicionar mais 2 pentes iguais aos atuais nos slots livres. " : "") + "Confirme a capacidade máxima no " + manualPlaca + ".",
                    tipo == "DDR5" ? "R$ 700 a R$ 1.300 por 2 × 16 GB" : "R$ 450 a R$ 800 por 2 × 16 GB", ExemploRam(tipo, "Kit 2 × 16 GB"));

            // XMP/EXPO desligado (memória rodando abaixo do que suporta) — melhoria grátis
            if (velMax > 0 && velAtual > 0 && velAtual < velMax - 100)
                Upg("médio", "Memória rodando abaixo da velocidade: ative o XMP/EXPO (grátis)",
                    (velNominal == velMax ? "O código dos pentes indica " + velMax + " MT/s" : "Os pentes suportam " + velMax + " MT/s") + ", mas estão rodando a " + velAtual + " MT/s. Em processadores Ryzen isso afeta bastante o desempenho em jogos.",
                    "Reinicie o PC e aperte Delete (ou F2) repetidamente para entrar na BIOS/UEFI. Procure a opção XMP (Intel), EXPO ou DOCP (AMD); em placas Gigabyte ela se chama \"Extreme Memory Profile (X.M.P.)\" na aba Tweaker. Escolha o Perfil 1, salve com F10 e reinicie. Abra o PCDiagnostico de novo e confira se a memória passou a rodar na velocidade certa. Se o PC travar ou não ligar, entre de novo na BIOS e desative a opção (ou limpe a CMOS conforme o manual).", "grátis");
        }

        void VerificarUpgradeDisco()
        {
            const string ns = @"root\Microsoft\Windows\Storage";
            string letra = Environment.SystemDirectory.Substring(0, 1);
            long discoSistema = -1;
            foreach (var p in W.QS(ns, "SELECT DiskNumber, DriveLetter FROM MSFT_Partition"))
            {
                object dl = W.V(p, "DriveLetter");
                if (dl != null && Convert.ToChar(dl).ToString().Equals(letra, StringComparison.OrdinalIgnoreCase)) discoSistema = W.L(p, "DiskNumber");
            }
            var discos = W.QS(ns, "SELECT DeviceId, FriendlyName, MediaType, BusType, Size, SpindleSpeed FROM MSFT_PhysicalDisk");
            if (discos.Count == 0) return;
            bool algumNvme = discos.Any(d => W.L(d, "BusType") == 17);
            foreach (var d in discos)
            {
                long media = W.L(d, "MediaType"), bus = W.L(d, "BusType");
                bool hdd = media == 3 || (media == 0 && W.L(d, "SpindleSpeed") > 0 && W.L(d, "SpindleSpeed") != 4294967295);
                bool sistema = W.S(d, "DeviceId") == discoSistema.ToString();
                string nome = W.S(d, "FriendlyName") + " (" + TipoMidia(media, bus) + ", " + F.Bytes(W.L(d, "Size")) + ")";
                if (hdd && sistema)
                    Upg("alto", "Trocar o disco do Windows por um SSD (maior ganho possível)",
                        "O Windows está instalado em um HD mecânico: " + nome + ". Um SSD deixa a inicialização, a abertura de programas e o carregamento de jogos de 3 a 10 vezes mais rápidos.",
                        "Compre um SSD de pelo menos 500 GB. Se a placa tiver slot M.2 livre (confira no " + manualPlaca + "), prefira NVMe; senão, um SSD SATA de 2,5\". Depois, clone o disco ou reinstale o Windows no SSD e use o HD para arquivos.",
                        "SSD SATA 480–512 GB: R$ 180 a R$ 300 · SSD NVMe 1 TB: R$ 350 a R$ 600", ExemploSsd);
                else if (hdd)
                    Upg("baixo", "HD mecânico secundário: " + nome, "Bom para guardar arquivos, mas lento para jogos.", "Se instalar jogos nele, considere movê-los para um SSD.", "SSD 1 TB: R$ 350 a R$ 600", ExemploSsd);
                else if (sistema && bus == 11 && !algumNvme)
                    Upg("baixo", "SSD SATA no Windows: NVMe seria mais rápido", nome + " já é SSD (a maior diferença já foi conquistada). Um NVMe é de 3 a 6 vezes mais rápido em leitura sequencial, mas a diferença no uso diário é pequena.",
                        "Só vale se a placa tiver slot M.2 com suporte a NVMe — o programa não consegue detectar slots M.2 vazios; verifique no " + manualPlaca + ".", "SSD NVMe 1 TB: R$ 350 a R$ 600", ExemploSsd);
                if (sistema && !hdd && W.L(d, "Size") < 300L * 1000 * 1000 * 1000)
                    Upg("médio", "SSD do Windows pequeno (" + F.Bytes(W.L(d, "Size")) + ")", "Com menos de 256 GB, atualizações e jogos enchem o disco rápido, e SSD cheio fica mais lento.",
                        "Adicione um segundo SSD para jogos/arquivos (se houver slot M.2 ou SATA livre — confira no " + manualPlaca + ") ou troque por um de 1 TB.", "SSD 1 TB: R$ 350 a R$ 600", ExemploSsd);
            }
        }

        static int GeracaoIntel(string nome)
        {
            var m = Regex.Match(nome, @"i[3579]-(\d{4,5})");
            if (!m.Success) return 0;
            string n = m.Groups[1].Value;
            return n.Length == 5 ? int.Parse(n.Substring(0, 2)) : int.Parse(n.Substring(0, 1));
        }

        void VerificarUpgradeCpu()
        {
            var cpu = W.QS(W.Cimv2, "SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, SocketDesignation FROM Win32_Processor").FirstOrDefault();
            if (cpu == null) return;
            string nome = (W.S(cpu, "Name") ?? "").Trim();
            long nucleos = W.L(cpu, "NumberOfCores"), threads = W.L(cpu, "NumberOfLogicalProcessors");

            // Uso médio: 5 amostras em ~5 s
            var amostras = new List<long>();
            for (int i = 0; i < 5; i++)
            {
                foreach (var o in W.QS(W.Cimv2, "SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name = '_Total'"))
                    amostras.Add(W.L(o, "PercentProcessorTime"));
                if (i < 4) Thread.Sleep(1000);
            }
            double uso = amostras.Count > 0 ? amostras.Average() : 0;

            string geracao = null; bool antigo = false;
            int gi = GeracaoIntel(nome);
            if (gi > 0) { geracao = gi + "ª geração Intel"; antigo = gi <= 7; }
            var mr = Regex.Match(nome, @"Ryzen\s+\d\s+(?:PRO\s+)?(\d)(\d)\d\d");
            if (mr.Success) { geracao = "Ryzen série " + mr.Groups[1].Value + "000"; antigo = mr.Groups[1].Value == "1" || mr.Groups[1].Value == "2"; }
            if (Regex.IsMatch(nome, @"(?i)\b(FX-|Athlon|Phenom|Pentium|Celeron|Core\(TM\)2|A[468]-\d)")) { antigo = true; geracao = geracao ?? "linha de entrada/antiga"; }

            var a = Add(Cat.Upgrade, Gravidade.Info, "Processador: " + nome,
                nucleos + " núcleos / " + threads + " threads" + (geracao != null ? ", " + geracao : "") + ". Uso médio medido agora: " + F.Pct(uso) + ".", null);
            if (!string.IsNullOrEmpty(W.S(cpu, "SocketDesignation"))) a.Detalhes.Add("Soquete informado pela BIOS: " + W.S(cpu, "SocketDesignation"));

            bool gargalo = nucleos < 4 || threads < 6 || antigo || uso >= 80;
            string mesmoSoquete = UpgradeMesmoSoquete(W.S(cpu, "SocketDesignation"), nome);
            if (!gargalo)
            {
                a.Detalhes.Add("Não é gargalo para o uso atual: upgrade de processador não é recomendado agora.");
                if (mesmoSoquete != null) a.Detalhes.Add("Se um dia quiser mais desempenho sem trocar a placa-mãe: " + mesmoSoquete + ". Confirme na lista de CPUs suportadas da placa.");
                return;
            }
            Upg(nucleos < 4 || uso >= 85 ? "alto" : "médio", "Processador pode ser um gargalo",
                (nucleos < 4 || threads < 6 ? "Poucos núcleos/threads (" + nucleos + "/" + threads + ") para jogos e multitarefa atuais. " : "") +
                (antigo ? "Modelo de geração antiga (" + geracao + "). " : "") +
                (uso >= 80 ? "O uso médio está muito alto (" + F.Pct(uso) + "). " : ""),
                "Antes de comprar, consulte a lista de processadores compatíveis (CPU support list) no site da placa-mãe: às vezes há um modelo melhor no mesmo soquete, exigindo só atualizar a BIOS. Na maioria dos casos de CPU antiga, porém, o upgrade exige trocar também placa-mãe e, às vezes, a memória.",
                "Processador intermediário: R$ 700 a R$ 1.500 · com placa-mãe + memória: R$ 1.800 a R$ 3.500",
                (mesmoSoquete != null ? "mesmo soquete: " + mesmoSoquete + " · " : "") + "plataforma nova: Ryzen 5 7600 + placa B650 + 2 × 16 GB DDR5, ou Core i5-14400F + placa B760");
        }

        static long VramRegistro(string nome)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var k = b.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"))
                {
                    if (k == null) return 0;
                    foreach (var s in k.GetSubKeyNames())
                    {
                        if (!Regex.IsMatch(s, @"^\d{4}$")) continue;
                        using (var a = k.OpenSubKey(s))
                        {
                            if (a == null || !string.Equals(a.GetValue("DriverDesc") as string, nome, StringComparison.OrdinalIgnoreCase)) continue;
                            object q = a.GetValue("HardwareInformation.qwMemorySize");
                            if (q is long) return (long)q;
                            if (q is byte[] && ((byte[])q).Length >= 8) return BitConverter.ToInt64((byte[])q, 0);
                            object m = a.GetValue("HardwareInformation.MemorySize");
                            if (m is int) return (uint)(int)m;
                            if (m is byte[] && ((byte[])m).Length >= 4) return BitConverter.ToUInt32((byte[])m, 0);
                        }
                    }
                }
            }
            catch { }
            return 0;
        }

        void VerificarUpgradeGpu()
        {
            var gpus = W.QS(W.Cimv2, "SELECT Name, AdapterRAM FROM Win32_VideoController")
                .Where(o => !Regex.IsMatch(W.S(o, "Name") ?? "", @"(?i)virtual|basic display|basic render|parsec|meta|remote|mirror")).ToList();
            if (gpus.Count == 0) return;
            Func<string, bool> integrada = n => Regex.IsMatch(n, @"(?i)Intel\(R\) (U?HD|Iris)|Intel.*Graphics$|Radeon\(TM\) (Vega |)Graphics|Radeon Graphics|Vega \d+ Graphics|AMD Radeon\(TM\) \d{3}M");
            bool temDedicada = gpus.Any(g => !integrada(W.S(g, "Name") ?? ""));

            foreach (var g in gpus)
            {
                string nome = W.S(g, "Name") ?? "";
                long vram = VramRegistro(nome);
                if (vram <= 0) vram = (long)(uint)W.L(g, "AdapterRAM");
                double gb = vram / 1073741824.0;
                bool integ = integrada(nome);
                var a = Add(Cat.Upgrade, Gravidade.Info, "Placa de vídeo: " + nome + (vram > 0 && !integ ? " (" + F.Bytes(vram) + ")" : ""),
                    integ ? "Vídeo integrado ao processador (usa a memória RAM do sistema)." : "Placa de vídeo dedicada.", null);
                if (integ && temDedicada) continue;
                if (integ)
                {
                    Upg(notebook ? "médio" : "alto", "Sem placa de vídeo dedicada",
                        "O vídeo integrado dá conta de uso comum, mas é fraco para jogos e programas 3D." + (notebook ? " Em notebooks não é possível adicionar placa de vídeo." : ""),
                        notebook ? "Para jogos leves, mantenha a RAM em dual channel (o vídeo integrado depende muito disso)." :
                        "Adicione uma placa de vídeo dedicada no slot PCIe x16. Antes, confira se a fonte tem potência e conector PCIe suficientes (veja a etiqueta da fonte) e se há espaço no gabinete.",
                        notebook ? null : "Entrada (1080p médio): R$ 1.200 a R$ 2.000 · Intermediária: R$ 2.000 a R$ 3.500", notebook ? null : ExemploGpu);
                    continue;
                }
                bool serieAntiga = Regex.IsMatch(nome, @"(?i)GTX\s?(6|7|9)\d\d|GTX\s?10[5-8]0|GT\s?\d{3,4}|RX\s?(4|5)\d\d|R[579]\s|HD\s?\d{4}|Quadro K");
                if (gb > 0 && gb < 3.5)
                    Upg("alto", "Pouca memória de vídeo (" + F.Bytes(vram) + ")", "Jogos atuais pedem pelo menos 6–8 GB de VRAM; com " + F.Bytes(vram) + " é preciso jogar no mínimo e há travadas.",
                        "Troque por uma placa com 8 GB ou mais. Confira a potência da fonte e o espaço no gabinete.", "R$ 1.300 a R$ 2.500", ExemploGpu);
                else if ((gb > 0 && gb < 6) || serieAntiga)
                    Upg("médio", "Placa de vídeo de geração antiga" + (gb > 0 && gb < 6 ? " / pouca VRAM" : ""),
                        nome + " ainda roda jogos em 1080p com qualidade média/baixa, mas não tem recursos novos (como upscaling por IA) e alguns jogos recentes já exigem mais.",
                        "Se jogos são prioridade, uma placa atual de entrada/intermediária com 8 GB ou mais traz o maior ganho em FPS. Veja na etiqueta lateral da fonte a potência (W) e se ela tem conectores PCIe de 8 pinos. Compre a placa e desinstale o driver antigo com o DDU antes de trocar. Encaixe a placa nova no slot PCIe x16, ligue os cabos de energia e instale o driver mais recente do fabricante.",
                        "R$ 1.500 a R$ 3.000", ExemploGpu);
            }
        }

        void VerificarUpgradeOutros()
        {
            if (saudeBateria.HasValue && saudeBateria.Value < 70)
                Upg(saudeBateria.Value < 50 ? "alto" : "médio", "Trocar a bateria do notebook (" + F.Pct(saudeBateria.Value) + " da capacidade original)",
                    "A bateria segura bem menos carga que quando era nova.", "Compre uma bateria compatível com o modelo exato do notebook (veja o código na bateria) ou faça a troca em assistência autorizada.",
                    "R$ 200 a R$ 600");
            if (tempMax.HasValue && tempMax.Value >= 80)
                Upg("médio", "Limpeza e troca de pasta térmica", "Temperatura de " + tempMax.Value.ToString("0", F.BR) + " °C detectada: o PC pode estar perdendo desempenho por aquecimento.",
                    "Limpe a poeira das ventoinhas e troque a pasta térmica do processador (e da placa de vídeo, se tiver alguns anos). Em PC de mesa, considere um cooler melhor ou mais ventoinhas no gabinete.",
                    "Pasta térmica: R$ 30 a R$ 80 · limpeza em assistência: R$ 100 a R$ 250 · cooler: R$ 120 a R$ 350", "pasta térmica Arctic MX-4/MX-6 ou Thermal Grizzly Kryonaut · cooler Thermalright Assassin X 120 ou DeepCool AK400");

            foreach (var o in W.QS(W.Cimv2, "SELECT Name, NetConnectionID FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE"))
            {
                string n = W.S(o, "Name") ?? "";
                if (!Regex.IsMatch(n, @"(?i)wi-?fi|wireless|wlan|802\.11")) continue;
                bool antigo = Regex.IsMatch(n, @"(?i)802\.11\s?[bgn]\b|Wireless[- ]N|b/g/n|\bN\s?\d{3}\b|150Mbps|300Mbps|RTL8188|RTL8192|AR9\d{3}|Centrino");
                if (antigo)
                    Upg("baixo", "Placa Wi-Fi antiga (Wi-Fi 4): " + n, "Placas 802.11n são lentas e instáveis em redes atuais, especialmente longe do roteador.",
                        notebook ? "Em muitos notebooks a placa Wi-Fi M.2 pode ser trocada por uma Wi-Fi 6 (confira no manual do notebook se não há bloqueio de BIOS)." : "Use um adaptador Wi-Fi 6 PCIe ou USB, ou cabo de rede.",
                        "R$ 80 a R$ 250", "Intel AX210 (placa M.2/PCIe), TP-Link Archer TX20E (PCIe) ou TP-Link Archer TX20U (USB)");
            }
        }
    }
}
