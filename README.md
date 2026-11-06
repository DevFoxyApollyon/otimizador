# Diagnóstico do PC

Ferramenta para Windows 10/11 que **analisa o computador e lista problemas, erros, ameaças, aplicativos desnecessários e melhorias possíveis**, com uma solução sugerida para cada item. O resultado é um relatório HTML (aberto no navegador ao final) e um resumo no console.

> **O diagnóstico é somente leitura.** Ele não instala, não apaga e não muda configurações.
> Alterações só acontecem no **modo de melhorias**, quando você escolhe cada item e confirma. Antes de qualquer mudança é criado um ponto de restauração do Windows, e tudo fica registrado em log.

## Download

Baixe o **`PCDiagnostico.exe`** na página de [Releases](../../releases/latest) (ou em `dist/PCDiagnostico.exe`). É um único arquivo, sem instalação. Ele precisa só do .NET Framework 4.8, que já vem no Windows 10/11.

Como o exe não tem assinatura digital, o Windows SmartScreen pode avisar na primeira vez. Clique em **Mais informações > Executar assim mesmo**, ou compile você mesmo a partir do código (veja "Como compilar").

## O que é verificado

| Área | Verificações |
|---|---|
| Ameaças e itens suspeitos | Histórico de detecções do **Microsoft Defender** (`MSFT_MpThreatDetection`/`MSFT_MpThreat`), status do Defender (tempo real, assinaturas, últimas verificações). Heurísticas, sempre marcadas como **"Suspeito"** e nunca como infecção confirmada: programas que iniciam com o Windows a partir de `%TEMP%`/AppData sem assinatura, tarefas agendadas que executam programas sem assinatura de pastas de usuário, processos em execução sem assinatura digital, arquivo `hosts` alterado, proxy configurado, exclusões perigosas no Defender, programa sem assinatura escutando portas, ativadores piratas (KMS) |
| Segurança | Antivírus ativo/desatualizado, firewall, UAC, Secure Boot, BitLocker, TPM |
| Contas, acesso remoto e portas | Administradores sem exigência de senha, contas Administrador/Convidado ativas, SMBv1, Área de Trabalho Remota (RDP) e NLA, programas que aceitam conexões de rede (com destaque para RDP, VNC, SSH, bancos de dados etc.) |
| Upgrade de peças | Placa-mãe (com link de busca do manual), RAM (total, tipo DDR3/4/5, velocidade, slots livres, capacidade máxima informada pela BIOS, single/dual channel, XMP/EXPO desligado), disco do Windows (HDD x SSD, SATA x NVMe, tamanho), CPU (geração, núcleos/threads, uso médio medido), GPU (integrada/dedicada, VRAM, geração), bateria, temperatura e placa Wi-Fi antiga. Cada recomendação tem **impacto alto/médio/baixo**, motivo e **faixa de preço estimada em R$** |
| Aplicativos instalados | Todos os programas (registro Uninstall, HKLM/HKCU, 32 e 64 bits) e apps da Microsoft Store, com tamanho, data de instalação, editor e último uso. Cada um é classificado (bloatware, adware/PUP, ativador pirata, sem uso há meses, sem editor/assinatura, duplicado ou mais de um antivírus) e recebe **Recomendado remover / Opcional / Manter**, com o motivo e o comando de desinstalação |
| Drivers e dispositivos | Dispositivos com erro ou sem driver, drivers de terceiros com mais de 5 anos, driver de vídeo genérico ou antigo |
| Erros do sistema | Eventos críticos e de erro (Sistema e Aplicativo, últimos 7 dias), agrupados por origem, com explicação e solução |
| Discos | Saúde (`MSFT_PhysicalDisk`), SMART (exige administrador), pouco espaço livre |
| Arquivos | Arquivos grandes (> 500 MB) e duplicados (> 20 MB) nas pastas do usuário, tamanho da Lixeira |
| Windows Update | Atualizações pendentes, reinicialização pendente, serviço desativado, última atualização |
| Desempenho | RAM e programas que mais consomem, programas na inicialização (destacando os pesados), arquivo de paginação, tempo desde a última reinicialização |
| Energia | Plano de energia, saúde da bateria, temperatura (quando o PC expõe sensores reais) |
| Integridade | Telas azuis dos últimos 90 dias (eventos BugCheck, com nome e causa provável do código) e minidumps, versão/idade da BIOS, recomendação de DISM/SFC |

Gravidades: **Crítico** (vermelho), **Aviso** (laranja), **Informação** (azul), **OK** (verde), mais o selo **Suspeito** (roxo) para indícios heurísticos.

## Como usar

1. Dê dois cliques em `dist\PCDiagnostico.exe`.
2. Aguarde de 1 a 3 minutos.
3. O relatório abre no navegador e fica salvo em `Documentos\Diagnóstico do PC\`.
4. No console aparece um menu:
   - **[1]** Abrir o relatório novamente
   - **[2]** Aplicar melhorias (você escolhe e confirma cada uma)
   - **[3]** Rodar a verificação rápida do Microsoft Defender (`MpCmdRun -Scan -ScanType 1`). Só roda se você confirmar.
   - **[4]** Gerar o relatório de bateria (`powercfg /batteryreport`) ou de energia (`powercfg /energy`, exige administrador)
   - **[5]** Corrigir automaticamente (todas as correções seguras de uma vez, com uma única confirmação)
   - **[6]** Ver as peças para trocar ou melhorar, com exemplos de modelos melhores, passo a passo e preço estimado
   - **[7]** Ver o passo a passo para corrigir cada problema crítico ou aviso
   - **[8]** Desinstalar aplicativos: mostra os recomendados para remover e os opcionais (ou **T** para todos). Você escolhe pelos números e confirma cada um. Antes é criado um ponto de restauração. Usa o desinstalador do próprio programa (MSI em modo `/passive`, apps da Store com `Remove-AppxPackage`), confere se o app realmente saiu e registra tudo no log. Componentes, drivers e runtimes recebem um aviso extra. Depois, procura **sobras** dos programas removidos (pasta de instalação e pastas/chaves de registro com o nome exato do programa em Arquivos de Programas, ProgramData e AppData) e remove só as que você escolher: pastas vão para a Lixeira e chaves de registro são exportadas para `.reg` em `Documentos\Diagnóstico do PC\backup-registro\` antes. Pastas usadas por outro programa instalado, ou por outra versão do mesmo programa, nunca entram na lista.
   - **[9]** **Otimização máxima**: tudo da correção automática, mais o plano Alto desempenho (em PC de mesa), efeitos visuais para desempenho, Modo de Jogo ligado e gravação em segundo plano do Xbox (Game DVR) desligada. Tem uma única confirmação, ponto de restauração e log. O XMP da memória continua manual, porque fica na BIOS.
   - **[10]** O que está travando o PC agora: mede por 5 segundos o uso de CPU, RAM e disco por programa, mostra os programas que não respondem e dá o passo a passo de cada causa.
   - **[14]** Atualizar drivers pelo **Windows Update** (drivers assinados e testados pela Microsoft; nada de sites de terceiros). Lista os drivers disponíveis, você escolhe e confirma cada um, é criado um ponto de restauração antes e tudo vai para o log. Para a placa de vídeo, o driver mais novo costuma estar no site da NVIDIA/AMD/Intel.
   - **[11]** Reiniciar o PC (sempre pede confirmação; reinicia em 30 s e pode ser cancelado com `shutdown /a`).

No topo do relatório e no console aparecem também:

- **"O PC precisa reiniciar?"**, com o motivo: atualização de componentes, Windows Update, arquivos aguardando substituição ou troca de nome do computador.
- **"O que está travando o PC"**, medido durante o diagnóstico.

Depois de melhorias, correção, otimização ou desinstalação, o programa verifica de novo se precisa reiniciar e pergunta se você quer reiniciar agora.

O console também mostra automaticamente, logo após o resumo, o **passo a passo de cada problema** e as **peças recomendadas**. No relatório HTML, cada solução aparece como uma lista numerada de passos, e há um quadro "Peças: o que trocar ou melhorar" no topo.

Os exemplos de peças (como kits de RAM DDR4/DDR5, SSDs NVMe, placas de vídeo de entrada/intermediárias e processadores do mesmo soquete) são sugestões genéricas por categoria, escritas no programa. Verifique disponibilidade, preço atual e compatibilidade com o manual da sua placa-mãe antes de comprar.

Para o diagnóstico **completo** (SMART, histórico e exclusões do Defender, BitLocker/TPM detalhados, Prefetch para saber o último uso dos programas, tarefas agendadas do sistema), clique com o botão direito no exe e escolha **Executar como administrador**. Sem isso, o programa funciona e avisa no relatório o que foi pulado.

### Modo de melhorias

Melhorias disponíveis (só aparecem as que se aplicam ao PC):

- Limpar arquivos temporários (do usuário e do Windows, com mais de 24 h)
- Limpar o cache do Windows Update
- Esvaziar a Lixeira
- Desativar programas na inicialização (você escolhe cada programa; é igual ao Gerenciador de Tarefas e pode ser revertido em Configurações > Aplicativos > Inicialização)
- Trocar o plano de energia
- Reparar o Windows com `DISM /RestoreHealth` e `sfc /scannow`
- Ativar o TRIM (se estiver desligado e houver SSD)
- Otimizar unidades (`defrag /C /O`: desfragmenta HD, TRIM em SSD)
- Ajustar efeitos visuais para desempenho (a suavização de fontes continua ligada)
- Desativar o SMBv1 (se estiver ativo)

Regras:

- Você escolhe os itens pelo número e confirma **cada um** (e alguns têm sub-escolhas, como quais programas desativar). No fim, há uma confirmação geral.
- O modo pede **administrador** (UAC) ao ser aberto, porque o ponto de restauração exige essa permissão. O diagnóstico em si não pede.
- Antes de qualquer mudança é criado um **ponto de restauração** ("PCDiagnostico - antes das melhorias"). Se a Proteção do Sistema estiver desligada, o programa pergunta se deve ativá-la. Se não for possível criar o ponto, ele pergunta se você quer continuar sem ele (o padrão é não).
- O Windows cria no máximo um ponto de restauração a cada 24 h. Se já existir um recente, ele será o ponto de volta, e o log informa isso.
- Tudo é registrado em `Documentos\Diagnóstico do PC\melhorias-log.txt`, com os valores anteriores e o comando para desfazer quando houver.
- Para desfazer tudo: Painel de Controle > Recuperação > Abrir Restauração do Sistema.
- Esvaziar a Lixeira não pode ser desfeito, nem pelo ponto de restauração.

### Correção automática

A opção **[5]** do menu (ou `PCDiagnostico.exe --corrigir`) aplica de uma vez só as correções **seguras e reversíveis** que se aplicam ao PC:

- limpar temporários (mais de 24 h) e o cache do Windows Update;
- `DISM /RestoreHealth` e `sfc /scannow`;
- ativar o TRIM (se desligado) e otimizar as unidades;
- trocar o plano "Economia de energia" por "Equilibrado";
- desativar na inicialização os programas marcados como pesados, exceto sincronização de arquivos (OneDrive, Dropbox...), antivírus e antitrapaça;
- atualizar as assinaturas do Defender e rodar a verificação rápida (quando o Defender é o antivírus ativo);
- religar o firewall, a proteção em tempo real do Defender e o UAC, se estiverem desligados;
- desativar o SMBv1, se estiver ativo.

Regras:

- Mostra a lista completa do que vai fazer e pede **uma única confirmação**.
- Pede administrador (UAC) e cria um **ponto de restauração** antes de qualquer mudança.
- Registra tudo em `melhorias-log.txt`.
- No final, mostra o resultado dividido em **corrigido / falhou / precisa de ação manual**. Por exemplo, ameaças encontradas, reinicialização pendente e SFC com problemas entram em "precisa de ação manual".

Fica **fora** do automático, porque precisa da sua decisão item por item:

- esvaziar a Lixeira, apagar arquivos ou desinstalar apps;
- drivers e BIOS;
- remoção de ameaças além do que o Defender faz;
- itens de inicialização de sincronização, segurança ou antitrapaça.

Upgrade de peças é apenas recomendação.

### Opções de linha de comando

```
PCDiagnostico.exe [opções]
  (sem opções)          diagnóstico completo + menu de ações no final
  --sem-pausa           só o diagnóstico, sem menu nem pausa no final
  --nao-abrir           não abre o relatório no navegador
  --saida <pasta>       pasta do relatório
  --corrigir            correção automática (confirmação única, pede administrador)
  --otimizar            otimização máxima (confirmação única, pede administrador)
  --desinstalar         desinstalar aplicativos escolhidos e limpar as sobras (pede administrador)
  --drivers             atualizar drivers pelo Windows Update, escolhendo cada um (pede administrador)
  --travando            mede o que está travando o PC agora e se precisa reiniciar
  --melhorias           abre direto o modo de melhorias (pede administrador)
  --verificacao-rapida  verificação rápida do Defender (após confirmar)
  --relatorio-energia   gera o relatório powercfg /energy (administrador)
  --simular             nos modos de melhorias e correção, mostra o que seria feito sem alterar nada
```

Código de saída do diagnóstico: `0` = sem problemas, `1` = há avisos, `2` = há itens críticos.

## Como compilar

Não precisa de Visual Studio nem de .NET SDK. O compilador C# (`csc.exe`) já vem com o .NET Framework 4.8, que faz parte do Windows 10/11.

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

O executável é gerado em `dist\PCDiagnostico.exe` (cerca de 280 KB, um único arquivo, sem dependências).

## Por que C# + .NET Framework 4.8

- **Roda em qualquer Windows 10/11 sem instalar nada.** O exe é pequeno e abre na hora.
- **Acesso nativo** a WMI, Visualizador de Eventos, registro, Agendador de Tarefas, API do Windows Update, `WinVerifyTrust` (assinaturas) e Ponto de Restauração, sem fazer parsing de texto de outros programas. A única exceção é a lista de apps da Store, lida com `Get-AppxPackage`.
- **Menos falsos positivos de antivírus** do que PyInstaller ou ps2exe, que extraem um interpretador ou script em tempo de execução.
- **Build reproduzível** com o que já está na máquina.

## Estrutura

```
pc-diagnostico/
├─ src/
│  ├─ Program.cs              entrada, console, menu e opções
│  ├─ Diagnostico.cs          sistema, drivers, eventos, discos, Update, segurança, desempenho, energia
│  ├─ DiagnosticoAmeacas.cs   Defender, heurísticas de itens suspeitos, processos sem assinatura
│  ├─ DiagnosticoApps.cs      inventário e classificação de aplicativos
│  ├─ DiagnosticoExtras.cs    BitLocker, TPM, contas, SMBv1, RDP, portas, arquivos, paginação, BIOS, telas azuis
│  ├─ DiagnosticoUpgrade.cs   recomendações de upgrade de peças
│  ├─ Melhorias.cs            modo de melhorias, ponto de restauração, log, Defender, relatórios powercfg
│  ├─ Correcao.cs             correção automática e otimização máxima (confirmação única + resumo final)
│  ├─ Desinstalar.cs          desinstalação de aplicativos item por item
│  ├─ Sobras.cs               limpeza de sobras após desinstalar (Lixeira + backup .reg)
│  ├─ Drivers.cs              atualização de drivers pelo Windows Update
│  ├─ Travamento.cs           o que está travando o PC (CPU/RAM/disco por programa) e se precisa reiniciar
│  ├─ Relatorio.cs            HTML autocontido (offline, tema claro/escuro, filtros, tabela de apps)
│  ├─ Nativo.cs               chamadas nativas (assinatura, Lixeira, processos), itens de inicialização
│  └─ Base.cs                 modelo e helpers de WMI/registro/formatação
├─ app.manifest               roda sem pedir UAC (asInvoker)
├─ build.ps1                  script de compilação
└─ dist/PCDiagnostico.exe
```

## Limitações conhecidas

- **Preços** de peças são faixas estimadas e fixas no programa (não são consultados online). Pesquise antes de comprar.
- **Compatibilidade** não é presumida. Slots M.2 livres, lista de CPUs suportadas e limites reais de memória não são detectáveis com segurança pelo Windows: o relatório manda conferir o manual da placa-mãe (com link de busca).
- A velocidade nominal (XMP/EXPO) da RAM é lida do código do pente quando ele a contém; o WMI só informa a velocidade padrão JEDEC.
- "Dual channel" é estimado pelo número e tamanho dos pentes. O Windows não informa o modo real.

- **Não é um antivírus.** A detecção de malware é do Microsoft Defender. As heurísticas apontam indícios e geram falsos positivos (jogos, mods e ferramentas de desenvolvimento costumam não ter assinatura).
- Arquivos do Windows e apps da Store são assinados por catálogo/pacote; por isso, executáveis em `C:\Windows` e `WindowsApps` são tratados como confiáveis sem verificação individual.
- "Último uso" vem do UserAssist (apps abertos pelo Menu Iniciar/Explorer), do Prefetch (só como administrador) e dos processos abertos. Sem administrador, muitos apps aparecem com uso "desconhecido" e nunca são sugeridos para remoção só por falta de uso.
- A conta "sem senha" é detectada pela flag `PasswordRequired=False`. O programa não tenta logar com senha vazia, para não gerar bloqueio de conta. A conta pode ter senha mesmo assim.
- O ponto de restauração depende da Proteção do Sistema e do limite de 1 ponto a cada 24 h do Windows.
- A busca de arquivos grandes e duplicados se limita às pastas do usuário e a cerca de 40 s. Duplicados são comparados por tamanho e pelo hash do início e do fim do arquivo.
- A temperatura vem das zonas térmicas ACPI. Leituras abaixo de 25 °C são descartadas como valor fixo de BIOS.
- A elevação do modo de melhorias usa a mesma conta. Se você entra com um usuário padrão e eleva com outra conta de administrador, a limpeza de `%TEMP%`, a Lixeira e os efeitos visuais afetam a conta de administrador.
