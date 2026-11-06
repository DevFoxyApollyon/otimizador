using System;
using System.Linq;
using System.Net;
using System.Text;

namespace PcDiagnostico
{
    /// <summary>Gera o relatório HTML autocontido (sem dependências externas, funciona offline).</summary>
    static class Relatorio
    {
        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        public static string Classe(Gravidade g)
        {
            switch (g)
            {
                case Gravidade.Critico: return "crit";
                case Gravidade.Aviso: return "warn";
                case Gravidade.Info: return "info";
                default: return "ok";
            }
        }

        public static string Rotulo(Gravidade g)
        {
            switch (g)
            {
                case Gravidade.Critico: return "Crítico";
                case Gravidade.Aviso: return "Aviso";
                case Gravidade.Info: return "Informação";
                default: return "OK";
            }
        }

        const string Css = @"
:root{--bg:#f3f4f7;--surface:#fff;--surface2:#f7f8fa;--text:#1b2130;--muted:#5d6678;--border:#e2e5eb;
--crit:#c62828;--crit-bg:#fdecec;--warn:#a85f00;--warn-bg:#fff3df;--info:#1f5fbf;--info-bg:#e9f0fc;--ok:#1b7a43;--ok-bg:#e6f5ec;
--code-bg:#eceef3;--accent:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--surface:#161a22;--surface2:#1c212b;--text:#e7eaf0;--muted:#9aa3b3;--border:#2a303c;
--crit:#ff7b7b;--crit-bg:rgba(255,123,123,.13);--warn:#ffb547;--warn-bg:rgba(255,181,71,.13);--info:#82abff;--info-bg:rgba(130,171,255,.13);
--ok:#62d394;--ok-bg:rgba(98,211,148,.13);--code-bg:#0a0d12;--accent:#93a6ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 'Segoe UI Variable Text','Segoe UI',system-ui,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:36px 16px 72px}
header h1{font-size:30px;line-height:1.15;margin:0 0 6px;letter-spacing:-.015em;font-weight:700}
.sub{color:var(--muted);margin:0}
.status{margin:22px 0 18px;padding:16px 18px;border-radius:12px;border:1px solid var(--border);border-left:5px solid var(--c);background:var(--surface);font-weight:600;font-size:16px}
.status small{display:block;font-weight:400;color:var(--muted);font-size:14px;margin-top:2px}
.notice{margin:0 0 18px;padding:12px 16px;border-radius:10px;background:var(--info-bg);color:var(--text);font-size:14px;border:1px solid var(--border)}
.notice b{color:var(--info)}
.notice ul{margin:6px 0 0;padding-left:20px;color:var(--muted)}
.sys{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin:0}
.sys div{background:var(--surface);padding:10px 14px;min-width:0}
.sys dt{font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.sys dd{margin:2px 0 0;font-weight:500;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:22px 0 6px}
.tile{cursor:pointer;border:1px solid var(--border);background:var(--surface);border-radius:12px;padding:12px 14px;text-align:left;color:var(--muted);font:inherit;font-size:13.5px;transition:border-color .15s,transform .15s}
.tile:hover{border-color:var(--accent)}
.tile b{display:block;font-size:28px;line-height:1.15;color:var(--text);font-variant-numeric:tabular-nums}
.tile.crit b{color:var(--crit)}.tile.warn b{color:var(--warn)}.tile.info b{color:var(--info)}.tile.ok b{color:var(--ok)}
.tile.sel{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
section h2{font-size:18px;margin:34px 0 12px;display:flex;flex-wrap:wrap;align-items:center;gap:8px;letter-spacing:-.005em}
.cnt{font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px;background:var(--cb);color:var(--c)}
.card{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:10px;padding:14px 18px;margin-bottom:10px}
.crit{--c:var(--crit);--cb:var(--crit-bg)}.warn{--c:var(--warn);--cb:var(--warn-bg)}.info{--c:var(--info);--cb:var(--info-bg)}.ok{--c:var(--ok);--cb:var(--ok-bg)}
.card.ok{padding:10px 18px}
.head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.pill{flex:none;font-size:11.5px;font-weight:700;padding:2px 9px;border-radius:999px;background:var(--cb);color:var(--c);text-transform:uppercase;letter-spacing:.03em}
.card h3{margin:0;font-size:15.5px;font-weight:600;overflow-wrap:anywhere;flex:1;min-width:0}
.desc{margin:6px 0 0}
.card.ok .desc{color:var(--muted);font-size:14px;margin-top:2px}
.det{margin:8px 0 0;font-size:13.5px;color:var(--muted)}
.det summary{cursor:pointer;color:var(--accent);font-weight:500}
.det ul{margin:6px 0 0;padding-left:18px}
.det li{overflow-wrap:anywhere;margin:2px 0}
.sol{margin-top:12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:14px}
.sol>b{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:2px}
.sol ol{margin:4px 0 0;padding-left:22px}
.sol ol li{margin:3px 0;padding-left:2px}
.sol .cmdlbl{margin:10px 0 0;font-size:12.5px;color:var(--muted)}
.cmd{display:flex;gap:8px;align-items:stretch;margin-top:8px}
.cmd code{flex:1;min-width:0;background:var(--code-bg);padding:7px 10px;border-radius:6px;font:13px/1.4 'Cascadia Mono',Consolas,monospace;overflow-x:auto;white-space:pre;color:var(--text)}
.cmd button{flex:none;font:inherit;font-size:12.5px;padding:0 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer}
.cmd button:hover{border-color:var(--accent)}
.empty{color:var(--muted);font-style:italic;display:none}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:13px}
.hide{display:none!important}
.pecas{margin:0 0 18px;padding:14px 18px;border-radius:12px;border:1px solid var(--border);background:var(--surface)}
.pecas>b{display:block;font-size:16px;margin-bottom:6px}
.pecas ul{list-style:none;margin:0 0 8px;padding:0}
.pecas li{padding:6px 0;border-bottom:1px solid var(--border)}
.pecas li:last-child{border-bottom:0}
.pecas li small{display:block;color:var(--muted);margin-top:2px}
.pecas a{color:var(--accent);font-size:14px}
.pill.sus{background:rgba(157,78,221,.13);color:#8a3fd1}
@media (prefers-color-scheme:dark){.pill.sus{color:#c77dff}}
.tile.sus b{color:#9d4edd}
.toc{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 0}
.toc a{font-size:13px;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);text-decoration:none}
.toc a:hover{border-color:var(--accent)}
.toc a i{font-style:normal;color:var(--crit);font-weight:600;margin-left:5px}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:16px 0 10px}
.chip{font:inherit;font-size:13px;padding:5px 12px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer}
.chip.sel{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
#busca{font:inherit;font-size:14px;padding:6px 10px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text);min-width:0;flex:1 1 200px}
.tbl{overflow:auto;max-height:80vh;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
#apps{border-collapse:collapse;width:100%;font-size:13.5px;min-width:900px}
#apps th{text-align:left;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);padding:9px 10px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface);z-index:1}
#apps td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top}
#apps tr:last-child td{border-bottom:0}
#apps td.num{white-space:nowrap;font-variant-numeric:tabular-nums}
#apps small{display:block;color:var(--muted)}
#apps .cls{color:var(--muted);font-size:12.5px}
#apps details summary{cursor:pointer;color:var(--accent)}
#apps details p{margin:4px 0}
#apps .cmd code{font-size:12px}
.rem{--c:var(--crit);--cb:var(--crit-bg)}.opc{--c:var(--warn);--cb:var(--warn-bg)}.man{--c:var(--ok);--cb:var(--ok-bg)}
.mel .card{--c:var(--accent);--cb:var(--info-bg)}
@media (max-width:560px){header h1{font-size:24px}.card{padding:12px 14px}.cmd{flex-direction:column}.cmd button{padding:6px}}
@media print{.tiles,.cmd button{display:none}.card{break-inside:avoid}}
";

        const string Js = @"
(function(){
var tiles=document.querySelectorAll('.tile');
tiles.forEach(function(t){t.addEventListener('click',function(){
var f=t.getAttribute('data-f');
tiles.forEach(function(x){x.classList.toggle('sel',x===t)});
document.querySelectorAll('.card').forEach(function(c){c.classList.toggle('hide',f==='sus'?c.getAttribute('data-sus')!=='1':(f!=='all'&&c.getAttribute('data-sev')!==f))});
document.querySelectorAll('section.cat').forEach(function(s){s.classList.toggle('hide',!s.querySelector('.card:not(.hide)'))});
});});
function copiar(txt,b){
function ok(){b.textContent='Copiado!';setTimeout(function(){b.textContent='Copiar'},1500)}
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(txt).then(ok,function(){fallback()})}else{fallback()}
function fallback(){var ta=document.createElement('textarea');ta.value=txt;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();try{document.execCommand('copy');ok()}catch(e){}document.body.removeChild(ta)}
}
document.querySelectorAll('.cmd button').forEach(function(b){b.addEventListener('click',function(){copiar(b.previousElementSibling.textContent,b)})});
var fr='all',busca=document.getElementById('busca');
function filtraApps(){var q=(busca&&busca.value||'').toLowerCase();var n=0;document.querySelectorAll('#apps tbody tr').forEach(function(r){var ok=(fr==='all'||r.getAttribute('data-r')===fr)&&(!q||r.getAttribute('data-n').indexOf(q)>=0);r.classList.toggle('hide',!ok);if(ok)n++});var c=document.getElementById('nApps');if(c)c.textContent=n}
document.querySelectorAll('.chip').forEach(function(c){c.addEventListener('click',function(){fr=c.getAttribute('data-r');document.querySelectorAll('.chip').forEach(function(x){x.classList.toggle('sel',x===c)});filtraApps()})});
if(busca)busca.addEventListener('input',filtraApps);
})();
";

        public static string Gerar(Diagnostico d)
        {
            int nc = d.Achados.Count(a => a.Gravidade == Gravidade.Critico);
            int na = d.Achados.Count(a => a.Gravidade == Gravidade.Aviso);
            int ni = d.Achados.Count(a => a.Gravidade == Gravidade.Info);
            int no = d.Achados.Count(a => a.Gravidade == Gravidade.Ok);

            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            sb.Append("<meta name=\"color-scheme\" content=\"light dark\">");
            sb.Append("<title>Diagnóstico do PC — ").Append(H(Environment.MachineName)).Append("</title><style>").Append(Css).Append("</style></head><body><div class=\"wrap\">");

            sb.Append("<header><h1>Diagnóstico do PC</h1><p class=\"sub\">")
              .Append(H(Environment.MachineName)).Append(" · ").Append(H(d.Inicio.ToString("dd 'de' MMMM 'de' yyyy, HH:mm", F.BR)))
              .Append(" · análise concluída em ").Append((int)Math.Max(1, d.Duracao.TotalSeconds)).Append(" s</p></header>");

            string statusClasse, statusTexto, statusSub;
            if (nc > 0)
            {
                statusClasse = "crit";
                statusTexto = nc + (nc == 1 ? " problema crítico encontrado" : " problemas críticos encontrados");
                statusSub = "Comece pelos itens vermelhos: eles podem causar perda de dados, falhas ou riscos de segurança.";
            }
            else if (na > 0)
            {
                statusClasse = "warn";
                statusTexto = "Nenhum problema crítico, mas " + na + (na == 1 ? " ponto merece atenção" : " pontos merecem atenção");
                statusSub = "Os itens em laranja não são urgentes, mas resolver melhora a estabilidade e o desempenho.";
            }
            else
            {
                statusClasse = "ok";
                statusTexto = "Tudo certo com este PC";
                statusSub = "Nenhum problema crítico ou aviso encontrado. Veja as sugestões informativas abaixo.";
            }
            sb.Append("<div class=\"status ").Append(statusClasse).Append("\">").Append(H(statusTexto)).Append("<small>").Append(H(statusSub)).Append("</small></div>");

            // Reinício e travamento no topo
            sb.Append("<div class=\"pecas ").Append(d.MotivosReinicio.Count > 0 ? "warn" : "ok").Append("\" style=\"border-left:5px solid var(--c)\"><b>")
              .Append(d.MotivosReinicio.Count > 0 ? "O PC precisa reiniciar" : "O PC não precisa reiniciar agora").Append("</b>");
            if (d.MotivosReinicio.Count > 0)
            {
                sb.Append("<ul>");
                foreach (var m in d.MotivosReinicio) sb.Append("<li>").Append(H(m)).Append("</li>");
                sb.Append("</ul><p style=\"margin:0;font-size:14px\">Salve seus arquivos e use Iniciar &gt; Energia &gt; <b>Reiniciar</b> (não \"Desligar\"), ou a opção [11] do programa.</p>");
            }
            sb.Append("</div>");
            if (d.Travamento != null)
            {
                var t = d.Travamento;
                bool trav = t.Causas.Count > 0;
                sb.Append("<div class=\"pecas ").Append(trav ? (t.Causas.Any(c => c.Item1 == Gravidade.Critico) ? "crit" : "warn") : "ok").Append("\" style=\"border-left:5px solid var(--c)\"><b>")
                  .Append(trav ? "O que está travando o PC" : "Nada está travando o PC agora").Append("</b><p style=\"margin:0 0 6px;font-size:14px;color:var(--muted)\">Medido durante o diagnóstico: processador ")
                  .Append(F.Pct(t.CpuTotal)).Append(", memória ").Append(F.Pct(t.MemPct)).Append(", disco ").Append(F.Pct(t.DiscoPct)).Append(" do tempo ocupado.</p>");
                if (trav)
                {
                    sb.Append("<ul>");
                    foreach (var c in t.Causas) sb.Append("<li>").Append(H(c.Item2)).Append("<small>").Append(H(c.Item3)).Append("</small></li>");
                    sb.Append("</ul><a href=\"#s").Append(Array.IndexOf(Cat.Ordem, Cat.Desempenho)).Append("\">Ver passo a passo ↓</a>");
                }
                sb.Append("</div>");
            }

            // Quadro de peças no topo
            var recs = d.Achados.Where(a => a.Impacto != null).OrderBy(a => a.Impacto == "alto" ? 0 : a.Impacto == "médio" ? 1 : 2).ToList();
            sb.Append("<div class=\"pecas\"><b>Peças: o que trocar ou melhorar</b>");
            if (recs.Count == 0) sb.Append("<p>Nenhuma peça precisa ser trocada agora: o hardware atende bem ao uso detectado.</p>");
            else
            {
                sb.Append("<ul>");
                foreach (var a in recs)
                {
                    string preco = a.Detalhes.FirstOrDefault(x => x.StartsWith("Preço"));
                    sb.Append("<li class=\"").Append(a.Impacto == "alto" ? "crit" : a.Impacto == "médio" ? "warn" : "info").Append("\"><span class=\"pill\">Impacto ").Append(H(a.Impacto)).Append("</span> ")
                      .Append(H(a.Titulo));
                    if (preco != null)
                    {
                        string p = preco.Substring(preco.IndexOf(':') + 1).Trim();
                        sb.Append("<small>").Append(H(p == "grátis" ? "Custo: grátis (só configuração na BIOS)" : "Preço estimado: " + p)).Append("</small>");
                    }
                    string ex = a.Detalhes.FirstOrDefault(x => x.StartsWith(Diagnostico.PrefixoCompra));
                    if (ex != null) sb.Append("<small><b>").Append(H(ex.Substring(0, ex.IndexOf(':') + 1))).Append("</b> ").Append(H(ex.Substring(ex.IndexOf(':') + 1).Replace(" — verifique disponibilidade e compatibilidade antes de comprar.", "").Trim())).Append("</small>");
                    sb.Append("</li>");
                }
                sb.Append("</ul>");
            }
            sb.Append("<a href=\"#s").Append(Array.IndexOf(Cat.Ordem, Cat.Upgrade)).Append("\">Ver detalhes, motivos e compatibilidade ↓</a></div>");

            if (!d.Admin && d.TestesSemPermissao.Count > 0)
            {
                sb.Append("<div class=\"notice\"><b>Executado sem privilégios de administrador.</b> Algumas verificações foram puladas. Para um diagnóstico completo, clique com o botão direito no programa e escolha <i>Executar como administrador</i>.<ul>");
                foreach (var t in d.TestesSemPermissao) sb.Append("<li>").Append(H(t)).Append("</li>");
                sb.Append("</ul></div>");
            }

            sb.Append("<dl class=\"sys\">");
            foreach (var kv in d.InfoSistema)
                sb.Append("<div><dt>").Append(H(kv.Key)).Append("</dt><dd>").Append(H(kv.Value)).Append("</dd></div>");
            sb.Append("</dl>");

            sb.Append("<div class=\"tiles\">");
            Tile(sb, "all", "", d.Achados.Count, "Todos os itens", true);
            Tile(sb, "crit", "crit", nc, "Críticos", false);
            Tile(sb, "warn", "warn", na, "Avisos", false);
            Tile(sb, "info", "info", ni, "Informações", false);
            Tile(sb, "ok", "ok", no, "Tudo OK", false);
            int ns = d.Achados.Count(a => a.Suspeito);
            if (ns > 0) Tile(sb, "sus", "sus", ns, "Itens suspeitos", false);
            sb.Append("</div>");

            sb.Append("<nav class=\"toc\">");
            for (int ci = 0; ci < Cat.Ordem.Length; ci++)
            {
                string cn = Cat.Ordem[ci];
                if (!d.Achados.Any(a => a.Categoria == cn)) continue;
                int q = d.Achados.Count(a => a.Categoria == cn && a.Gravidade <= Gravidade.Aviso);
                sb.Append("<a href=\"#s").Append(ci).Append("\">").Append(H(cn.Split('(')[0].Trim())).Append(q > 0 ? "<i>" + q + "</i>" : "").Append("</a>");
            }
            if (d.MelhoriasDisponiveis.Count > 0) sb.Append("<a href=\"#melhorias\">Melhorias aplicáveis</a>");
            sb.Append("</nav>");

            foreach (string cat in Cat.Ordem)
            {
                var itens = d.Achados.Where(a => a.Categoria == cat).OrderBy(a => a.Gravidade).ToList();
                if (itens.Count == 0) continue;
                sb.Append("<section class=\"cat\" id=\"s").Append(Array.IndexOf(Cat.Ordem, cat)).Append("\"><h2>").Append(H(cat));
                foreach (Gravidade g in new[] { Gravidade.Critico, Gravidade.Aviso })
                {
                    int n = itens.Count(a => a.Gravidade == g);
                    if (n > 0) sb.Append(" <span class=\"cnt ").Append(Classe(g)).Append("\">").Append(n).Append(" ").Append(H(g == Gravidade.Critico ? (n == 1 ? "crítico" : "críticos") : (n == 1 ? "aviso" : "avisos"))).Append("</span>");
                }
                sb.Append("</h2>");
                foreach (var a in itens) Card(sb, a);
                if (cat == Cat.Apps && d.Apps.Count > 0) TabelaApps(sb, d);
                sb.Append("</section>");
            }
            SecaoMelhorias(sb, d);

            sb.Append("<footer>Este relatório foi gerado pelo <b>Diagnóstico do PC</b>, que apenas lê informações do sistema e <b>não altera nada</b> no computador. ")
              .Append("Os comandos sugeridos só são executados se você mesmo os rodar. Na dúvida sobre um item crítico, procure um técnico de confiança.</footer>");
            sb.Append("</div><script>").Append(Js).Append("</script></body></html>");
            return sb.ToString();
        }

        static void TabelaApps(StringBuilder sb, Diagnostico d)
        {
            var apps = d.Apps.OrderBy(a => a.Recomendacao).ThenByDescending(a => a.Tamanho).ThenBy(a => a.Nome).ToList();
            int nr = apps.Count(a => a.Recomendacao == Recomendacao.Remover), no = apps.Count(a => a.Recomendacao == Recomendacao.Opcional), nm = apps.Count(a => a.Recomendacao == Recomendacao.Manter);
            sb.Append("<div class=\"tools\"><button class=\"chip sel\" data-r=\"all\">Todos (").Append(apps.Count).Append(")</button>")
              .Append("<button class=\"chip\" data-r=\"rem\">Recomendado remover (").Append(nr).Append(")</button>")
              .Append("<button class=\"chip\" data-r=\"opc\">Opcional (").Append(no).Append(")</button>")
              .Append("<button class=\"chip\" data-r=\"man\">Manter (").Append(nm).Append(")</button>")
              .Append("<input id=\"busca\" type=\"search\" placeholder=\"Buscar aplicativo ou editor…\" aria-label=\"Buscar aplicativo\"></div>");
            sb.Append("<p class=\"sub\" style=\"font-size:13px;margin:0 0 8px\"><span id=\"nApps\">").Append(apps.Count)
              .Append("</span> aplicativos mostrados. O PCDiagnostico nunca remove nada: use o comando ou Configurações &gt; Aplicativos.</p>");
            sb.Append("<div class=\"tbl\"><table id=\"apps\"><thead><tr><th>Aplicativo</th><th>Editor</th><th>Tamanho</th><th>Instalado</th><th>Último uso</th><th>Classificação</th><th>Recomendação</th></tr></thead><tbody>");
            foreach (var a in apps)
            {
                string r = a.Recomendacao == Recomendacao.Remover ? "rem" : a.Recomendacao == Recomendacao.Opcional ? "opc" : "man";
                string rt = a.Recomendacao == Recomendacao.Remover ? "Recomendado remover" : a.Recomendacao == Recomendacao.Opcional ? "Opcional" : "Manter";
                string uso = a.UltimoUso.HasValue ? F.Dia(a.UltimoUso.Value) : a.UsoDesconhecido ? "desconhecido" : "sem registro";
                sb.Append("<tr data-r=\"").Append(r).Append("\" data-n=\"").Append(H((a.Nome + " " + a.Editor).ToLowerInvariant())).Append("\">")
                  .Append("<td><b>").Append(H(a.Nome)).Append("</b><small>").Append(H(a.Tipo + (string.IsNullOrEmpty(a.Versao) ? "" : " · v" + a.Versao))).Append("</small></td>")
                  .Append("<td>").Append(H(string.IsNullOrEmpty(a.Editor) ? "—" : a.Editor)).Append("</td>")
                  .Append("<td class=\"num\">").Append(a.Tamanho > 0 ? H(F.Bytes(a.Tamanho)) : "—").Append("</td>")
                  .Append("<td class=\"num\">").Append(a.InstaladoEm.HasValue ? F.Dia(a.InstaladoEm.Value) : "—").Append("</td>")
                  .Append("<td class=\"num\">").Append(H(uso)).Append("</td>")
                  .Append("<td class=\"cls\">").Append(H(a.Classificacao.Count > 0 ? string.Join("; ", a.Classificacao) : "—")).Append("</td>")
                  .Append("<td class=\"").Append(r).Append("\"><span class=\"pill\">").Append(rt).Append("</span>")
                  .Append("<details><summary>Motivo e comando</summary><p>").Append(H(a.Motivo)).Append("</p>");
                if (!string.IsNullOrEmpty(a.ComandoDesinstalar) && a.Recomendacao != Recomendacao.Manter)
                    sb.Append("<div class=\"cmd\"><code>").Append(H(a.ComandoDesinstalar)).Append("</code><button type=\"button\">Copiar</button></div>");
                else if (!string.IsNullOrEmpty(a.ComandoDesinstalar))
                    sb.Append("<p style=\"color:var(--muted)\">Desinstalação: Configurações &gt; Aplicativos &gt; Aplicativos instalados.</p>");
                sb.Append("</details></td></tr>");
            }
            sb.Append("</tbody></table></div>");
        }

        static void SecaoMelhorias(StringBuilder sb, Diagnostico d)
        {
            if (d.MelhoriasDisponiveis.Count == 0) return;
            sb.Append("<section class=\"mel\" id=\"melhorias\"><h2>Melhorias que o programa pode aplicar</h2>")
              .Append("<div class=\"notice\" style=\"background:var(--surface)\">Por segurança, este relatório não executa nada. Para aplicar, abra o <b>PCDiagnostico.exe</b> e escolha <b>[2] Aplicar melhorias</b> no menu final (ou rode o comando abaixo). ")
              .Append("Você escolhe item por item e confirma cada um; antes de qualquer mudança é criado um ponto de restauração do Windows e tudo é registrado em <i>Documentos\\Diagnóstico do PC\\melhorias-log.txt</i>.")
              .Append("<div class=\"cmd\"><code>PCDiagnostico.exe --melhorias</code><button type=\"button\">Copiar</button></div>")
              .Append("<p style=\"margin:12px 0 0\"><b>Correção automática:</b> a opção <b>[5] Corrigir automaticamente</b> aplica de uma vez só as correções seguras (temporários, cache do Windows Update, DISM/SFC, TRIM/otimização, plano de energia em modo economia, programas pesados na inicialização, assinaturas e verificação do Defender, e religa firewall/Defender/UAC ou desliga o SMBv1 quando necessário), com uma única confirmação, ponto de restauração antes e resumo \"corrigido / falhou / ação manual\" no final. Não desinstala apps, não mexe em drivers/BIOS e não apaga arquivos seus.</p>")
              .Append("<div class=\"cmd\"><code>PCDiagnostico.exe --corrigir</code><button type=\"button\">Copiar</button></div></div>");
            foreach (var m in d.MelhoriasDisponiveis)
            {
                sb.Append("<article class=\"card\"><div class=\"head\"><span class=\"pill\">Melhoria</span><h3>").Append(H(m.Titulo)).Append("</h3></div>")
                  .Append("<p class=\"desc\">").Append(H(m.Descricao)).Append("</p>")
                  .Append("<details class=\"det\" open><summary>Situação e risco</summary><ul><li>Situação: ").Append(H(m.Estado)).Append("</li><li>Risco: ").Append(H(m.Risco)).Append("</li></ul></details></article>");
            }
            sb.Append("</section>");
        }

        static void Tile(StringBuilder sb, string f, string cls, int n, string rotulo, bool sel)
        {
            sb.Append("<button class=\"tile ").Append(cls).Append(sel ? " sel" : "").Append("\" data-f=\"").Append(f).Append("\"><b>")
              .Append(n).Append("</b>").Append(H(rotulo)).Append("</button>");
        }

        static void Card(StringBuilder sb, Achado a)
        {
            string c = Classe(a.Gravidade);
            sb.Append("<article class=\"card ").Append(c).Append("\" data-sev=\"").Append(c).Append(a.Suspeito ? "\" data-sus=\"1" : "").Append("\"><div class=\"head\"><span class=\"pill\">")
              .Append(H(a.Impacto != null ? "Impacto " + a.Impacto : Rotulo(a.Gravidade))).Append("</span>")
              .Append(a.Suspeito ? "<span class=\"pill sus\" title=\"Indício, não uma infecção confirmada\">Suspeito</span>" : "").Append("<h3>").Append(H(a.Titulo)).Append("</h3></div>");
            if (!string.IsNullOrEmpty(a.Descricao)) sb.Append("<p class=\"desc\">").Append(H(a.Descricao)).Append("</p>");
            if (!string.IsNullOrEmpty(a.Link))
                sb.Append("<p class=\"desc\"><a href=\"").Append(H(a.Link)).Append("\" target=\"_blank\" rel=\"noopener noreferrer\" style=\"color:var(--accent)\">")
                  .Append(H(a.TextoLink ?? a.Link)).Append(" ↗</a></p>");

            if (a.Detalhes.Count > 0)
            {
                bool aberto = a.Detalhes.Count <= 4 && a.Gravidade != Gravidade.Ok;
                if (a.Gravidade == Gravidade.Ok && a.Detalhes.Count <= 4) aberto = true;
                sb.Append("<details class=\"det\"").Append(aberto ? " open" : "").Append("><summary>Detalhes (")
                  .Append(a.Detalhes.Count).Append(a.Detalhes.Count == 1 ? " item" : " itens").Append(")</summary><ul>");
                foreach (var t in a.Detalhes) sb.Append("<li>").Append(H(t)).Append("</li>");
                sb.Append("</ul></details>");
            }

            if (!string.IsNullOrEmpty(a.Solucao) || a.Comandos.Count > 0)
            {
                var passos = Passos.De(a.Solucao);
                sb.Append("<div class=\"sol\"><b>").Append(passos.Count > 1 ? "Passo a passo para resolver" : "Como resolver").Append("</b>");
                if (passos.Count > 1)
                {
                    sb.Append("<ol>");
                    foreach (var p in passos) sb.Append("<li>").Append(H(p)).Append("</li>");
                    sb.Append("</ol>");
                }
                else if (passos.Count == 1) sb.Append(H(passos[0]));
                if (a.Comandos.Count > 0)
                    sb.Append("<p class=\"cmdlbl\">").Append(a.Comandos.Count == 1 ? "Comando útil" : "Comandos úteis")
                      .Append(" (copie e cole no Terminal; os que terminam em .msc ou .exe também funcionam em Win+R):</p>");
                foreach (var cmd in a.Comandos)
                    sb.Append("<div class=\"cmd\"><code>").Append(H(cmd)).Append("</code><button type=\"button\">Copiar</button></div>");
                sb.Append("</div>");
            }
            sb.Append("</article>");
        }
    }
}
