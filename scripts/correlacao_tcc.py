#!/usr/bin/env python3
"""
Teste de correlacao de eventos de rede com IoCs do MISP (laboratorio do TCC).

1. Le do MISP os indicadores de rede (IP, dominio/host e URL) marcados para deteccao (to_ids).
2. Monta eventos de rede SIMULADOS, com rotulo definido antes das consultas:
     - positivos exatos: o indicador no mesmo formato em que esta no MISP;
     - positivos com variacao de formato: o mesmo indicador como costuma aparecer em logs
       (IP:porta, nome DNS em maiusculas com ponto final, dominio dentro de URL,
       URL com host em maiusculas ou com a porta padrao explicita);
     - negativos: enderecos e dominios benignos conhecidos.
   Com --real ARQUIVO, inclui observaveis reais (por exemplo, o cache DNS do Windows), sem rotulo.
3. Consulta cada evento no MISP com tres estrategias:
     A) exata: o valor do log como esta (correspondencia por valor, como a correlacao nativa);
     B) normalizada: consulta tambem o valor sem porta, sem ponto final, com host em minusculas
        e, no caso de URLs, o host extraido;
     C) normalizada com filtros: so gera alerta se a correspondencia tiver to_ids e nao estiver
        em warninglist.
4. Calcula VP, FP, FN, VN, precisao e revocacao, mede o tempo das consultas e registra o contexto
   das correspondencias (evento, fonte, data, to_ids e warninglists).

Nenhum IP, dominio ou URL e acessado: o teste so compara valores dentro do MISP.
A chave de API e pedida sem aparecer na tela e nao e gravada. Use uma chave somente leitura.
Somente a biblioteca padrao do Python 3 e usada.

Uso (no Ubuntu):
    python3 correlacao_tcc.py                                   # gera o conjunto e testa
    python3 correlacao_tcc.py --real dns_cache.txt              # inclui observaveis reais
    python3 correlacao_tcc.py --conjunto conjunto_teste_X.csv   # repete com o mesmo conjunto
"""
import argparse
import collections
import csv
import datetime as dt
import getpass
import json
import os
import random
import re
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SEMENTE = 42
MAX_POSITIVOS = 20
LIMITE_PAGINA = 5000
TIPOS_REDE = ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain", "hostname", "domain|ip", "url"]
CATEGORIAS = ("IP", "Dominio", "URL")
IP_LAB = "192.168.0.10"  # endereco ficticio do computador de origem nos eventos simulados
PORTAS = (443, 80, 8080, 53, 22)

# Valores benignos conhecidos (rotulo "benigno" definido antes do teste)
NEGATIVOS = [
    ("IP", "8.8.8.8"), ("IP", "8.8.4.4"), ("IP", "1.1.1.1"), ("IP", "1.0.0.1"), ("IP", "9.9.9.9"),
    ("IP", "208.67.222.222"), ("IP", "192.168.0.1"), ("IP", "192.168.1.1"), ("IP", "10.0.0.1"),
    ("IP", "127.0.0.1"),
    ("Dominio", "google.com"), ("Dominio", "www.google.com"), ("Dominio", "microsoft.com"),
    ("Dominio", "windowsupdate.com"), ("Dominio", "wikipedia.org"), ("Dominio", "youtube.com"),
    ("Dominio", "whatsapp.com"), ("Dominio", "instagram.com"), ("Dominio", "github.com"),
    ("Dominio", "ubuntu.com"), ("Dominio", "gov.br"), ("Dominio", "www.gov.br"),
    ("Dominio", "uol.com.br"), ("Dominio", "globo.com"), ("Dominio", "mercadolivre.com.br"),
    ("Dominio", "bb.com.br"), ("Dominio", "office.com"), ("Dominio", "cloudflare.com"),
    ("Dominio", "unifagoc.edu.br"), ("Dominio", "misp-project.org"),
    ("URL", "https://www.google.com/"), ("URL", "https://www.gov.br/pt-br"),
    ("URL", "https://github.com/MISP/MISP"), ("URL", "https://www.unifagoc.edu.br/"),
]

RE_ESQUEMA = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
RE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
RE_IPV4_PORTA = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
RE_IPV6_PORTA = re.compile(r"^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$")

CAMPOS_CONJUNTO = ["id", "grupo", "variacao", "categoria", "evento_simulado", "observavel", "indicador", "rotulo"]


# --------------------------------------------------------------------- API
class Misp:
    def __init__(self, url, chave):
        self.url = url.rstrip("/")
        self.chave = chave
        self.ctx = ssl._create_unverified_context()  # certificado autoassinado do laboratorio

    def chamar(self, caminho, corpo=None, timeout=300):
        dados = json.dumps(corpo).encode() if corpo is not None else None
        req = urllib.request.Request(self.url + caminho, data=dados,
                                     method="POST" if corpo is not None else "GET")
        req.add_header("Authorization", self.chave)
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))


def lista_atributos(resposta):
    if isinstance(resposta, dict):
        r = resposta.get("response", resposta)
        if isinstance(r, dict):
            return r.get("Attribute", []) or []
        if isinstance(r, list):
            return r
    return []


def verdadeiro(x):
    return x in (True, 1, "1", "true", "True")


def categoria_tipo(tipo):
    if tipo.startswith("ip-"):
        return "IP"
    if tipo in ("domain", "hostname", "domain|ip"):
        return "Dominio"
    return "URL"


def mapa_eventos(api):
    eventos = {}
    pagina = 1
    while True:
        lote = api.chamar("/events/index", {"limit": 500, "page": pagina})
        if not lote:
            break
        for item in lote:
            e = item.get("Event", item)
            orgc = (e.get("Orgc") or item.get("Orgc") or {}).get("name") or f"orgc_id {e.get('orgc_id')}"
            eventos[str(e.get("id"))] = {"info": e.get("info"), "data": e.get("date"), "fonte": orgc}
        if len(lote) < 500:
            break
        pagina += 1
    return eventos


def ler_indicadores(api):
    """Indicadores de rede com to_ids: {(categoria, valor): {ids de evento}}."""
    ind = collections.OrderedDict()
    pagina = 1
    while True:
        corpo = {"returnFormat": "json", "type": TIPOS_REDE, "to_ids": 1, "limit": LIMITE_PAGINA,
                 "page": pagina}
        lote = lista_atributos(api.chamar("/attributes/restSearch", corpo, timeout=900))
        for a in lote:
            if not verdadeiro(a.get("to_ids")):
                continue
            tipo = a.get("type", "")
            valor = (a.get("value") or "").strip()
            if tipo in ("ip-src|port", "ip-dst|port", "domain|ip"):
                valor = valor.split("|")[0].strip()
            if valor:
                ind.setdefault((categoria_tipo(tipo), valor), set()).add(str(a.get("event_id")))
        if len(lote) < LIMITE_PAGINA:
            break
        pagina += 1
    return ind


# ------------------------------------------------------- conjunto de teste
def amostrar(indicadores, excluir, n=MAX_POSITIVOS):
    """Amostra estratificada (IP, dominio, URL), com semente fixa para ser reproduzivel."""
    rng = random.Random(SEMENTE)
    filas = {c: sorted(v for (cat, v) in indicadores if cat == c and v.lower() not in excluir)
             for c in CATEGORIAS}
    for c in CATEGORIAS:
        rng.shuffle(filas[c])
    escolhidos = []
    while len(escolhidos) < n and any(filas.values()):
        for c in CATEGORIAS:
            if filas[c] and len(escolhidos) < n:
                escolhidos.append((c, filas[c].pop(0)))
    return escolhidos


def _partes_netloc(netloc):
    usuario, arroba, resto = netloc.rpartition("@")
    prefixo = usuario + arroba
    if resto.startswith("["):
        fim = resto.find("]") + 1
        return prefixo, resto[:fim], resto[fim:]
    host, dois_pontos, porta = resto.partition(":")
    return prefixo, host, dois_pontos + porta


def variante(cat, valor, i):
    """O mesmo indicador no formato em que costuma aparecer em logs (o rotulo continua 'malicioso')."""
    if cat == "IP":
        porta = PORTAS[i % len(PORTAS)]
        obs = f"[{valor}]:{porta}" if ":" in valor else f"{valor}:{porta}"
        return obs, "IP com porta", f"conexao {IP_LAB} -> {obs}"
    if cat == "Dominio":
        if i % 2 == 0:
            obs = valor.upper() + "."
            return obs, "nome DNS em maiusculas com ponto final", f"consulta DNS {obs}"
        obs = f"http://{valor}/index.php"
        return obs, "dominio dentro de URL", f"HTTP GET {obs}"
    if RE_ESQUEMA.match(valor):
        p = urllib.parse.urlsplit(valor)
        prefixo, host, porta = _partes_netloc(p.netloc)
        if not host.startswith("[") and re.search(r"[a-zA-Z]", host):
            obs = urllib.parse.urlunsplit((p.scheme, prefixo + host.upper() + porta, p.path, p.query,
                                           p.fragment))
            tipo_var = "URL com host em maiusculas"
        elif not porta and p.scheme.lower() in ("http", "https"):
            padrao = 80 if p.scheme.lower() == "http" else 443
            obs = urllib.parse.urlunsplit((p.scheme, f"{prefixo}{host}:{padrao}", p.path, p.query,
                                           p.fragment))
            tipo_var = "URL com porta padrao explicita"
        else:
            obs = p.scheme.upper() + valor[len(p.scheme):]
            tipo_var = "URL com esquema em maiusculas"
    else:
        host, barra, resto = valor.partition("/")
        obs = host.upper() + barra + resto
        tipo_var = "URL com host em maiusculas"
    return obs, tipo_var, f"HTTP GET {obs}"


def evento_base(cat, v):
    return {"IP": f"conexao {IP_LAB} -> {v}", "Dominio": f"consulta DNS {v}", "URL": f"HTTP GET {v}"}[cat]


def montar_conjunto(indicadores, reais):
    excluir = {v.lower() for _, v in NEGATIVOS}
    conflitos = sorted(v for (_, v) in indicadores if v.lower() in excluir)
    positivos = amostrar(indicadores, excluir)
    conj = []

    def novo(grupo, variacao, cat, evento, obs, indicador, rotulo):
        conj.append({"id": f"E{len(conj) + 1:03d}", "grupo": grupo, "variacao": variacao, "categoria": cat,
                     "evento_simulado": evento, "observavel": obs, "indicador": indicador, "rotulo": rotulo})

    for cat, v in positivos:
        novo("positivo exato", "-", cat, evento_base(cat, v), v, v, "malicioso")
    contador = collections.Counter()
    for cat, v in positivos:
        obs, tipo_var, evento = variante(cat, v, contador[cat])
        contador[cat] += 1
        novo("positivo com variacao", tipo_var, cat, evento, obs, v, "malicioso")
    for cat, v in NEGATIVOS:
        novo("negativo", "-", cat, evento_base(cat, v), v, "-", "benigno")
    for v in reais:
        cat = "IP" if RE_IPV4.match(v) else ("URL" if RE_ESQUEMA.match(v) else "Dominio")
        novo("real", "-", cat, "consulta DNS real", v, "-", "desconhecido")
    return conj, conflitos


def ler_conjunto(caminho):
    with open(caminho, encoding="utf-8-sig", newline="") as f:
        return [{k: linha.get(k, "") for k in CAMPOS_CONJUNTO} for linha in csv.DictReader(f, delimiter=";")]


def ler_reais(caminho):
    dados = open(caminho, "rb").read()
    if dados.startswith(b"\xff\xfe") or dados.startswith(b"\xfe\xff"):
        texto = dados.decode("utf-16")
    else:
        texto = dados.decode("utf-8-sig", "replace")
    vistos = []
    for linha in texto.splitlines():
        v = linha.strip()
        if not v or v.startswith("#") or " " in v or "." not in v:
            continue
        if v.lower().endswith((".in-addr.arpa", ".ip6.arpa")):
            continue
        if v not in vistos:
            vistos.append(v)
    return vistos


# -------------------------------------------------------- normalizacao (B)
def rearmar(v):
    v = v.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    for a, b in (("[://]", "://"), ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":")):
        v = v.replace(a, b)
    return v


def candidatos(obs):
    """Valores consultados na estrategia B: o original e suas formas normalizadas."""
    saida = []

    def add(x):
        if x and x not in saida:
            saida.append(x)

    add(obs.strip())
    v = rearmar(obs)
    if RE_ESQUEMA.match(v):
        p = urllib.parse.urlsplit(v)
        esquema = p.scheme.lower()
        host = (p.hostname or "").rstrip(".")
        try:
            porta = p.port
        except ValueError:
            porta = None
        padrao = {"http": 80, "https": 443}.get(esquema)
        h = f"[{host}]" if ":" in host else host
        netloc = h if porta in (None, padrao) else f"{h}:{porta}"
        add(urllib.parse.urlunsplit((esquema, netloc, p.path, p.query, p.fragment)))
        add(host)
        return saida
    m = RE_IPV4_PORTA.match(v) or RE_IPV6_PORTA.match(v)
    if m:
        add(m.group(1).lower())
        return saida
    host, barra, resto = v.partition("/")
    host = host.lower().rstrip(".")
    add(host + barra + resto)
    if barra:
        add(host)
    return saida


# ------------------------------------------------------------------ testes
def consultar(api, valores):
    corpo = {"returnFormat": "json", "value": valores[0] if len(valores) == 1 else valores,
             "limit": 100, "includeWarninglistHits": True}
    t0 = time.perf_counter()
    attrs = lista_atributos(api.chamar("/attributes/restSearch", corpo, timeout=120))
    return attrs, (time.perf_counter() - t0) * 1000


def resumir(attrs, eventos):
    hits = []
    for a in attrs:
        ev = str(a.get("event_id"))
        avisos = [w.get("warninglist_name") or w.get("name") or "?"
                  for w in (a.get("warnings") or []) if isinstance(w, dict)]
        hits.append({"evento": ev, "fonte": eventos.get(ev, {}).get("fonte", "?"),
                     "data_evento": eventos.get(ev, {}).get("data"), "tipo": a.get("type"),
                     "valor": a.get("value"), "to_ids": verdadeiro(a.get("to_ids")), "warninglists": avisos})
    return hits


def executar(api, conjunto, eventos):
    resultados = []
    for n, item in enumerate(conjunto, 1):
        obs = item["observavel"]
        attrs_a, ms_a = consultar(api, [obs])
        cands = candidatos(obs)
        attrs_b, ms_b = consultar(api, cands)
        hits_a, hits_b = resumir(attrs_a, eventos), resumir(attrs_b, eventos)
        r = dict(item)
        r.update({"candidatos_B": cands, "A": bool(hits_a), "B": bool(hits_b),
                  "C": any(h["to_ids"] and not h["warninglists"] for h in hits_b),
                  "ms_A": round(ms_a, 1), "ms_B": round(ms_b, 1), "hits_A": hits_a, "hits_B": hits_b})
        resultados.append(r)
        if n % 10 == 0:
            print(f"  {n}/{len(conjunto)} eventos consultados", file=sys.stderr)
    return resultados


def checar_warninglists(api, valores):
    """Verifica se os proprios observaveis estao em warninglists ativas no MISP."""
    try:
        r = api.chamar("/warninglists/checkValue", valores, timeout=300)
    except urllib.error.HTTPError as e:
        return None, f"nao disponivel (HTTP {e.code})"
    except Exception as e:  # noqa: BLE001
        return None, f"nao disponivel ({e.__class__.__name__})"
    if isinstance(r, list) and not r:
        return {}, None  # nenhuma ocorrencia
    if not isinstance(r, dict):
        return None, "nao disponivel (resposta em formato inesperado)"
    res = {}
    for v, lst in r.items():
        itens = lst if isinstance(lst, list) else [lst]
        nomes = [(w.get("name") or w.get("warninglist_name") or "?") if isinstance(w, dict) else str(w)
                 for w in itens if w]
        if nomes:
            res[v] = nomes
    return res, None


def metricas(resultados, chave):
    vp = fp = fn = vn = 0
    for r in resultados:
        if r["rotulo"] == "malicioso":
            vp, fn = (vp + 1, fn) if r[chave] else (vp, fn + 1)
        elif r["rotulo"] == "benigno":
            fp, vn = (fp + 1, vn) if r[chave] else (fp, vn + 1)
    prec = vp / (vp + fp) if vp + fp else None
    rev = vp / (vp + fn) if vp + fn else None
    return {"VP": vp, "FP": fp, "FN": fn, "VN": vn, "precisao": prec, "revocacao": rev}


def pct(x):
    return "n/d" if x is None else f"{100 * x:.1f}%"


def estat_ms(valores):
    if not valores:
        return "n/d"
    return (f"media {statistics.mean(valores):.1f} | mediana {statistics.median(valores):.1f} | "
            f"min {min(valores):.1f} | max {max(valores):.1f} (n={len(valores)})")


# --------------------------------------------------------------- relatorio
def escrever(base, momento, url, versao, conflitos, indicadores, resultados, wl_obs, wl_erro):
    rotulados = [r for r in resultados if r["rotulo"] in ("malicioso", "benigno")]
    reais = [r for r in resultados if r["rotulo"] == "desconhecido"]
    L = [f"TESTE DE CORRELACAO DE EVENTOS DE REDE COM IOCS - {momento}", "=" * 72,
         f"MISP: {url} (versao {versao})",
         "Regra de decisao (definida antes do teste): o evento e considerado correlacionado quando a",
         "consulta retorna ao menos um atributo; na estrategia C, quando ao menos um atributo",
         "retornado tem to_ids e nao esta em warninglist.",
         "Nenhum IP, dominio ou URL foi acessado: as consultas comparam valores dentro do MISP.", ""]

    cont_ind = collections.Counter(c for (c, _) in indicadores)
    L += ["[1] CONJUNTO DE TESTE",
          f"  Indicadores de rede com to_ids no MISP: {len(indicadores)} "
          f"(IP {cont_ind['IP']}, Dominio {cont_ind['Dominio']}, URL {cont_ind['URL']})"]
    if conflitos:
        L.append(f"  Valores benignos conhecidos que aparecem como indicador no MISP: {', '.join(conflitos)}")
    grupos = collections.Counter(r["grupo"] for r in resultados)
    L.append(f"  Eventos simulados: {len(resultados)}")
    for g in ("positivo exato", "positivo com variacao", "negativo", "real"):
        if grupos[g]:
            cats = collections.Counter(r["categoria"] for r in resultados if r["grupo"] == g)
            L.append(f"    - {g}: {grupos[g]} ({', '.join(f'{c} {cats[c]}' for c in CATEGORIAS if cats[c])})")
    var = collections.Counter(r["variacao"] for r in resultados if r["grupo"] == "positivo com variacao")
    for v, n in sorted(var.items()):
        L.append(f"        variacao '{v}': {n}")

    L += ["", "[2] RESULTADOS POR ESTRATEGIA (somente eventos rotulados)",
          "  Estrategia                                   VP   FP   FN   VN   Precisao  Revocacao"]
    nomes = {"A": "A - exata", "B": "B - normalizada", "C": "C - normalizada + filtros (to_ids e WL)"}
    resumo = {}
    for k in ("A", "B", "C"):
        m = metricas(rotulados, k)
        resumo[k] = m
        L.append(f"  {nomes[k]:<44} {m['VP']:>3}  {m['FP']:>3}  {m['FN']:>3}  {m['VN']:>3}   "
                 f"{pct(m['precisao']):>7}   {pct(m['revocacao']):>7}")

    L += ["", "[3] REVOCACAO POR GRUPO E TIPO DE VARIACAO (corretos / total)"]
    chaves_grupo = [("positivo exato", "-")] + [("positivo com variacao", v) for v in sorted(var)]
    for g, v in chaves_grupo:
        sub = [r for r in rotulados if r["grupo"] == g and r["variacao"] == v]
        if sub:
            nome = g if v == "-" else f"variacao: {v}"
            L.append(f"  {nome:<52} A {sum(r['A'] for r in sub)}/{len(sub)}  "
                     f"B {sum(r['B'] for r in sub)}/{len(sub)}  C {sum(r['C'] for r in sub)}/{len(sub)}")
    neg = [r for r in rotulados if r["rotulo"] == "benigno"]
    if neg:
        L.append(f"  {'negativos sem correspondencia (VN)':<52} A {sum(not r['A'] for r in neg)}/{len(neg)}  "
                 f"B {sum(not r['B'] for r in neg)}/{len(neg)}  C {sum(not r['C'] for r in neg)}/{len(neg)}")

    L += ["", "[4] ERROS (falsos positivos e falsos negativos)"]
    erros = 0
    for r in rotulados:
        marcas = []
        for k in ("A", "B", "C"):
            if r["rotulo"] == "malicioso" and not r[k]:
                marcas.append(f"FN em {k}")
            if r["rotulo"] == "benigno" and r[k]:
                marcas.append(f"FP em {k}")
        if marcas:
            erros += 1
            ctx = "; ".join(f"evento {h['evento']} ({h['fonte']}), {h['tipo']}, to_ids={'S' if h['to_ids'] else 'N'}"
                            f"{', WL: ' + '/'.join(h['warninglists']) if h['warninglists'] else ''}"
                            for h in r["hits_B"][:3])
            L.append(f"  {r['id']} | {r['grupo']} | {r['variacao']} | {r['observavel']} | {', '.join(marcas)}"
                     + (f" | correspondencia em B: {ctx}" if ctx else ""))
    if not erros:
        L.append("  nenhum")

    L += ["", "[5] WARNINGLISTS"]
    if wl_erro:
        L.append(f"  Verificacao dos observaveis em warninglists: {wl_erro}")
    else:
        neg_wl = [r for r in neg if any(c in wl_obs for c in r["candidatos_B"])]
        L.append(f"  Negativos presentes em alguma warninglist ativa: {len(neg_wl)} de {len(neg)}"
                 + ("  (se for 0, confira se as warninglists estao ativadas no MISP)" if not neg_wl else ""))
        nomes_wl = collections.Counter(n for r in neg_wl for c in r["candidatos_B"] for n in wl_obs.get(c, []))
        for n, q in nomes_wl.most_common(10):
            L.append(f"    - {n}: {q}")
        pos_wl = [r for r in rotulados if r["rotulo"] == "malicioso"
                  and any(c in wl_obs for c in r["candidatos_B"])]
        L.append(f"  Positivos presentes em alguma warninglist ativa: {len(pos_wl)}")
    corr_wl = sum(1 for r in resultados for h in r["hits_B"] if h["warninglists"])
    L.append(f"  Correspondencias (estrategia B) marcadas por warninglist: {corr_wl}")

    L += ["", "[6] CONTEXTO DAS CORRESPONDENCIAS (estrategia B, positivos)"]
    hits_pos = [h for r in rotulados if r["rotulo"] == "malicioso" for h in r["hits_B"]]
    fontes = collections.Counter(h["fonte"] for h in hits_pos)
    L.append(f"  Atributos correspondentes: {len(hits_pos)}; por fonte: "
             + (", ".join(f"{f} {q}" for f, q in fontes.most_common()) or "nenhum"))
    datas = sorted(h["data_evento"] for h in hits_pos if h["data_evento"])
    if datas:
        hoje = dt.date.today()
        idades = []
        for d in datas:
            try:
                idades.append((hoje - dt.date.fromisoformat(d)).days)
            except ValueError:
                pass
        L.append(f"  Data dos eventos de origem: de {datas[0]} a {datas[-1]}")
        if idades:
            L.append(f"  Correspondencias com indicador de evento com mais de 1 ano: "
                     f"{sum(i > 365 for i in idades)} de {len(idades)}")

    if reais:
        L += ["", "[7] OBSERVAVEIS REAIS (sem rotulo; valores sem correspondencia nao sao listados)",
              f"  Observaveis reais consultados: {len(reais)}",
              f"  Com correspondencia: A {sum(r['A'] for r in reais)} | B {sum(r['B'] for r in reais)} | "
              f"C (alerta) {sum(r['C'] for r in reais)}"]
        if not wl_erro:
            L.append(f"  Presentes em alguma warninglist ativa: "
                     f"{sum(1 for r in reais if any(c in wl_obs for c in r['candidatos_B']))}")
        for r in reais:
            if r["B"]:
                for h in r["hits_B"][:3]:
                    L.append(f"    - {r['observavel']} -> evento {h['evento']} ({h['fonte']}, {h['data_evento']}), "
                             f"{h['tipo']}, to_ids={'S' if h['to_ids'] else 'N'}"
                             f"{', WL: ' + '/'.join(h['warninglists']) if h['warninglists'] else ''}")

    L += ["", "[8] TEMPO DE CONSULTA A API (ms por evento)",
          f"  A - exata: {estat_ms([r['ms_A'] for r in resultados])}",
          f"  B - normalizada (uma consulta com todas as formas): {estat_ms([r['ms_B'] for r in resultados])}"]

    L += ["", "[9] DETALHE DOS EVENTOS ROTULADOS (S = correlacionou; N = nao)"]
    for r in rotulados:
        L.append(f"  {r['id']} | {r['grupo']:<21} | {r['categoria']:<7} | {r['observavel']} | "
                 f"A={'S' if r['A'] else 'N'} B={'S' if r['B'] else 'N'} C={'S' if r['C'] else 'N'}")

    with open(base + ".txt", "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    with open(base + ".csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["id", "grupo", "variacao", "categoria", "evento_simulado", "observavel", "indicador", "rotulo",
                    "A", "B", "C", "ms_A", "ms_B", "eventos", "fontes", "to_ids", "warninglists_correspondencia",
                    "warninglists_observavel"])
        for r in resultados:
            omitir = r["rotulo"] == "desconhecido" and not r["B"]
            hb = r["hits_B"]
            w.writerow([r["id"], r["grupo"], r["variacao"], r["categoria"],
                        "(omitido)" if omitir else r["evento_simulado"],
                        "(omitido)" if omitir else r["observavel"], r["indicador"], r["rotulo"],
                        "S" if r["A"] else "N", "S" if r["B"] else "N", "S" if r["C"] else "N",
                        r["ms_A"], r["ms_B"],
                        " ".join(sorted({h["evento"] for h in hb})),
                        " / ".join(sorted({h["fonte"] for h in hb})),
                        " ".join("S" if h["to_ids"] else "N" for h in hb),
                        " / ".join(sorted({n for h in hb for n in h["warninglists"]})),
                        "" if wl_erro else " / ".join(sorted({n for c in r["candidatos_B"]
                                                               for n in wl_obs.get(c, [])}))])
    return resumo


def salvar_conjunto(caminho, conjunto):
    with open(caminho, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CAMPOS_CONJUNTO, delimiter=";")
        w.writeheader()
        w.writerows(conjunto)


def main():
    ap = argparse.ArgumentParser(description="Teste de correlacao de eventos de rede com IoCs do MISP")
    ap.add_argument("--url", default="https://misp.local", help="endereco do MISP")
    ap.add_argument("--real", help="arquivo com observaveis reais, um por linha (ex.: cache DNS do Windows)")
    ap.add_argument("--conjunto", help="CSV de conjunto gerado antes, para repetir o mesmo teste")
    args = ap.parse_args()

    agora = dt.datetime.now()
    momento = agora.strftime("%Y-%m-%d %H:%M:%S")
    sufixo = agora.strftime("%Y%m%d_%H%M%S")

    reais = []
    if args.real:
        reais = ler_reais(args.real)
        print(f"Observaveis reais lidos: {len(reais)}", file=sys.stderr)

    chave = getpass.getpass("Cole a chave de API (somente leitura) e tecle Enter: ").strip()
    if not chave:
        sys.exit("Chave vazia. Encerrando.")
    api = Misp(args.url, chave)
    try:
        versao = api.chamar("/servers/getVersion").get("version")
        print("Lendo eventos e indicadores do MISP...", file=sys.stderr)
        eventos = mapa_eventos(api)
        indicadores = ler_indicadores(api)
        if args.conjunto:
            conjunto = ler_conjunto(args.conjunto)
            excluir = {v.lower() for _, v in NEGATIVOS}
            conflitos = sorted(v for (_, v) in indicadores if v.lower() in excluir)
            if reais:  # substitui os observaveis reais do conjunto anterior pelos novos
                conjunto = [c for c in conjunto if c["grupo"] != "real"]
                n0 = max((int(c["id"][1:]) for c in conjunto if c["id"][1:].isdigit()), default=0)
                for i, v in enumerate(reais, n0 + 1):
                    cat = "IP" if RE_IPV4.match(v) else ("URL" if RE_ESQUEMA.match(v) else "Dominio")
                    conjunto.append({"id": f"E{i:03d}", "grupo": "real", "variacao": "-", "categoria": cat,
                                     "evento_simulado": "consulta DNS real", "observavel": v, "indicador": "-",
                                     "rotulo": "desconhecido"})
        else:
            if not indicadores:
                sys.exit("Nenhum indicador de rede com to_ids encontrado no MISP.")
            conjunto, conflitos = montar_conjunto(indicadores, reais)
            arq_conj = f"conjunto_teste_{sufixo}.csv"
            salvar_conjunto(arq_conj, conjunto)
            print(f"Conjunto de teste salvo em {os.path.abspath(arq_conj)}", file=sys.stderr)
        print(f"Consultando {len(conjunto)} eventos simulados...", file=sys.stderr)
        resultados = executar(api, conjunto, eventos)
        valores_wl = sorted({c for r in resultados for c in r["candidatos_B"]})
        wl_obs, wl_erro = checar_warninglists(api, valores_wl)
    except urllib.error.HTTPError as e:
        sys.exit(f"Erro HTTP {e.code} ao consultar o MISP. Confira a chave e o endereco ({args.url}).")
    except urllib.error.URLError as e:
        sys.exit(f"Nao foi possivel conectar ao MISP em {args.url}: {e.reason}")

    base = f"correlacao_tcc_{sufixo}"
    resumo = escrever(base, momento, args.url, versao, conflitos, indicadores, resultados, wl_obs or {}, wl_erro)
    print("\nResumo (VP / FP / FN / VN | precisao | revocacao):")
    for k, nome in (("A", "exata"), ("B", "normalizada"), ("C", "normalizada + filtros")):
        m = resumo[k]
        print(f"  {k} - {nome}: {m['VP']} / {m['FP']} / {m['FN']} / {m['VN']} | {pct(m['precisao'])} | "
              f"{pct(m['revocacao'])}")
    print(f"\nPronto. Relatorio: {os.path.abspath(base + '.txt')}")
    print(f"Detalhe por evento: {os.path.abspath(base + '.csv')}")
    print("Envie o arquivo .txt (ele nao contem a chave de API).")


if __name__ == "__main__":
    main()
