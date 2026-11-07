#!/usr/bin/env python3
"""
Coleta de dados do laboratorio (MISP + misp-dashboard) para o TCC.

Gera um relatorio de texto (e um JSON) com:
  - versoes do ambiente (Ubuntu, kernel, MISP, MariaDB, Redis, Apache, PHP, Python, misp-dashboard);
  - hardware visto pelo WSL (modelo do processador, nucleos, memoria disponivel, .wslconfig);
  - consumo de memoria e CPU dos servicos do laboratorio (instantaneo);
  - feeds configurados no MISP;
  - eventos e atributos por fonte (organizacao criadora) e por tipo;
  - sobreposicao de indicadores entre fontes e ocorrencias em warninglists;
  - tempo de resposta de consultas a API (restSearch).

Uso (no Ubuntu):
    sudo python3 coleta_tcc.py              # coleta completa (pede a chave de API)
    sudo python3 coleta_tcc.py --recursos   # so versoes e consumo (sem API)

A chave de API e pedida sem aparecer na tela e NAO e gravada no relatorio.
Use uma chave "somente leitura" (Read only) criada no MISP.
Somente a biblioteca padrao do Python 3 e usada.
"""
import argparse
import collections
import datetime as dt
import getpass
import glob
import json
import os
import random
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

LIMITE_PAGINA = 5000

GRUPOS_TIPO = {
    "IP": {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port"},
    "Dominio/host": {"domain", "hostname", "domain|ip"},
    "URL": {"url", "uri"},
    "Hash": {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ssdeep", "imphash",
             "tlsh", "authentihash", "filename|md5", "filename|sha1", "filename|sha256",
             "filename|sha512", "filename|ssdeep", "filename|imphash", "filename|tlsh"},
}
GRUPOS_REDE = ("IP", "Dominio/host", "URL")


def grupo_do_tipo(tipo):
    for nome, tipos in GRUPOS_TIPO.items():
        if tipo in tipos:
            return nome
    return "Outros"


def valor_rede(tipo, valor):
    """Normaliza o valor de rede para comparar fontes (parte de rede de tipos compostos)."""
    v = (valor or "").strip().lower()
    if tipo in ("ip-src|port", "ip-dst|port", "domain|ip"):
        v = v.split("|")[0]
    return v


# ----------------------------------------------------------------- sistema
def rodar(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        out = r.stdout or b""
        if b"\x00" in out:  # saida UTF-16 de programas do Windows (wsl.exe)
            try:
                out = out.decode("utf-16-le")
            except UnicodeDecodeError:
                out = out.replace(b"\x00", b"").decode("utf-8", "replace")
        else:
            out = out.decode("utf-8", "replace")
        return out.strip()
    except Exception as e:  # noqa: BLE001
        return f"(nao disponivel: {e.__class__.__name__})"


def ler(caminho):
    try:
        with open(caminho, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def info_sistema():
    info = collections.OrderedDict()
    osr = ler("/etc/os-release")
    pretty = [l.split("=", 1)[1].strip('"') for l in osr.splitlines() if l.startswith("PRETTY_NAME=")]
    info["Sistema (WSL)"] = pretty[0] if pretty else rodar("lsb_release -ds")
    info["Kernel"] = rodar("uname -r")
    cpu = [l.split(":", 1)[1].strip() for l in ler("/proc/cpuinfo").splitlines() if l.startswith("model name")]
    info["Processador"] = cpu[0] if cpu else "(nao identificado)"
    info["Nucleos logicos visiveis"] = rodar("nproc")
    mem = {}
    for l in ler("/proc/meminfo").splitlines():
        p = l.split()
        if len(p) >= 2:
            mem[p[0].rstrip(":")] = int(p[1])
    if mem:
        info["Memoria total do WSL (MB)"] = round(mem.get("MemTotal", 0) / 1024)
        info["Memoria disponivel agora (MB)"] = round(mem.get("MemAvailable", 0) / 1024)
        info["Swap total (MB)"] = round(mem.get("SwapTotal", 0) / 1024)
    info["Windows (ver)"] = rodar("cmd.exe /c ver 2>/dev/null", timeout=10)
    info["WSL (--version)"] = rodar("wsl.exe --version 2>/dev/null", timeout=10)
    cfgs = []
    for c in glob.glob("/mnt/c/Users/*/.wslconfig"):
        linhas = [l.strip() for l in ler(c).splitlines()
                  if l.strip() and not l.strip().startswith("#")]
        cfgs.append(f"{os.path.basename(os.path.dirname(c))}: " + "; ".join(linhas))
    info[".wslconfig"] = " | ".join(cfgs) if cfgs else "(nao encontrado: WSL usa os limites padrao)"
    versao = ler("/var/www/MISP/VERSION.json")
    try:
        v = json.loads(versao)
        info["MISP"] = f"{v.get('major')}.{v.get('minor')}.{v.get('hotfix')}"
    except Exception:  # noqa: BLE001
        info["MISP"] = "(VERSION.json nao lido)"
    info["misp-dashboard (commit)"] = rodar(
        "git -c safe.directory=/var/www/misp-dashboard -C /var/www/misp-dashboard "
        "log -1 --format='%h %ad' --date=short")
    info["Apache"] = rodar("apache2 -v 2>/dev/null | head -n 1")
    info["MariaDB"] = rodar("mariadb --version 2>/dev/null || mysql --version")
    info["Redis"] = rodar("redis-server --version")
    info["PHP"] = rodar("php -v 2>/dev/null | head -n 1")
    info["Python"] = rodar("python3 --version")
    info["Uso de disco"] = rodar("du -sh /var/lib/mysql /var/www/MISP /var/www/misp-dashboard 2>/dev/null")
    return info


def cpu_ocupada(intervalo=5.0):
    def amostra():
        campos = ler("/proc/stat").splitlines()[0].split()[1:]
        valores = list(map(int, campos))
        ocioso = valores[3] + (valores[4] if len(valores) > 4 else 0)
        return sum(valores), ocioso
    t1, o1 = amostra()
    time.sleep(intervalo)
    t2, o2 = amostra()
    total, ocioso = t2 - t1, o2 - o1
    return round(100.0 * (total - ocioso) / total, 1) if total else 0.0


def consumo_servicos():
    grupos = collections.OrderedDict((g, 0) for g in (
        "Apache (interface web do MISP)", "MariaDB (banco)", "Redis", "Workers do MISP (PHP)",
        "ZeroMQ do MISP", "misp-dashboard", "Supervisor"))
    saida = rodar("ps -eo rss=,comm=,args=")
    for linha in saida.splitlines():
        partes = linha.split(None, 2)
        if len(partes) < 2:
            continue
        try:
            rss = int(partes[0])
        except ValueError:
            continue
        comm = partes[1]
        args = partes[2] if len(partes) > 2 else ""
        if "mispzmq.py" in args:
            g = "ZeroMQ do MISP"
        elif "misp-dashboard" in args or any(s in args for s in ("server.py", "zmq_subscriber", "zmq_dispatcher")):
            g = "misp-dashboard"
        elif comm.startswith("apache2"):
            g = "Apache (interface web do MISP)"
        elif comm in ("mariadbd", "mysqld"):
            g = "MariaDB (banco)"
        elif comm.startswith("redis-server"):
            g = "Redis"
        elif comm.startswith("php") and ("cake" in args or "worker" in args.lower()):
            g = "Workers do MISP (PHP)"
        elif comm.startswith("supervisord") or "supervisord" in args:
            g = "Supervisor"
        else:
            continue
        grupos[g] += rss
    mb = collections.OrderedDict((g, round(v / 1024)) for g, v in grupos.items())
    mb["TOTAL dos servicos do laboratorio"] = sum(mb.values())
    mem = {}
    for l in ler("/proc/meminfo").splitlines():
        p = l.split()
        if len(p) >= 2:
            mem[p[0].rstrip(":")] = int(p[1])
    uso = {
        "Memoria em uso no WSL (MB)": round((mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)) / 1024),
        "Memoria total do WSL (MB)": round(mem.get("MemTotal", 0) / 1024),
        "CPU ocupada (media de 5 s, %)": cpu_ocupada(),
        "Carga media (1/5/15 min)": " ".join(ler("/proc/loadavg").split()[:3]),
    }
    return mb, uso


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


def coletar_misp(api):
    res = collections.OrderedDict()
    try:
        res["versao_api"] = api.chamar("/servers/getVersion").get("version")
    except Exception as e:  # noqa: BLE001
        res["versao_api"] = f"(erro: {e})"

    feeds = []
    try:
        for item in api.chamar("/feeds/index"):
            f = item.get("Feed", item)
            feeds.append({k: f.get(k) for k in ("id", "name", "provider", "source_format", "enabled",
                                                 "caching_enabled", "url", "event_id")})
    except Exception as e:  # noqa: BLE001
        feeds.append({"erro": str(e)})
    res["feeds"] = feeds

    eventos = {}
    pagina = 1
    while True:
        lote = api.chamar("/events/index", {"limit": 500, "page": pagina})
        if not lote:
            break
        for item in lote:
            e = item.get("Event", item)
            orgc = (e.get("Orgc") or item.get("Orgc") or {}).get("name") or f"orgc_id {e.get('orgc_id')}"
            eventos[str(e.get("id"))] = {"info": e.get("info"), "data": e.get("date"), "fonte": orgc,
                                         "atributos": int(e.get("attribute_count") or 0),
                                         "publicado": e.get("published")}
        if len(lote) < 500:
            break
        pagina += 1
    res["eventos"] = eventos
    print(f"  eventos lidos: {len(eventos)}", file=sys.stderr)

    por_fonte = collections.defaultdict(lambda: {"eventos": set(), "atributos": 0, "to_ids": 0,
                                                 "warninglist": 0, "tipos": collections.Counter(),
                                                 "mais_antigo": None, "mais_recente": None})
    fontes_por_valor = collections.defaultdict(set)
    eventos_por_valor = collections.defaultdict(set)
    nomes_wl = collections.Counter()
    suporte_wl = False
    total = 0
    pagina = 1
    while True:
        corpo = {"returnFormat": "json", "limit": LIMITE_PAGINA, "page": pagina,
                 "includeWarninglistHits": True, "deleted": False}
        t0 = time.time()
        lote = lista_atributos(api.chamar("/attributes/restSearch", corpo, timeout=900))
        print(f"  pagina {pagina}: {len(lote)} atributos ({time.time() - t0:.1f} s)", file=sys.stderr)
        for a in lote:
            total += 1
            ev = str(a.get("event_id"))
            fonte = eventos.get(ev, {}).get("fonte", "(evento nao listado)")
            pf = por_fonte[fonte]
            pf["eventos"].add(ev)
            pf["atributos"] += 1
            tipo = a.get("type", "")
            grupo = grupo_do_tipo(tipo)
            pf["tipos"][grupo] += 1
            if a.get("to_ids") in (True, "1", 1):
                pf["to_ids"] += 1
            if "warnings" in a:
                suporte_wl = True
                if a.get("warnings"):
                    pf["warninglist"] += 1
                    for w in a["warnings"]:
                        nomes_wl[w.get("warninglist_name") or w.get("name") or "?"] += 1
            try:
                ts = dt.date.fromtimestamp(int(a.get("timestamp")))
                pf["mais_antigo"] = min(filter(None, [pf["mais_antigo"], ts]))
                pf["mais_recente"] = max(filter(None, [pf["mais_recente"], ts]))
            except (TypeError, ValueError):
                pass
            if grupo in GRUPOS_REDE:
                v = valor_rede(tipo, a.get("value"))
                fontes_por_valor[v].add(fonte)
                eventos_por_valor[v].add(ev)
        if len(lote) < LIMITE_PAGINA:
            break
        pagina += 1

    res["total_atributos"] = total
    res["suporte_warninglist"] = suporte_wl
    res["por_fonte"] = {
        f: {"eventos": len(d["eventos"]), "atributos": d["atributos"], "to_ids": d["to_ids"],
            "warninglist": d["warninglist"], "tipos": dict(d["tipos"]),
            "mais_antigo": str(d["mais_antigo"]), "mais_recente": str(d["mais_recente"])}
        for f, d in sorted(por_fonte.items(), key=lambda x: -x[1]["atributos"])}
    res["valores_rede_distintos"] = len(fontes_por_valor)
    res["valores_em_2_ou_mais_fontes"] = sum(1 for s in fontes_por_valor.values() if len(s) >= 2)
    res["valores_em_2_ou_mais_eventos"] = sum(1 for s in eventos_por_valor.values() if len(s) >= 2)
    pares = collections.Counter()
    for s in fontes_por_valor.values():
        if len(s) >= 2:
            for a in sorted(s):
                for b in sorted(s):
                    if a < b:
                        pares[f"{a} x {b}"] += 1
    res["sobreposicao_por_par"] = dict(pares.most_common(10))
    res["warninglists_mais_frequentes"] = dict(nomes_wl.most_common(10))

    amostra = random.Random(42).sample(sorted(fontes_por_valor), min(30, len(fontes_por_valor)))
    tempos = []
    for v in amostra:
        t0 = time.perf_counter()
        try:
            api.chamar("/attributes/restSearch", {"returnFormat": "json", "value": v, "limit": 50})
            tempos.append((time.perf_counter() - t0) * 1000)
        except Exception:  # noqa: BLE001
            pass
    if tempos:
        tempos.sort()
        res["consulta_api_ms"] = {"n": len(tempos), "media": round(statistics.mean(tempos), 1),
                                  "mediana": round(statistics.median(tempos), 1),
                                  "minimo": round(tempos[0], 1), "maximo": round(tempos[-1], 1)}
    return res


# ----------------------------------------------------------------- relatorio
def escrever(caminho_txt, caminho_json, sistema, consumo, uso, misp, momento):
    linhas = [f"COLETA DO LABORATORIO - {momento}", "=" * 60, "", "[1] AMBIENTE"]
    linhas += [f"  {k}: {v}" for k, v in sistema.items()]
    linhas += ["", "[2] CONSUMO DOS SERVICOS (memoria residente, MB)"]
    linhas += [f"  {k}: {v}" for k, v in consumo.items()]
    linhas += [f"  {k}: {v}" for k, v in uso.items()]
    if misp:
        linhas += ["", "[3] MISP", f"  Versao (API): {misp.get('versao_api')}", "", "  Feeds configurados:"]
        for f in misp.get("feeds", []):
            if "erro" in f:
                linhas.append(f"    erro: {f['erro']}")
                continue
            linhas.append(f"    - {f.get('name')} | {f.get('provider')} | formato {f.get('source_format')} | "
                          f"ativo={f.get('enabled')} | cache={f.get('caching_enabled')}")
        linhas += ["", f"  Eventos: {len(misp.get('eventos', {}))} | Atributos: {misp.get('total_atributos')}",
                   "", "  Por fonte (organizacao criadora):"]
        for fonte, d in misp.get("por_fonte", {}).items():
            tipos = ", ".join(f"{k} {v}" for k, v in sorted(d["tipos"].items()))
            linhas.append(f"    - {fonte}: {d['eventos']} eventos, {d['atributos']} atributos "
                          f"({tipos}); to_ids={d['to_ids']}; em warninglist={d['warninglist']}; "
                          f"atributos modificados entre {d['mais_antigo']} e {d['mais_recente']}")
        linhas += ["", f"  Valores de rede distintos (IP, dominio, URL): {misp.get('valores_rede_distintos')}",
                   f"  Valores presentes em 2 ou mais fontes: {misp.get('valores_em_2_ou_mais_fontes')}",
                   f"  Valores presentes em 2 ou mais eventos: {misp.get('valores_em_2_ou_mais_eventos')}",
                   f"  Sobreposicao por par de fontes: {misp.get('sobreposicao_por_par')}",
                   f"  Suporte a includeWarninglistHits: {misp.get('suporte_warninglist')}",
                   f"  Warninglists mais frequentes: {misp.get('warninglists_mais_frequentes')}",
                   f"  Tempo de consulta a API (ms): {misp.get('consulta_api_ms')}"]
        linhas += ["", "  Eventos (id | data | fonte | atributos | titulo):"]
        for i, e in sorted(misp.get("eventos", {}).items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
            linhas.append(f"    {i} | {e['data']} | {e['fonte']} | {e['atributos']} | {e['info']}")
    with open(caminho_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas) + "\n")
    with open(caminho_json, "w", encoding="utf-8") as f:
        json.dump({"momento": momento, "ambiente": sistema, "consumo_mb": consumo, "uso": uso,
                   "misp": misp}, f, ensure_ascii=False, indent=2, default=str)


def main():
    ap = argparse.ArgumentParser(description="Coleta de dados do laboratorio MISP para o TCC")
    ap.add_argument("--url", default="https://misp.local", help="endereco do MISP")
    ap.add_argument("--recursos", action="store_true", help="coletar so ambiente e consumo (sem API)")
    args = ap.parse_args()

    momento = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sufixo = "recursos" if args.recursos else "completa"
    base = f"coleta_tcc_{sufixo}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    misp = None
    if not args.recursos:
        chave = getpass.getpass("Cole a chave de API (somente leitura) e tecle Enter: ").strip()
        if not chave:
            sys.exit("Chave vazia. Encerrando.")
        print("Consultando o MISP (pode levar alguns minutos)...", file=sys.stderr)
        try:
            misp = coletar_misp(Misp(args.url, chave))
        except urllib.error.HTTPError as e:
            sys.exit(f"Erro HTTP {e.code} ao consultar o MISP. Confira a chave e o endereco ({args.url}).")
        except urllib.error.URLError as e:
            sys.exit(f"Nao foi possivel conectar ao MISP em {args.url}: {e.reason}")

    print("Coletando ambiente e consumo...", file=sys.stderr)
    sistema = info_sistema()
    consumo, uso = consumo_servicos()
    escrever(base + ".txt", base + ".json", sistema, consumo, uso, misp, momento)
    print(f"\nPronto. Relatorio gerado: {os.path.abspath(base + '.txt')}")
    print("Envie esse arquivo .txt (ele nao contem a chave de API).")


if __name__ == "__main__":
    main()
