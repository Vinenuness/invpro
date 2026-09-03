import os
import sys
import json
import time
import uuid
import socket
import getpass
import re
import subprocess

# =========================
# DEPENDENCY CHECK
# =========================
missing_deps = []
try:
    import requests
except ImportError:
    missing_deps.append("requests")

try:
    import psutil
except ImportError:
    missing_deps.append("psutil")

try:
    import wmi
except ImportError:
    missing_deps.append("wmi")

if missing_deps:
    print("=" * 60)
    print("ERRO: Dependencias faltando!")
    print(f"Pacotes nao encontrados: {', '.join(missing_deps)}")
    print()
    print("Para instalar, execute:")
    print("  pip install " + " ".join(missing_deps))
    print()
    print("Ou instale todas de uma vez:")
    print("  pip install -r requirements-agent.txt")
    print("=" * 60)
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import simpledialog, messagebox
except:
    tk = None
    simpledialog = None
    messagebox = None

try:
    import winreg  # Windows only
except:
    winreg = None


# =========================
# CONFIG
# =========================
BASE_URL = os.environ.get("AGENT_BASE_URL", "http://127.0.0.1:5000")
API_URL = os.environ.get("AGENT_API_URL", f"{BASE_URL}/api/agent")
BIND_URL = os.environ.get("AGENT_BIND_URL", f"{BASE_URL}/api/agent/bind")

# Jobs (servidor)
JOBS_URL = os.environ.get("AGENT_JOBS_URL", f"{BASE_URL}/api/agent/jobs")
JOB_RESULT_URL = os.environ.get("AGENT_JOB_RESULT_URL", f"{BASE_URL}/api/agent/jobs/{{job_id}}/result")

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "SEU_TOKEN_SUPER_SECRETO")
INTERVALO_SEG = int(os.environ.get("AGENT_INTERVAL_SECONDS", "30"))

BASE_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "AgenteTI")
STATE_FILE = os.path.join(BASE_DIR, "agent.json")
JOBS_DIR = os.path.join(BASE_DIR, "jobs")

c = wmi.WMI()


# =========================
# STATE
# =========================
def load_state():
    os.makedirs(BASE_DIR, exist_ok=True)
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {}

def save_state(state: dict):
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

def get_device_uid():
    st = load_state()
    if st.get("device_uid"):
        return st["device_uid"]
    st["device_uid"] = str(uuid.uuid4())
    save_state(st)
    return st["device_uid"]

def get_agent_id():
    st = load_state()
    if st.get("agent_id"):
        return st["agent_id"]
    st["agent_id"] = str(uuid.uuid4())
    save_state(st)
    return st["agent_id"]


# =========================
# UI TAG
# =========================
def ask_tag_gui():
    if tk is None or simpledialog is None:
        return None
    root = tk.Tk()
    root.withdraw()
    tag = simpledialog.askstring("Vincular Estacao", "Digite a etiqueta EVO (ex: EVO-1234):")
    root.destroy()
    return tag


# =========================
# HELPERS
# =========================
def get_ip_best_effort():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            return socket.gethostbyname(socket.getfqdn())
        except:
            return None

def get_mac_best_effort():
    try:
        for nic, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                fam = getattr(a.family, "name", "")
                if fam == "AF_LINK" or str(a.family).endswith("AF_LINK"):
                    mac = a.address
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
    except:
        pass
    return None

def get_uptime_h():
    try:
        boot = psutil.boot_time()
        return round((time.time() - boot) / 3600, 2)
    except:
        return None


# =========================
# MONITORES root\wmi
# =========================
def _arr_to_str(arr):
    try:
        return "".join([chr(x) for x in (arr or []) if x and x != 0]).strip()
    except:
        return ""

def get_monitores():
    mons = []
    try:
        w = wmi.WMI(namespace="root\\wmi")
        id_map = {}
        for m in w.WmiMonitorID():
            inst = getattr(m, "InstanceName", "") or ""
            id_map[inst] = {
                "instance": inst or None,
                "manufacturer": _arr_to_str(getattr(m, "ManufacturerName", None)),
                "model": _arr_to_str(getattr(m, "UserFriendlyName", None)),
                "serial": _arr_to_str(getattr(m, "SerialNumberID", None)),
            }

        size_map = {}
        try:
            for p in w.WmiMonitorBasicDisplayParams():
                inst = getattr(p, "InstanceName", "") or ""
                size_map[inst] = {
                    "width_cm": getattr(p, "MaxHorizontalImageSize", None),
                    "height_cm": getattr(p, "MaxVerticalImageSize", None),
                }
        except:
            pass

        for inst, info in id_map.items():
            merged = dict(info)
            merged.update(size_map.get(inst, {}))
            mons.append(merged)

        if not mons:
            for m in c.Win32_DesktopMonitor():
                name = getattr(m, "Name", None)
                if name:
                    mons.append({"model": name})
    except:
        pass
    return mons


# =========================
# INVENTARIO
# =========================
def get_os_info():
    try:
        osr = next(iter(c.Win32_OperatingSystem()), None)
        return {"os_caption": getattr(osr, "Caption", None), "os_version": getattr(osr, "Version", None)}
    except:
        return {}

def get_cpu():
    try:
        cpu = next(iter(c.Win32_Processor()), None)
        return getattr(cpu, "Name", None)
    except:
        return None

def get_gpu():
    g = []
    try:
        for v in c.Win32_VideoController():
            name = getattr(v, "Name", None)
            if name:
                g.append(name)
    except:
        pass
    return g

def get_serial():
    try:
        bios = next(iter(c.Win32_BIOS()), None)
        return getattr(bios, "SerialNumber", None)
    except:
        return None

def get_physical_disks():
    disks = []
    try:
        for d in c.Win32_DiskDrive():
            model = getattr(d, "Model", None) or getattr(d, "Name", None)
            size = getattr(d, "Size", None)
            size_gb = round(int(size) / (1024**3), 2) if size else None
            media = getattr(d, "MediaType", None)
            if not media and model:
                media = "SSD" if re.search(r"SSD|NVME|NVMe", model, re.I) else None
            disks.append({"name": model, "size_gb": size_gb, "media_type": media})
    except:
        pass
    return disks

def get_volumes():
    vols = []
    try:
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
                vols.append({
                    "device": p.device,
                    "mount": p.mountpoint,
                    "fstype": p.fstype,
                    "total_gb": round(u.total / (1024**3), 2),
                    "free_gb": round(u.free / (1024**3), 2),
                })
            except:
                continue
    except:
        pass
    return vols

def reg_read_str(root, path, name):
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(root, path) as k:
            val, _ = winreg.QueryValueEx(k, name)
            return str(val)
    except:
        return None

def get_installed_programs(limit=350):
    if winreg is None:
        return []
    programs = set()
    uninstall_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    for up in uninstall_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, up) as base:
                n = winreg.QueryInfoKey(base)[0]
                for i in range(n):
                    try:
                        sub = winreg.EnumKey(base, i)
                        dn = reg_read_str(winreg.HKEY_LOCAL_MACHINE, up + "\\" + sub, "DisplayName")
                        if dn:
                            programs.add(dn)
                    except:
                        continue
        except:
            continue
    return sorted(programs)[:limit]

def get_anydesk_id_best_effort():
    paths = [
        r"C:\ProgramData\AnyDesk\system.conf",
        r"C:\ProgramData\AnyDesk\service.conf",
        r"C:\ProgramData\AnyDesk\ad_svc.conf",
    ]
    for p in paths:
        try:
            if os.path.exists(p):
                txt = open(p, "r", encoding="utf-8", errors="ignore").read()
                m = re.search(r"(?:ad\.(?:anynet\.)?id)\s*=\s*(\d+)", txt)
                if m:
                    return m.group(1)
        except:
            pass
    return None



def get_process_count():
    """Get count of running processes"""
    try:
        return len(psutil.pids())
    except:
        return None

def get_network_stats():
    """Get network I/O statistics"""
    try:
        net = psutil.net_io_counters()
        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv
        }
    except:
        return {}

def get_cpu_percent():
    """Get current CPU usage percentage"""
    try:
        return psutil.cpu_percent(interval=1)
    except:
        return None

def get_ram_percent():
    """Get current RAM usage percentage"""
    try:
        return psutil.virtual_memory().percent
    except:
        return None

def get_disk_io():
    """Get disk I/O statistics"""
    try:
        disk = psutil.disk_io_counters()
        return {
            "read_bytes": disk.read_bytes,
            "write_bytes": disk.write_bytes,
            "read_count": disk.read_count,
            "write_count": disk.write_count
        }
    except:
        return {}

def get_battery_info():
    """Get battery information (for laptops)"""
    try:
        bat = psutil.sensors_battery()
        if bat:
            return {
                "percent": bat.percent,
                "power_plugged": bat.power_plugged,
                "seconds_left": bat.secsleft if bat.secsleft != psutil.POWER_TIME_UNLIMITED else None
            }
    except:
        pass
    return {}

def install_as_service():
    """Install agent as Windows service (requires admin)"""
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    
    class AgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "AtivoFixAgent"
        _svc_display_name_ = "AtivoFix Inventory Agent"
        _svc_description_ = "Collects system inventory and reports to AtivoFix server"
        
        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        
        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)
        
        def SvcDoRun(self):
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                 servicemanager.PYS_SERVICE_STARTED,
                                 (self._svc_name_, ''))
            self.main()
        
        def main(self):
            # Run the agent main loop
            while True:
                try:
                    data = payload()
                    headers = {"X-AGENT-TOKEN": AGENT_TOKEN}
                    requests.post(API_URL, json=data, headers=headers, timeout=20)
                except:
                    pass
                time.sleep(INTERVALO_SEG)
    
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(AgentService)

def payload():
    hostname = socket.gethostname()
    ip = get_ip_best_effort()

    return {
        "agent_id": get_agent_id(),
        "device_uid": get_device_uid(),
        "hostname": hostname,
        "windows_user": getpass.getuser(),
        "anydesk_id": get_anydesk_id_best_effort(),
        "cpu": get_cpu(),
        "gpu": get_gpu(),
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "serial": get_serial(),
        "uptime_h": get_uptime_h(),
        "network": {"ip": ip, "mac": get_mac_best_effort()},
        "physical_disks": get_physical_disks(),
        "volumes": get_volumes(),
        "programas": get_installed_programs(limit=350),
        "monitores": get_monitores(),
        "process_count": get_process_count(),
        "network_stats": get_network_stats(),
        "cpu_percent": get_cpu_percent(),
        "ram_percent": get_ram_percent(),
        "disk_io": get_disk_io(),
        "battery": get_battery_info(),
        **get_os_info(),
    }


def bind_tag(device_uid: str, tag_evo: str):
    headers = {"X-AGENT-TOKEN": AGENT_TOKEN}
    return requests.post(
        BIND_URL,
        json={"device_uid": device_uid, "tag_evo": tag_evo},
        headers=headers,
        timeout=10
    )


# =========================
# JOBS (confirmacao local, sem execucao automatica)
# =========================
def fetch_jobs(device_uid: str):
    headers = {"X-AGENT-TOKEN": AGENT_TOKEN}
    r = requests.get(JOBS_URL, headers=headers, params={"device_uid": device_uid}, timeout=20)
    r.raise_for_status()
    data = r.json() or {}
    return data.get("jobs", [])

def post_job_result(job_id: str, status: str, stdout: str = "", stderr: str = "", exit_code=None):
    headers = {"X-AGENT-TOKEN": AGENT_TOKEN}
    url = JOB_RESULT_URL.format(job_id=job_id)
    stdout = (stdout or "")[:20000]
    stderr = (stderr or "")[:20000]
    payload = {"status": status, "stdout": stdout, "stderr": stderr, "exit_code": exit_code}
    r = requests.post(url, json=payload, headers=headers, timeout=20)
    r.raise_for_status()

def confirm_local(script_name: str, content: str) -> bool:
    if tk is None or messagebox is None:
        return False
    preview = (content or "").strip()
    if len(preview) > 900:
        preview = preview[:900] + "\n...\n(Conteudo truncado)"
    root = tk.Tk()
    root.withdraw()
    ok = messagebox.askyesno(
        "Solicitacao de Script",
        f"Voce autoriza salvar este script para execucao manual?\n\n"
        f"Script: {script_name or 'Sem nome'}\n\n"
        f"Preview:\n{preview}\n\n"
        f"Se clicar SIM, o arquivo .bat sera salvo e aberto para voce executar."
    )
    root.destroy()
    return bool(ok)

def save_bat(job_id: str, script_name: str, content: str):
    os.makedirs(JOBS_DIR, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", (script_name or "script")).strip("_")[:40]
    bat_path = os.path.join(JOBS_DIR, f"{safe_name}_{job_id}.bat")
    with open(bat_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)
    return bat_path

def open_file_or_folder(path: str):
    try:
        # abre o arquivo no Explorer (selecionando)
        subprocess.run(["explorer.exe", "/select,", path], check=False)
    except:
        try:
            subprocess.run(["explorer.exe", os.path.dirname(path)], check=False)
        except:
            pass




# =========================
# AUTO-START (Windows Startup)
# =========================
REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
AGENT_REG_NAME = "AtivoFixAgent"

def get_agent_path():
    """Get the full path to this agent script"""
    return os.path.abspath(__file__)

def is_in_startup():
    """Check if agent is in Windows startup"""
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, AGENT_REG_NAME)
            return bool(val)
    except:
        return False

def install_startup():
    """Add agent to Windows startup (runs on login)"""
    if winreg is None:
        print("ERRO: winreg nao disponivel (so funciona no Windows)")
        return False
    
    agent_path = get_agent_path()
    # Use pythonw.exe to run without console window
    python_dir = os.path.dirname(sys.executable)
    pythonw = os.path.join(python_dir, "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable  # fallback to python.exe
    
    # Command to run: pythonw.exe agent.py --background
    cmd = f'"{pythonw}" "{agent_path}" --background'
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, AGENT_REG_NAME, 0, winreg.REG_SZ, cmd)
        print(f"✅ Agente adicionado ao startup do Windows!")
        print(f"   Comando: {cmd}")
        print(f"   O agente iniciara automaticamente no proximo login.")
        return True
    except Exception as e:
        print(f"❌ Erro ao adicionar ao startup: {e}")
        return False

def remove_startup():
    """Remove agent from Windows startup"""
    if winreg is None:
        print("ERRO: winreg nao disponivel")
        return False
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, AGENT_REG_NAME)
        print("✅ Agente removido do startup do Windows!")
        return True
    except FileNotFoundError:
        print("⚠️  Agente nao estava no startup")
        return True
    except Exception as e:
        print(f"❌ Erro ao remover do startup: {e}")
        return False

def run_background():
    """Run agent in background mode (no console)"""
    # Hide console window on Windows
    if sys.platform == "win32":
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
        except:
            pass

if __name__ == "__main__":
    # Handle command line arguments
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "--install-startup" or cmd == "install":
            install_startup()
            sys.exit(0)
        elif cmd == "--remove-startup" or cmd == "remove":
            remove_startup()
            sys.exit(0)
        elif cmd == "--status":
            status = "[OK] Instalado" if is_in_startup() else "[X] Nao instalado"
            print(f"Status do auto-start: {status}")
            sys.exit(0)
        elif cmd == "--background":
            run_background()
            # Continue to main loop
    
    print("=" * 60)
    print("Agente de Inventario - Iniciando...")
    print("=" * 60)
    print(f"Servidor: {BASE_URL}")
    print(f"Token: {AGENT_TOKEN[:4]}{'*' * max(0, len(AGENT_TOKEN) - 4)}")
    print(f"Intervalo: {INTERVALO_SEG} segundos")
    print()
    
    # Check auto-start status
    if is_in_startup():
        print("[OK] Auto-start: Ativado")
    else:
        print("[!] Auto-start: Desativado (execute: python agente.py --install-startup)")
    print()

    # Testar conexao com o servidor
    print("Testando conexao com o servidor...")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"Servidor OK! Status: {r.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"ERRO: Nao foi possivel conectar ao servidor em {BASE_URL}")
        print("Verifique se o servidor esta rodando e acessivel.")
        print("Tentando novamente em 10 segundos...")
        time.sleep(10)
    except Exception as e:
        print(f"ERRO ao conectar: {e}")
        print("Tentando novamente em 10 segundos...")
        time.sleep(10)

    print()
    print("Iniciando coleta de informacoes...")
    print()

    while True:
        try:
            print("-" * 60)
            print(f"Coletando informacoes do PC...")
            data = payload()

            print(f"  Hostname: {data.get('hostname')}")
            print(f"  IP: {data.get('network', {}).get('ip')}")
            print(f"  CPU: {data.get('cpu')}")
            print(f"  RAM: {data.get('ram_total_gb')} GB")
            print(f"  OS: {data.get('os_caption')}")

            headers = {"X-AGENT-TOKEN": AGENT_TOKEN}

            # Inventario
            print()
            print("Enviando inventario para o servidor...")
            r = requests.post(API_URL, json=data, headers=headers, timeout=20)
            print(f"Resposta: {r.status_code} - {r.text}")

            try:
                resp = r.json()
            except:
                resp = {}

            # TAG
            if resp.get("status") == "need_tag":
                print()
                print("Servidor solicitou TAG. Abrindo janela...")
                tag = ask_tag_gui()
                if tag:
                    rb = bind_tag(data["device_uid"], tag)
                    print(f"Bind: {rb.status_code} - {rb.text}")

            # JOBS (consome e pede confirmacao)
            try:
                print()
                print("Verificando jobs pendentes...")
                jobs = fetch_jobs(data["device_uid"])
                if jobs:
                    print(f"Jobs recebidos: {len(jobs)}")
                else:
                    print("Nenhum job pendente.")

                for j in jobs:
                    job_id = j.get("job_id")
                    script_name = j.get("script_name") or "Script"
                    content = j.get("content") or ""

                    if not job_id or not content.strip():
                        if job_id:
                            post_job_result(job_id, "error", stderr="Script vazio", exit_code=None)
                        continue

                    allowed = confirm_local(script_name, content)
                    if not allowed:
                        post_job_result(job_id, "error", stderr="Negado pelo usuario local", exit_code=None)
                        continue

                    # SALVA E ABRE (SEM EXECUTAR AUTOMATICAMENTE)
                    try:
                        bat_path = save_bat(job_id, script_name, content)
                        open_file_or_folder(bat_path)

                        msg = (
                            "Aprovado localmente.\n"
                            f"Arquivo salvo em: {bat_path}\n"
                            "Abra o arquivo e execute manualmente."
                        )
                        post_job_result(job_id, "done", stdout=msg, stderr="", exit_code=0)
                    except Exception as ex:
                        post_job_result(job_id, "error", stderr=str(ex), exit_code=None)

            except Exception as ex:
                print(f"Erro ao processar jobs: {ex}")

        except Exception as e:
            print(f"ERRO geral: {e}")
            import traceback
            traceback.print_exc()

        print()
        print(f"Proxima atualizacao em {INTERVALO_SEG} segundos...")
        time.sleep(INTERVALO_SEG)
