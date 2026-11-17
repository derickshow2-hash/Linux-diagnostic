from __future__ import annotations

import re
from typing import Any

from app.models import Finding


def _text(obj: Any) -> str:
    if isinstance(obj, dict): return "\n".join(str(v) for v in obj.values())
    if isinstance(obj, (list, tuple)): return "\n".join(_text(v) for v in obj)
    return str(obj or "")


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any, default: float = 0) -> float:
    try: return float(value)
    except (TypeError, ValueError): return default


def analyze(data: dict[str, Any]) -> list[Finding]:
    if not isinstance(data, dict):
        return [Finding("Некорректный формат диагностических данных", "warning", "probable",
            [f"Получен объект типа {type(data).__name__}"],
            "Анализатор принимает словарь результатов модулей; данные не распознаны и не интерпретируются.", .95,
            ["Повторите сбор данных и приложите исходный JSON отчёта."], [], "Общее")]
    out: list[Finding] = []
    system=_mapping(data.get("system"))
    failed=_text(system.get("systemd_failed", {}))
    failed_lines=[x.strip() for x in failed.splitlines() if x.strip() and "not found" not in x.lower()]
    if failed_lines:
        out.append(Finding("Службы systemd завершились с ошибкой", "warning", "confirmed", failed_lines[:12],
            "systemctl --failed перечисляет units в состоянии failed. Наличие failed unit само по себе не доказывает влияние на симптом.", .9,
            ["Откройте журнал конкретной службы и проверьте, нужна ли она для вашей задачи."],
            ["systemctl status <unit>", "journalctl -u <unit> -b"], "Службы"))

    perf=_mapping(data.get("performance"))
    mem=_mapping(perf.get("memory"))
    if _number(mem.get("percent")) >= 95 and _number(mem.get("available"),float("inf")) < 512*1024**2:
        out.append(Finding("Доступной памяти мало", "critical", "probable", [f"RAM занято: {_number(mem.get('percent')):g}%", f"Доступно: {_number(mem.get('available'))/1024**2:.0f} MiB"],
            "Низкий объём доступной RAM может вызывать reclaim и задержки. Linux page cache не считается нехваткой памяти отдельно; учитывается available.", .75,
            ["Проверьте процессы с высоким RSS и сопоставьте время торможения с журналом OOM."], ["ps -eo pid,comm,rss,%mem --sort=-rss | head"], "CPU и RAM"))
    oom=_text(perf.get("oom_recent", {}))
    if re.search(r"Out of memory|oom-kill|Killed process", oom, re.I):
        out.append(Finding("Зафиксировано событие OOM", "critical", "confirmed", [x for x in oom.splitlines() if re.search(r"Out of memory|oom-kill|Killed process", x, re.I)][:8],
            "Ядро зарегистрировало нехватку памяти и запуск OOM killer. Это подтверждает событие, но виновный процесс и первопричину нужно смотреть в полном контексте.", .95,
            ["Сопоставьте PID и время события с нагрузкой и приложениями."], ["journalctl -k -b -g 'Out of memory|oom-kill|Killed process'"], "CPU и RAM"))

    gpu=_mapping(data.get("gpu"))
    gpu_log=_text(gpu.get("gpu_journal", {})); kwin=_text(gpu.get("kwin_journal", {}))
    nvidia=_text(gpu.get("nvidia_smi", {})); mods=_text(gpu.get("modules", {}))
    g_errors=re.findall(r"^.*(?:NVRM: Xid|GPU has fallen off the bus|RmInitAdapter failed).*$", gpu_log, re.I|re.M)
    if g_errors:
        out.append(Finding("Журнал содержит ошибки NVIDIA/Xid", "warning", "confirmed", g_errors[:10],
            "Xid и ошибки инициализации указывают на сбой в графическом стеке. Один журнал не позволяет отличить драйвер, питание, PCIe или аппаратную причину.", .85,
            ["Сравните время с зависанием интерфейса и событиями ядра; сохраните отчёт для дальнейшего анализа."], ["journalctl -k -b -g 'NVRM|Xid|fallen off the bus'"], "GPU"))
    if "nvidia" in gpu_log.lower() and "kwin" in kwin.lower() and (g_errors or re.search(r"error|failed|crash|segfault",kwin,re.I)):
        out.append(Finding("Ошибки графики и KWin совпадают по контексту", "warning", "probable",
            [*(g_errors[:3]), *[x for x in kwin.splitlines() if re.search(r"error|failed|crash|segfault",x,re.I)][:3]],
            "В журналах есть события драйвера и KWin. Ограниченные выборки не устанавливают точный временной порядок или причинность; проверьте полные записи вокруг времени сбоя.", .55,
            ["Сопоставьте timestamps и boot ID; проверьте, повторяется ли симптом после конкретного обновления."],
            ["journalctl -b -o short-precise -g 'NVRM|Xid|kwin|plasmashell'"], "GPU", ["Журнал содержит ошибки NVIDIA/Xid"] if g_errors else []))
    nvidia_result=_mapping(gpu.get("nvidia_smi"))
    if nvidia_result.get("returncode") not in (0, None) and nvidia_result.get("available"):
        out.append(Finding("nvidia-smi не смог получить состояние GPU", "warning", "probable", [_text(gpu["nvidia_smi"])[:800]],
            "Утилита присутствует, но запрос завершился ошибкой. Это может быть связано с модулем, устройством или контейнерной/виртуальной средой.", .65,
            ["Сопоставьте сообщение nvidia-smi с версией загруженного модуля и журналом ядра."], ["nvidia-smi", "cat /sys/module/nvidia/version"], "GPU"))
    loaded_version=str(gpu.get("loaded_nvidia", "")).strip()
    smi_version=re.search(r"NVIDIA GeForce[^,]*,\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",nvidia)
    if loaded_version and smi_version and loaded_version.split(".")[:2] != smi_version.group(1).split(".")[:2]:
        out.append(Finding("Версия загруженного модуля NVIDIA отличается от версии nvidia-smi", "warning", "confirmed", [f"Модуль: {loaded_version}",f"nvidia-smi: {smi_version.group(1)}"],
            "Номера версий указывают на несоответствие компонентов драйвера; проверьте журнал загрузки и время последнего обновления. Само наблюдение не доказывает, что это вызывает сбой.", .8,
            ["Проверьте, соответствует ли загруженный модуль установленным пакетам NVIDIA после перезагрузки."], ["cat /sys/module/nvidia/version", "nvidia-smi"], "GPU"))
    if re.search(r"nvidia", mods, re.I) and re.search(r"nouveau", mods, re.I):
        out.append(Finding("Загружены модули NVIDIA и nouveau", "warning", "probable", ["lsmod содержит оба имени модулей"],
            "Одновременное наличие в lsmod не доказывает, что оба управляют одной видеокартой; проверьте привязку PCI устройств.", .5,
            ["Проверьте драйвер, привязанный к каждому GPU, прежде чем менять конфигурацию."], ["lspci -nnk"], "GPU"))

    storage=_mapping(data.get("storage"))
    partitions=storage.get("partitions", [])
    partitions=partitions if isinstance(partitions,list) else []
    full=[d for d in partitions if isinstance(d,dict) and _number(d.get("percent")) >= 95]
    if full:
        out.append(Finding("Файловая система почти заполнена", "warning", "confirmed", [f"{d.get('mountpoint','?')} ({_number(d.get('percent')):g}%, {_number(d.get('free'))/1024**3:.1f} GiB свободно)" for d in full],
            "Заполнение выше 95% может мешать приложениям и обновлениям, но не означает повреждение файловой системы.", .9,
            ["Проверьте, какие каталоги занимают место, прежде чем удалять данные."], ["df -hT"], "Накопители"))
    io=_text(storage.get("io_journal", {}))
    io_errors=[x for x in io.splitlines() if re.search(r"I/O error|Buffer I/O|uncorrectable|medium error",x,re.I)]
    if io_errors:
        out.append(Finding("Ядро зарегистрировало ошибки ввода-вывода", "critical", "confirmed", io_errors[:10],
            "Журнал ядра содержит ошибки I/O. Это серьёзное свидетельство сбоя операции, но само по себе не доказывает физическую неисправность накопителя.", .9,
            ["Сделайте резервную копию важных данных и прочитайте SMART/NVMe health без запуска ремонта."], ["journalctl -k -b -g 'I/O error|Buffer I/O|uncorrectable|medium error'", "sudo smartctl -a <device>"], "Накопители"))
    smart_flags=[]
    smart_devices=storage.get("smart_devices", [])
    smart_devices=smart_devices if isinstance(smart_devices,list) else []
    for device_report in smart_devices:
        if not isinstance(device_report,dict): continue
        device=device_report.get("device","устройство")
        raw=_text(device_report)
        patterns=[(r"Reallocated_Sector_Ct\s+.*?\s+(\d+)\s*$","reallocated sectors"),
                  (r"Current_Pending_Sector\s+.*?\s+(\d+)\s*$","pending sectors"),
                  (r"Offline_Uncorrectable\s+.*?\s+(\d+)\s*$","offline uncorrectable sectors")]
        for pattern,label in patterns:
            vals=re.findall(pattern,raw,re.I|re.M)
            if vals and any(int(x)>0 for x in vals): smart_flags.append(f"{device}: {label} = {vals[-1]}")
        for line in raw.splitlines():
            if re.search(r"Critical Warning:\s*(?!0x00\b)0x[0-9a-f]+|Media and Data Integrity Errors:\s*[1-9]",line,re.I):
                smart_flags.append(f"{device}: {line.strip()}")
    if smart_flags:
        out.append(Finding("SMART сообщает о признаках деградации накопителя", "critical", "confirmed", smart_flags[:12],
            "SMART/NVMe счётчики содержат ненулевые значения для переназначенных, ожидающих или неисправимых секторов либо ошибок целостности. Интерпретация отдельных атрибутов зависит от производителя; сделайте резервную копию и проверьте полную health-информацию.", .85,
            ["Сохраните важные данные и проверьте полную документацию SMART для модели накопителя."], ["sudo smartctl -a <device>", "sudo nvme smart-log <device>"], "Накопители"))
    logs=_mapping(data.get("logs"))
    if io_errors and _mapping(logs.get("blame")).get("stdout"):
        out.append(Finding("Ошибки I/O могут быть связаны с задержками", "warning", "probable", io_errors[:4]+["systemd-analyze blame собрал время запуска units"],
            "Есть ошибки накопителя и сведения о длительности units, но причинная связь с медленной загрузкой по этим данным не установлена.", .45,
            ["Сопоставьте временные отметки I/O ошибок с журналом загрузки."], ["systemd-analyze critical-chain", "journalctl -b -k -o short-precise"], "Загрузка", ["Ядро зарегистрировало ошибки ввода-вывода"]))

    temps=_mapping(perf.get("temperatures"))
    hot=[]
    for source, readings in temps.items():
        for r in readings if isinstance(readings,list) else []:
            if isinstance(r,dict) and r.get("critical") is not None and r.get("current") is not None and _number(r["current"]) >= _number(r["critical"])-5:
                hot.append(f"{source} {r.get('label')}: {_number(r['current']):g}°C (critical {_number(r['critical']):g}°C)")
    if hot:
        out.append(Finding("Температура близка к критическому порогу", "warning", "confirmed", hot,
            "Датчик показывает значение в пределах 5 °C от объявленного им critical порога. Датчики и пороги зависят от платформы.", .8,
            ["Проверьте охлаждение и повторно измерьте температуру под обычной нагрузкой."], ["sensors -j"], "CPU и RAM"))
    mce=_text(_mapping(data.get("hardware")).get("mce", {}))
    hw=re.findall(r"^.*(?:Hardware Error|Machine Check|MCE|EDAC.*error).*$",mce,re.I|re.M)
    if hw:
        out.append(Finding("Журнал содержит аппаратные MCE/EDAC события", "critical", "confirmed", hw[:10],
            "Журнал сообщает об аппаратной ошибке. Нужны полная запись и контекст платформы, чтобы определить источник.", .85,
            ["Сохраните полный журнал события и проверьте, повторяется ли оно."], ["journalctl -k -b -g 'MCE|EDAC|Hardware Error'"], "Аппаратное"))

    net=_mapping(data.get("network"))
    ping=_mapping(net.get("gateway_ping"))
    if ping.get("available") and ping.get("returncode") not in (0, None) and ping.get("stdout"):
        out.append(Finding("Проба до шлюза не получила успешного ответа", "warning", "probable", [ping.get("stdout","")[-1200:]],
            "Короткая серия из трёх ICMP проб не завершилась успешно. Шлюз или сеть могут фильтровать ICMP, поэтому это не доказывает потерю пользовательского трафика.", .55,
            ["Сопоставьте с состоянием интерфейса и выполните повторную проверку в момент симптома."], ["ip route", "ping -c 3 <gateway>"], "Сеть"))
    dns=_mapping(net.get("dns_probe"))
    if dns.get("available") and dns.get("returncode") not in (0, None):
        out.append(Finding("Тестовое DNS-разрешение завершилось ошибкой", "warning", "probable", [dns.get("stderr","") or dns.get("stdout","") or dns.get("error","")],
            "Системный resolver не разрешил тестовое имя во время проверки. Причиной могут быть временная недоступность, политика сети или DNS-конфигурация.", .65,
            ["Сопоставьте результат с resolvectl status и проверкой других имён."], ["resolvectl status", "getent ahosts fedoraproject.org"], "Сеть"))

    current=_text(_mapping(data.get("logs")).get("current_errors", {}))
    # Generic error-level records are information until a rule can tie them to a concrete subsystem.
    count=sum(1 for line in current.splitlines() if line.strip())
    if count and not out:
        out.append(Finding("В журнале есть записи уровня error без подтверждённого дефекта", "info", "info", [f"В выборке текущей загрузки: {count} строк"],
            "Приоритет journalctl — уровень журнала, а не оценка пользовательского влияния. Без конкретной повторяющейся ошибки вывод о неисправности не делается.", .3,
            ["Откройте отдельные события и сопоставьте их с симптомами."], ["journalctl -b -p err --no-pager"], "Журналы"))
    return out
