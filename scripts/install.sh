#!/usr/bin/env bash
set -euo pipefail
clean_install=0
if [[ "${1:-}" == "--clean" ]]; then
    clean_install=1
    shift
fi
if (($# > 0)); then
    echo "Использование: $0 [--clean]" >&2
    exit 2
fi
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/fedora-doctor"
venv_dir="$install_dir/venv"
bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
applications_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$install_dir" "$bin_dir" "$applications_dir"
if ((clean_install)); then
    rm -rf -- "$venv_dir"
fi
python3 -m venv "$venv_dir"
if ((clean_install)); then
    "$venv_dir/bin/pip" install "$project_dir"
else
    # Reinstall local source even when package metadata still says version 0.1.0.
    "$venv_dir/bin/pip" install --force-reinstall --no-deps "$project_dir"
fi
(cd /tmp && "$venv_dir/bin/python" -c 'import app.main, app.reliability; print("Установлен модуль:", app.main.__file__)')
cat > "$bin_dir/fedora-doctor" <<EOF
#!/usr/bin/env bash
exec "$venv_dir/bin/fedora-doctor" "\$@"
EOF
chmod +x "$bin_dir/fedora-doctor"
cat > "$applications_dir/fedora-doctor.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Fedora Doctor
Comment=Read-only Fedora diagnostics
Exec=$bin_dir/fedora-doctor
Icon=utilities-system-monitor
Terminal=false
Categories=System;Utility;
EOF
echo "Установка завершена. Запустите: $bin_dir/fedora-doctor"
echo "Если $bin_dir не входит в PATH, запустите файл по полному пути или добавьте каталог в PATH."
if ((clean_install)); then
    echo "История и база мониторинга сохранены в $install_dir; удалено только виртуальное окружение."
fi
