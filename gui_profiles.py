"""Профили серверов и история подключений: сохранение, загрузка, удаление, выбор из истории.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы _profiles_file, _load_profiles, _save_profiles, save_profile, load_profile, delete_profile, _refresh_profiles, _load_conn_history, _save_conn_history, _on_history_select."""

from tkinter import messagebox, simpledialog
import os
import json


class ProfilesMixin:
    # ---------- ПРОФИЛИ СЕРВЕРОВ ----------
    def _profiles_file(self):
        return os.path.expanduser("~/.techsupp_diagtool_profiles.json")

    def _load_profiles(self):
        try:
            if os.path.exists(self._profiles_file()):
                with open(self._profiles_file(), 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_profiles(self, profiles):
        try:
            with open(self._profiles_file(), 'w', encoding='utf-8') as f:
                json.dump(profiles, f, indent=2)
            os.chmod(self._profiles_file(), 0o600)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить профили: {e}", parent=self.root)

    def save_profile(self):
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showerror("Ошибка", "Введите IP перед сохранением профиля", parent=self.root)
            return
        name = simpledialog.askstring("Профиль", "Имя профиля:", parent=self.root)
        if not name:
            return
        profiles = self._load_profiles()
        profiles[name.strip()] = {
            "ip": ip,
            "port": self.port_var.get().strip(),
            "user": self.user_var.get().strip(),
            "key": self.key_var.get().strip(),
            "panel": self.panel_var.get(),
        }
        self._save_profiles(profiles)
        self._refresh_profiles()
        self.log(f"✅ Профиль '{name}' сохранён")

    def load_profile(self):
        name = self.profile_var.get().strip()
        if not name:
            return
        profiles = self._load_profiles()
        p = profiles.get(name)
        if not p:
            return
        self.ip_var.set(p.get("ip", ""))
        self.port_var.set(p.get("port", "22"))
        self.user_var.set(p.get("user", "root"))
        self.key_var.set(p.get("key", "~/.ssh/id_rsa"))
        self.panel_var.set(p.get("panel", "auto"))
        self.log(f"Профиль '{name}' загружен")

    def delete_profile(self):
        name = self.profile_var.get().strip()
        if not name:
            return
        if not messagebox.askyesno("Удалить", f"Удалить профиль '{name}'?", parent=self.root):
            return
        profiles = self._load_profiles()
        profiles.pop(name, None)
        self._save_profiles(profiles)
        self._refresh_profiles()

    def _refresh_profiles(self):
        names = sorted(self._load_profiles().keys())
        if hasattr(self, 'profile_combo'):
            self.profile_combo['values'] = names

    def _load_conn_history(self):
        try:
            if os.path.exists(self.conn_history_file):
                with open(self.conn_history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)[:10]
        except Exception:
            pass
        return []

    def _save_conn_history(self, ip, port, user):
        entry = {"ip": ip, "port": str(port), "user": user}
        self.conn_history = [e for e in self.conn_history if e["ip"] != ip or e["port"] != str(port) or e["user"] != user]
        self.conn_history.insert(0, entry)
        self.conn_history = self.conn_history[:10]
        try:
            with open(self.conn_history_file, 'w', encoding='utf-8') as f:
                json.dump(self.conn_history, f, indent=2)
            os.chmod(self.conn_history_file, 0o600)
        except Exception:
            pass

    def _on_history_select(self, event):
        sel = self.history_combo.get()
        for entry in self.conn_history:
            if f"{entry['ip']}:{entry['port']} ({entry['user']})" == sel:
                self.ip_var.set(entry['ip'])
                self.port_var.set(entry['port'])
                self.user_var.set(entry['user'])
                break
