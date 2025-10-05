#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cesar_gui.py

Interfaz gráfica (Tkinter + ttk) para cifrado y descifrado César (mod 26).
Guarda como cesar_gui.py y ejecútalo: python cesar_gui.py

Características:
 - Entrada de texto manual
 - Clave numérica (0..25) con slider y campo
 - Botones Cifrar / Descifrar
 - Vista de resultado, copiar al portapapeles, guardar a archivo
 - Lista de fuerza bruta que muestra las 26 posibilidades
 - Conserva mayúsculas/minúsculas y no altera caracteres no alfabéticos
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List

# -----------------------
# Lógica modular (módulo del cifrado César)
# -----------------------
def mod_add(a: int, b: int, m: int) -> int:
    return ((a % m) + (b % m)) % m

def char_to_num(c: str) -> int:
    if c.isalpha():
        return ord(c.upper()) - ord('A')
    raise ValueError("Caracter no alfabético")

def num_to_char(n: int, is_upper: bool = True) -> str:
    n_mod = n % 26
    ch = chr(n_mod + ord('A'))
    return ch if is_upper else ch.lower()

def caesar_encrypt(plaintext: str, k: int) -> str:
    out = []
    k = k % 26
    for ch in plaintext:
        if ch.isalpha():
            p = ord(ch.upper()) - ord('A')
            c = mod_add(p, k, 26)
            out.append(num_to_char(c, is_upper=ch.isupper()))
        else:
            out.append(ch)
    return ''.join(out)

def caesar_decrypt(ciphertext: str, k: int) -> str:
    out = []
    k = k % 26
    for ch in ciphertext:
        if ch.isalpha():
            c = ord(ch.upper()) - ord('A')
            p = mod_add(c, -k, 26)
            out.append(num_to_char(p, is_upper=ch.isupper()))
        else:
            out.append(ch)
    return ''.join(out)

def all_shifts(text: str) -> List[str]:
    """Devuelve lista de (k, resultado) para k=0..25 usando cifrado (aplicable para análisis por fuerza bruta)."""
    results = []
    for k in range(26):
        results.append(f"{k:2d}: {caesar_decrypt(text, k)}")  # Mostrar como descifrado con k
    return results

# -----------------------
# GUI
# -----------------------
class CaesarGUI(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=12)
        self.parent = parent
        self.parent.title("Cifrado César — GUI")
        self.pack(fill=tk.BOTH, expand=True)

        # Estilo ttk para apariencia más moderna
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('TButton', padding=6)
        style.configure('TLabel', padding=4)
        style.configure('TEntry', padding=4)
        style.configure('Header.TLabel', font=('Helvetica', 14, 'bold'))

        # Variables
        self.key_var = tk.IntVar(value=3)
        self.key_text_var = tk.StringVar(value="3")
        self.input_text_var = tk.StringVar(value="")
        self.output_text_var = tk.StringVar(value="")

        # Layout
        self._create_widgets()
        self._bind_events()
        self._update_force_brute()

    def _create_widgets(self):
        # Header
        header = ttk.Label(self, text="Cifrado César (mod 26)", style='Header.TLabel')
        header.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0,8))

        # Input text
        ttk.Label(self, text="Texto (ingresa aquí):").grid(row=1, column=0, sticky="w")
        self.input_text = tk.Text(self, height=6, wrap='word')
        self.input_text.grid(row=2, column=0, columnspan=3, sticky="nsew")
        self.input_text.insert('1.0', "")  # vacío por defecto

        # Key controls
        ttk.Label(self, text="Clave (K, entero):").grid(row=3, column=0, sticky="w", pady=(8,0))
        self.key_scale = ttk.Scale(self, from_=0, to=25, orient='horizontal', command=self._on_scale_change)
        self.key_scale.set(self.key_var.get())
        self.key_scale.grid(row=4, column=0, sticky="ew", padx=(0,8))

        self.key_entry = ttk.Entry(self, textvariable=self.key_text_var, width=6)
        self.key_entry.grid(row=4, column=1, sticky="w")
        ttk.Label(self, text="(0-25)").grid(row=4, column=2, sticky="w")

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=5, column=0, columnspan=3, sticky="w", pady=(8,0))
        self.encrypt_btn = ttk.Button(btn_frame, text="Cifrar ▶", command=self.on_encrypt)
        self.encrypt_btn.grid(row=0, column=0, padx=(0,6))
        self.decrypt_btn = ttk.Button(btn_frame, text="◀ Descifrar", command=self.on_decrypt)
        self.decrypt_btn.grid(row=0, column=1, padx=(0,6))
        self.copy_btn = ttk.Button(btn_frame, text="Copiar resultado", command=self.copy_result)
        self.copy_btn.grid(row=0, column=2, padx=(0,6))
        self.save_btn = ttk.Button(btn_frame, text="Guardar a archivo", command=self.save_to_file)
        self.save_btn.grid(row=0, column=3, padx=(0,6))
        self.clear_btn = ttk.Button(btn_frame, text="Limpiar", command=self.clear_all)
        self.clear_btn.grid(row=0, column=4, padx=(6,0))

        # Output
        ttk.Label(self, text="Resultado:").grid(row=6, column=0, sticky="w", pady=(8,0))
        self.output_text = tk.Text(self, height=6, wrap='word', state='normal')
        self.output_text.grid(row=7, column=0, columnspan=3, sticky="nsew")
        self.output_text.insert('1.0', "")

        # Brute-force list
        ttk.Label(self, text="Fuerza bruta (todas las claves):").grid(row=1, column=3, sticky="w", padx=(12,0))
        self.brutelist = tk.Listbox(self, width=40, height=20)
        self.brutelist.grid(row=2, column=3, rowspan=6, sticky="nsew", padx=(12,0))
        self.brutelist.bind('<<ListboxSelect>>', self.on_brute_select)

        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.columnconfigure(3, weight=0)
        self.rowconfigure(2, weight=0)
        self.rowconfigure(7, weight=0)
        self.rowconfigure(8, weight=1)

    def _bind_events(self):
        # Actualizar cuando cambie el Entry de la clave
        self.key_text_var.trace_add('write', lambda *args: self._on_key_entry_change())
        # Actualizar fuerza bruta cuando cambie el texto de entrada
        self.input_text.bind('<<Modified>>', self._on_input_modified)

    # ---- Event handlers / util ----
    def _on_scale_change(self, val):
        try:
            ival = int(float(val))
        except Exception:
            ival = 0
        self.key_var.set(ival)
        # actualizar entry (sin disparar bucle infinito)
        self.key_text_var.set(str(ival))

    def _on_key_entry_change(self):
        s = self.key_text_var.get()
        try:
            v = int(s)
        except Exception:
            return
        v = v % 26
        self.key_var.set(v)
        self.key_scale.set(v)

    def _on_input_modified(self, event=None):
        # Tkinter sets a "modified" flag; debemos resetearlo
        try:
            if self.input_text.edit_modified():
                self.input_text.edit_modified(False)
                self._update_force_brute()
        except Exception:
            pass

    def _update_force_brute(self):
        text = self.input_text.get("1.0", "end").rstrip('\n')
        self.brutelist.delete(0, tk.END)
        if not text:
            for k in range(26):
                self.brutelist.insert(tk.END, f"{k:2d}: ")
        else:
            for item in all_shifts(text):
                self.brutelist.insert(tk.END, item)

    def on_encrypt(self):
        text = self.input_text.get("1.0", "end").rstrip('\n')
        if text == "":
            messagebox.showinfo("Info", "Ingresa algún texto para cifrar.")
            return
        try:
            k = int(self.key_var.get()) % 26
        except Exception:
            messagebox.showerror("Error", "Clave no válida. Ingresa un entero.")
            return
        result = caesar_encrypt(text, k)
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', result)
        self.output_text.config(state='disabled')

    def on_decrypt(self):
        text = self.input_text.get("1.0", "end").rstrip('\n')
        if text == "":
            messagebox.showinfo("Info", "Ingresa algún texto para descifrar.")
            return
        try:
            k = int(self.key_var.get()) % 26
        except Exception:
            messagebox.showerror("Error", "Clave no válida. Ingresa un entero.")
            return
        result = caesar_decrypt(text, k)
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', result)
        self.output_text.config(state='disabled')

    def copy_result(self):
        result = self.output_text.get("1.0", "end").rstrip('\n')
        if not result:
            messagebox.showinfo("Info", "No hay resultado para copiar.")
            return
        self.parent.clipboard_clear()
        self.parent.clipboard_append(result)
        messagebox.showinfo("Copiado", "Resultado copiado al portapapeles.")

    def save_to_file(self):
        result = self.output_text.get("1.0", "end").rstrip('\n')
        if not result:
            messagebox.showinfo("Info", "No hay resultado para guardar.")
            return
        fn = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Guardar resultado como..."
        )
        if not fn:
            return
        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(result)
            messagebox.showinfo("Guardado", f"Resultado guardado en:\n{fn}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{e}")

    def clear_all(self):
        self.input_text.delete('1.0', tk.END)
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.config(state='disabled')
        self._update_force_brute()

    def on_brute_select(self, event):
        sel = self.brutelist.curselection()
        if not sel:
            return
        text = self.brutelist.get(sel[0])
        # text tiene "k: resultado" -> mostrar resultado en output
        parts = text.split(":", 1)
        if len(parts) == 2:
            resultado = parts[1].lstrip()
            self.output_text.config(state='normal')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', resultado)
            self.output_text.config(state='disabled')

# Ejecutar la app
def main():
    root = tk.Tk()
    # Tamaño y aspecto inicial
    root.geometry("950x520")
    app = CaesarGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
