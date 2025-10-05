#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cesar_modular.py

Interfaz gráfica (Tkinter + ttk) para cifrado y descifrado clásico (mod 26).
Incluye César y Afin, además de utilidades de aritmética modular.

Ejecuta: python cesar_modular.py

Características:
- Entrada de texto manual y lectura desde archivo
- Selector de algoritmo: César / Afin
- Claves con controles dinámicos (slider/entry para K y b, combobox para a)
- Botones Cifrar / Descifrar / Copiar / Guardar / Limpiar / Intercambiar
- Menú: Abrir, Guardar, Sugerir K (César), Calculadora modular, Acerca de
- Vista de resultado (solo lectura)
- Panel de fuerza bruta (26 claves para César o 26 para b con a fijo en Afin)
- Conserva mayúsculas/minúsculas y no altera caracteres no alfabéticos
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Tuple

# -----------------------
# Lógica modular (módulo del cifrado César)
# -----------------------
def mod_add(a: int, b: int, m: int) -> int:
    return ((a % m) + (b % m)) % m

def mod_sub(a: int, b: int, m: int) -> int:
    return ((a % m) - (b % m)) % m

def mod_mul(a: int, b: int, m: int) -> int:
    return ((a % m) * (b % m)) % m

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Ext. Euclides: retorna (g, x, y) tal que ax + by = g = gcd(a,b)."""
    if b == 0:
        return (abs(a), 1 if a > 0 else -1, 0)
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def mod_inv(a: int, m: int) -> int:
    """Inverso modular de a modulo m. Lanza ValueError si no existe."""
    a_mod = a % m
    g, x, _ = egcd(a_mod, m)
    if g != 1:
        raise ValueError(f"a={a} no tiene inverso módulo {m}")
    return x % m

def mod_pow(a: int, e: int, m: int) -> int:
    return pow(a % m, e, m)

def char_to_num(c: str) -> int:
    if c.isalpha():
        return ord(c.upper()) - ord('A')
    raise ValueError("Caracter no alfabético")

def num_to_char(n: int, is_upper: bool = True) -> str:
    n_mod = n % 26
    ch = chr(n_mod + ord('A'))
    return ch if is_upper else ch.lower()

# -----------------------
# Cifrado César
# -----------------------

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

# -----------------------
# Cifrado Afin (a debe ser coprimo con 26)
# E(x) = (a*x + b) mod 26
# D(x) = a^{-1} * (x - b) mod 26
# -----------------------
VALID_A_VALUES = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

def affine_encrypt(plaintext: str, a: int, b: int) -> str:
    a = a % 26
    b = b % 26
    if a not in VALID_A_VALUES:
        raise ValueError("La clave 'a' debe ser coprima con 26")
    out = []
    for ch in plaintext:
        if ch.isalpha():
            x = ord(ch.upper()) - ord('A')
            c = mod_add(mod_mul(a, x, 26), b, 26)
            out.append(num_to_char(c, is_upper=ch.isupper()))
        else:
            out.append(ch)
    return ''.join(out)

def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    a = a % 26
    b = b % 26
    if a not in VALID_A_VALUES:
        raise ValueError("La clave 'a' debe ser coprima con 26")
    a_inv = mod_inv(a, 26)
    out = []
    for ch in ciphertext:
        if ch.isalpha():
            y = ord(ch.upper()) - ord('A')
            p = mod_mul(a_inv, mod_sub(y, b, 26), 26)
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

def all_affine_b_shifts_for_a(text: str, a: int) -> List[str]:
    """Devuelve lista para Afin variando b=0..25 con 'a' fijo (descifrado)."""
    if a not in VALID_A_VALUES:
        return [f"b={b:2d}: [a inválido]" for b in range(26)]
    results = []
    for b in range(26):
        try:
            results.append(f"b={b:2d}: {affine_decrypt(text, a, b)}")
        except Exception:
            results.append(f"b={b:2d}: [error]")
    return results

# -----------------------
# GUI
# -----------------------
class CaesarGUI(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=12)
        self.parent = parent
        self.parent.title("Cifrador clásico (César / Afin) — GUI")
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
        self.algorithm_var = tk.StringVar(value="César")
        self.key_var = tk.IntVar(value=3)
        self.key_text_var = tk.StringVar(value="3")
        # Afin
        self.a_var = tk.IntVar(value=5)
        self.a_text_var = tk.StringVar(value="5")
        self.b_var = tk.IntVar(value=8)
        self.b_text_var = tk.StringVar(value="8")
        self.input_text_var = tk.StringVar(value="")
        self.output_text_var = tk.StringVar(value="")

        # Layout
        self._create_menubar()
        self._create_widgets()
        self._bind_events()
        self._update_force_brute()

    def _create_widgets(self):
        # Header
        header = ttk.Label(self, text="Cifrado clásico (mod 26)", style='Header.TLabel')
        header.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0,8))

        # Input text
        ttk.Label(self, text="Texto (ingresa aquí):").grid(row=1, column=0, sticky="w")
        self.input_text = tk.Text(self, height=6, wrap='word')
        self.input_text.grid(row=2, column=0, columnspan=3, sticky="nsew")
        self.input_text.insert('1.0', "")  # vacío por defecto

        # Algorithm selector
        ttk.Label(self, text="Algoritmo:").grid(row=3, column=0, sticky="w", pady=(8,0))
        self.alg_combo = ttk.Combobox(self, state="readonly", values=["César", "Afin"], textvariable=self.algorithm_var, width=12)
        self.alg_combo.grid(row=3, column=1, sticky="w")

        # Key controls container
        self.key_container = ttk.Frame(self)
        self.key_container.grid(row=4, column=0, columnspan=3, sticky="ew")

        # Caesar key frame
        self.caesar_keys_frame = ttk.Frame(self.key_container)
        ttk.Label(self.caesar_keys_frame, text="Clave (K, entero):").grid(row=0, column=0, sticky="w")
        self.key_scale = ttk.Scale(self.caesar_keys_frame, from_=0, to=25, orient='horizontal', command=self._on_scale_change)
        self.key_scale.set(self.key_var.get())
        self.key_scale.grid(row=1, column=0, sticky="ew", padx=(0,8))
        self.key_entry = ttk.Entry(self.caesar_keys_frame, textvariable=self.key_text_var, width=6)
        self.key_entry.grid(row=1, column=1, sticky="w")
        ttk.Label(self.caesar_keys_frame, text="(0-25)").grid(row=1, column=2, sticky="w")

        # Affine key frame
        self.affine_keys_frame = ttk.Frame(self.key_container)
        ttk.Label(self.affine_keys_frame, text="Clave afin a (coprimo con 26):").grid(row=0, column=0, sticky="w")
        self.a_combo = ttk.Combobox(self.affine_keys_frame, state="readonly", values=[str(v) for v in VALID_A_VALUES], width=6)
        self.a_combo.set(str(self.a_var.get()))
        self.a_combo.grid(row=0, column=1, sticky="w", padx=(4,8))
        ttk.Label(self.affine_keys_frame, text="b:").grid(row=0, column=2, sticky="w", padx=(12,0))
        self.b_scale = ttk.Scale(self.affine_keys_frame, from_=0, to=25, orient='horizontal', command=self._on_b_scale_change)
        self.b_scale.set(self.b_var.get())
        self.b_scale.grid(row=0, column=3, sticky="ew", padx=(4,8))
        self.b_entry = ttk.Entry(self.affine_keys_frame, textvariable=self.b_text_var, width=6)
        self.b_entry.grid(row=0, column=4, sticky="w")
        ttk.Label(self.affine_keys_frame, text="(0-25)").grid(row=0, column=5, sticky="w", padx=(4,0))

        # Show initial key frame
        self._show_key_frame()

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
        self.swap_btn = ttk.Button(btn_frame, text="Intercambiar ↔", command=self.swap_io)
        self.swap_btn.grid(row=0, column=5, padx=(6,0))

        # Output
        ttk.Label(self, text="Resultado:").grid(row=6, column=0, sticky="w", pady=(8,0))
        self.output_text = tk.Text(self, height=6, wrap='word', state='normal')
        self.output_text.grid(row=7, column=0, columnspan=3, sticky="nsew")
        self.output_text.insert('1.0', "")

        # Brute-force list
        self.brute_label = ttk.Label(self, text="Fuerza bruta (todas las claves):")
        self.brute_label.grid(row=1, column=3, sticky="w", padx=(12,0))
        self.brutelist = tk.Listbox(self, width=40, height=20)
        self.brutelist.grid(row=2, column=3, rowspan=6, sticky="nsew", padx=(12,0))
        self.brutelist.bind('<<ListboxSelect>>', self.on_brute_select)

        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.columnconfigure(3, weight=0)
        self.rowconfigure(2, weight=0)
        self.rowconfigure(7, weight=0)
        self.rowconfigure(8, weight=1)

    def _create_menubar(self):
        menubar = tk.Menu(self.parent)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Abrir…", command=self.open_file_to_input)
        file_menu.add_command(label="Guardar resultado…", command=self.save_to_file)
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.parent.destroy)
        menubar.add_cascade(label="Archivo", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Sugerir K (César)", command=self.suggest_caesar_key)
        tools_menu.add_command(label="Calculadora modular…", command=self.open_modcalc)
        menubar.add_cascade(label="Herramientas", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Acerca de", command=self.show_about)
        menubar.add_cascade(label="Ayuda", menu=help_menu)

        self.parent.config(menu=menubar)

    def _bind_events(self):
        # Actualizar cuando cambie el Entry de la clave
        self.key_text_var.trace_add('write', lambda *args: self._on_key_entry_change())
        # Actualizar fuerza bruta cuando cambie el texto de entrada
        self.input_text.bind('<<Modified>>', self._on_input_modified)
        # Algoritmo / Afin keys
        self.alg_combo.bind('<<ComboboxSelected>>', lambda e: self._on_algorithm_change())
        self.a_combo.bind('<<ComboboxSelected>>', lambda e: self._on_a_change())
        self.b_text_var.trace_add('write', lambda *args: self._on_b_entry_change())

    # ---- Event handlers / util ----
    def _on_scale_change(self, val):
        try:
            ival = int(float(val))
        except Exception:
            ival = 0
        self.key_var.set(ival)
        # actualizar entry (sin disparar bucle infinito)
        self.key_text_var.set(str(ival))
        # No actualiza fuerza bruta porque lista ya cubre todos los k

    def _on_key_entry_change(self):
        s = self.key_text_var.get()
        try:
            v = int(s)
        except Exception:
            return
        v = v % 26
        self.key_var.set(v)
        self.key_scale.set(v)

    def _on_b_scale_change(self, val):
        try:
            ival = int(float(val))
        except Exception:
            ival = 0
        ival = ival % 26
        self.b_var.set(ival)
        self.b_text_var.set(str(ival))
        # No es necesario recalcular fuerza bruta (depende solo de a)

    def _on_b_entry_change(self):
        s = self.b_text_var.get()
        try:
            v = int(s)
        except Exception:
            return
        v = v % 26
        self.b_var.set(v)
        self.b_scale.set(v)

    def _on_a_change(self):
        try:
            a = int(self.a_combo.get())
        except Exception:
            a = 1
        self.a_var.set(a)
        self._update_force_brute()

    def _on_input_modified(self, event=None):
        # Tkinter sets a "modified" flag; debemos resetearlo
        try:
            if self.input_text.edit_modified():
                self.input_text.edit_modified(False)
                self._update_force_brute()
        except Exception:
            pass

    def _on_algorithm_change(self):
        self._show_key_frame()
        self._update_force_brute()

    def _show_key_frame(self):
        # Limpiar key_container
        for child in self.key_container.winfo_children():
            child.grid_forget()
        algo = self.algorithm_var.get()
        if algo == "César":
            self.caesar_keys_frame.grid(row=0, column=0, sticky="ew")
            self.brute_label.config(text="Fuerza bruta (todas las claves K):")
        else:
            self.affine_keys_frame.grid(row=0, column=0, sticky="ew")
            self.brute_label.config(text="Fuerza bruta Afin (variando b, a fijo):")

    def _update_force_brute(self):
        text = self.input_text.get("1.0", "end").rstrip('\n')
        self.brutelist.delete(0, tk.END)
        algo = self.algorithm_var.get()
        if algo == "César":
            if not text:
                for k in range(26):
                    self.brutelist.insert(tk.END, f"{k:2d}: ")
            else:
                for item in all_shifts(text):
                    self.brutelist.insert(tk.END, item)
        else:
            a = self.a_var.get()
            if not text:
                for b in range(26):
                    self.brutelist.insert(tk.END, f"b={b:2d}: ")
            else:
                for item in all_affine_b_shifts_for_a(text, a):
                    self.brutelist.insert(tk.END, item)

    def on_encrypt(self):
        text = self.input_text.get("1.0", "end").rstrip('\n')
        if text == "":
            messagebox.showinfo("Info", "Ingresa algún texto para cifrar.")
            return
        algo = self.algorithm_var.get()
        try:
            if algo == "César":
                k = int(self.key_var.get()) % 26
                result = caesar_encrypt(text, k)
            else:
                a = int(self.a_var.get())
                b = int(self.b_var.get()) % 26
                result = affine_encrypt(text, a, b)
        except Exception as e:
            messagebox.showerror("Error", f"Clave no válida: {e}")
            return
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', result)
        self.output_text.config(state='disabled')

    def on_decrypt(self):
        text = self.input_text.get("1.0", "end").rstrip('\n')
        if text == "":
            messagebox.showinfo("Info", "Ingresa algún texto para descifrar.")
            return
        algo = self.algorithm_var.get()
        try:
            if algo == "César":
                k = int(self.key_var.get()) % 26
                result = caesar_decrypt(text, k)
            else:
                a = int(self.a_var.get())
                b = int(self.b_var.get()) % 26
                result = affine_decrypt(text, a, b)
        except Exception as e:
            messagebox.showerror("Error", f"Clave no válida: {e}")
            return
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

    def open_file_to_input(self):
        fn = filedialog.askopenfilename(
            title="Abrir archivo de texto…",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not fn:
            return
        try:
            with open(fn, "r", encoding="utf-8") as f:
                data = f.read()
            self.input_text.delete('1.0', tk.END)
            self.input_text.insert('1.0', data)
            self._update_force_brute()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el archivo:\n{e}")

    def clear_all(self):
        self.input_text.delete('1.0', tk.END)
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.config(state='disabled')
        self._update_force_brute()

    def swap_io(self):
        input_text = self.input_text.get('1.0', 'end').rstrip('\n')
        output_text = self.output_text.get('1.0', 'end').rstrip('\n')
        self.input_text.delete('1.0', tk.END)
        self.input_text.insert('1.0', output_text)
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert('1.0', input_text)
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

    # -----------------------
    # Herramientas
    # -----------------------
    def suggest_caesar_key(self):
        text = self.input_text.get('1.0', 'end')
        letters = [ch.upper() for ch in text if ch.isalpha()]
        if not letters:
            messagebox.showinfo("Sugerencia", "No hay letras para analizar.")
            return
        # Conteo simple y suposición de letra 'E' (4) como más frecuente
        from collections import Counter
        cnt = Counter(letters)
        most_common_letter, _ = cnt.most_common(1)[0]
        cipher_idx = ord(most_common_letter) - ord('A')
        candidates_plain = ['E', 'A', 'O']  # suposiciones comunes en ES
        suggestions = []
        for plain in candidates_plain:
            k = (cipher_idx - (ord(plain) - ord('A'))) % 26
            suggestions.append((plain, k))
        # Mostrar
        msg_lines = [f"Letra más frecuente: {most_common_letter}"]
        for plain, k in suggestions:
            msg_lines.append(f"Si representa '{plain}', K ≈ {k}")
        apply = messagebox.askyesno("Sugerir K (César)", "\n".join(msg_lines) + "\n\n¿Aplicar la mejor K sugerida?")
        if apply:
            best_k = suggestions[0][1]
            self.key_var.set(best_k)
            self.key_scale.set(best_k)
            self.key_text_var.set(str(best_k))

    def open_modcalc(self):
        win = tk.Toplevel(self.parent)
        win.title("Calculadora modular")
        frame = ttk.Frame(win, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Módulo (m):").grid(row=0, column=0, sticky='w')
        m_var = tk.StringVar(value="26")
        m_entry = ttk.Entry(frame, textvariable=m_var, width=8)
        m_entry.grid(row=0, column=1, sticky='w')

        ttk.Label(frame, text="Operación:").grid(row=1, column=0, sticky='w', pady=(6,0))
        op_combo = ttk.Combobox(frame, state='readonly', values=[
            'a + b (mod m)',
            'a - b (mod m)',
            'a * b (mod m)',
            'a^b (mod m)',
            'inv(a) (mod m)'
        ], width=18)
        op_combo.current(0)
        op_combo.grid(row=1, column=1, sticky='w', pady=(6,0))

        ttk.Label(frame, text="a:").grid(row=2, column=0, sticky='w', pady=(6,0))
        a_var = tk.StringVar(value="5")
        a_entry = ttk.Entry(frame, textvariable=a_var, width=12)
        a_entry.grid(row=2, column=1, sticky='w', pady=(6,0))

        ttk.Label(frame, text="b:").grid(row=3, column=0, sticky='w')
        b_var = tk.StringVar(value="8")
        b_entry = ttk.Entry(frame, textvariable=b_var, width=12)
        b_entry.grid(row=3, column=1, sticky='w')

        result_var = tk.StringVar(value="")
        ttk.Label(frame, text="Resultado:").grid(row=4, column=0, sticky='w', pady=(8,0))
        result_entry = ttk.Entry(frame, textvariable=result_var, width=32, state='readonly')
        result_entry.grid(row=4, column=1, sticky='w', pady=(8,0))

        def compute():
            try:
                m = int(m_var.get())
                a = int(a_var.get())
                op = op_combo.get()
                if m <= 0:
                    raise ValueError('m debe ser positivo')
                if op == 'a + b (mod m)':
                    b = int(b_var.get())
                    result = mod_add(a, b, m)
                elif op == 'a - b (mod m)':
                    b = int(b_var.get())
                    result = mod_sub(a, b, m)
                elif op == 'a * b (mod m)':
                    b = int(b_var.get())
                    result = mod_mul(a, b, m)
                elif op == 'a^b (mod m)':
                    b = int(b_var.get())
                    result = mod_pow(a, b, m)
                else:  # inv(a)
                    result = mod_inv(a, m)
                result_var.set(str(result))
            except Exception as e:
                messagebox.showerror('Error', f'Entrada inválida: {e}')

        def on_op_change(event=None):
            op = op_combo.get()
            if op == 'inv(a) (mod m)':
                b_entry.configure(state='disabled')
            else:
                b_entry.configure(state='normal')

        op_combo.bind('<<ComboboxSelected>>', on_op_change)
        on_op_change()

        compute_btn = ttk.Button(frame, text='Calcular', command=compute)
        compute_btn.grid(row=5, column=0, columnspan=2, pady=(10,0))

    def show_about(self):
        message = (
            "Cifrador clásico (César / Afin) — versión educativa\n\n"
            "Aplica aritmética modular (mod 26).\n"
            "Incluye calculadora modular y fuerza bruta.\n\n"
            "Autor: Equipo de proyecto"
        )
        messagebox.showinfo("Acerca de", message)

# Ejecutar la app
def main():
    root = tk.Tk()
    # Tamaño y aspecto inicial
    root.geometry("1050x560")
    app = CaesarGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
