import tkinter as tk
from tkinter import messagebox, Menu, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Generate a random 16-byte key for AES encryption
# توليد مفتاح عشوائي 16 بايت لتشفير AES
key = get_random_bytes(16)

# ---------- Language Dictionary / قاموس الترجمات ----------
lang_dict = {
    "ar": {
        "input_text": "أدخل النص للتشفير أو لفك التشفير:",
        "output_text": "الناتج:",
        "btn_encrypt": "🔐 تشفير",
        "btn_decrypt": "🔓 فك التشفير",
        "btn_copy": "📋 نسخ الناتج",
        "warning_input": "الرجاء إدخال نص.",
        "warning_decrypt_input": "الرجاء إدخال نص مشفر.",
        "error_decrypt": "فشل في فك التشفير:\n",
        "success_copy": "تم نسخ الناتج إلى الحافظة."
    },
    "en": {
        "input_text": "Enter text to encrypt or decrypt:",
        "output_text": "Output:",
        "btn_encrypt": "🔐 Encrypt",
        "btn_decrypt": "🔓 Decrypt",
        "btn_copy": "📋 Copy Result",
        "warning_input": "Please enter text.",
        "warning_decrypt_input": "Please enter encrypted text.",
        "error_decrypt": "Decryption failed:\n",
        "success_copy": "Result copied to clipboard."
    }
}

# Current language (default: Arabic)
# اللغة الحالية (الافتراضية: العربية)
current_lang = "ar"

# ---------- Theme Definitions / تعريفات السمات ----------
light_theme = {
    "bg": "#f5f5f5",  # Background color / لون الخلفية
    "fg": "#000000",  # Foreground (text) color / لون النص
    "primary": "#6200EE",  # Primary color / اللون الأساسي
    "secondary": "#03DAC6",  # Secondary color / اللون الثانوي
    "entry_bg": "#FFFFFF",  # Entry background / خلفية مربع النص
    "button_fg": "#000000",  # Button text color / لون نص الأزرار
    "button_active": "#6200EE",  # Active button color / لون الزر النشط
    "output_bg": "#eeeeee",  # Output background / خلفية منطقة الإخراج
    "top_bar": "#6200EE",  # Top bar color (fixed) / لون الشريط العلوي (ثابت)
    "copy_btn_fg": "#FFFFFF"  # Copy button text color / لون نص زر النسخ
}

dark_theme = {
    "bg": "#303030",
    "fg": "#FFFFFF",
    "primary": "#BB86FC",
    "secondary": "#03DAC6",
    "entry_bg": "#505050",
    "button_fg": "#FFFFFF",
    "button_active": "#3700B3",
    "output_bg": "#505050",
    "top_bar": "#6200EE",  # Same as light theme / نفس لون السمة الفاتحة
    "copy_btn_fg": "#000000"  # Black text on copy button in dark theme / نص أسود على زر النسخ في السمة المظلمة
}

# Current theme (default: light)
# السمة الحالية (الافتراضية: فاتحة)
current_theme = light_theme

# ---------- Encryption/Decryption Functions / وظائف التشفير وفك التشفير ----------

def encrypt_text():
    """Encrypt the input text using AES-CBC / تشفير النص المدخل باستخدام AES-CBC"""
    data = input_text.get("1.0", tk.END).strip()
    if not data:
        messagebox.showwarning("Warning", lang_dict[current_lang]["warning_input"])
        return
    
    # Create cipher object and encrypt
    # إنشاء كائن التشفير والتشفير
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = cipher.iv
    
    # Combine IV and ciphertext and encode as base64
    # دمج متجه التهيئة والنص المشفر وتشفيرها باستخدام base64
    encrypted_data = base64.b64encode(iv + ct_bytes).decode()
    
    # Display the result
    # عرض النتيجة
    output_text.config(state=tk.NORMAL)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted_data)
    output_text.config(state=tk.DISABLED)

def decrypt_text():
    """Decrypt the input text using AES-CBC / فك تشفير النص المدخل باستخدام AES-CBC"""
    data = input_text.get("1.0", tk.END).strip()
    if not data:
        messagebox.showwarning("Warning", lang_dict[current_lang]["warning_decrypt_input"])
        return
    
    try:
        # Decode base64 and separate IV from ciphertext
        # فك تشفير base64 وفصل متجه التهيئة عن النص المشفر
        raw = base64.b64decode(data)
        iv = raw[:AES.block_size]
        ct = raw[AES.block_size:]
        
        # Create cipher object and decrypt
        # إنشاء كائن التشفير وفك التشفير
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode()
        
        # Display the result
        # عرض النتيجة
        output_text.config(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted)
        output_text.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", lang_dict[current_lang]["error_decrypt"] + str(e))

def copy_output():
    """Copy output text to clipboard / نسخ النص الناتج إلى الحافظة"""
    result = output_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Info", lang_dict[current_lang]["success_copy"])

# ---------- Context Menu / قائمة السياق ----------
def add_context_menu(widget):
    """Add right-click context menu to a widget / إضافة قائمة سياق بالزر الأيمن لأداة"""
    menu = Menu(widget, tearoff=0)
    menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    
    def show_menu(event):
        """Show the context menu / عرض قائمة السياق"""
        menu.tk_popup(event.x_root, event.y_root)
    
    widget.bind("<Button-3>", show_menu)

# ---------- UI Update Function / دالة تحديث واجهة المستخدم ----------
def update_ui():
    """Update UI elements with current language / تحديث عناصر الواجهة باللغة الحالية"""
    input_label.config(text=lang_dict[current_lang]["input_text"])
    output_label.config(text=lang_dict[current_lang]["output_text"])
    btn_encrypt.config(text=lang_dict[current_lang]["btn_encrypt"])
    btn_decrypt.config(text=lang_dict[current_lang]["btn_decrypt"])
    btn_copy.config(text=lang_dict[current_lang]["btn_copy"])

# ---------- Language Toggle Function / دالة تبديل اللغة ----------
def toggle_language():
    """Toggle between Arabic and English / التبديل بين العربية والإنجليزية"""
    global current_lang
    current_lang = "en" if current_lang == "ar" else "ar"
    update_ui()

# ---------- Theme Toggle Function / دالة تبديل السمة ----------
def toggle_theme():
    """Toggle between light and dark themes / التبديل بين السمة الفاتحة والغامقة"""
    global current_theme
    if current_theme == light_theme:
        current_theme = dark_theme
    else:
        current_theme = light_theme
    
    # Update UI colors / تحديث ألوان الواجهة
    root.configure(bg=current_theme["bg"])
    input_label.config(bg=current_theme["bg"], fg=current_theme["fg"])
    output_label.config(bg=current_theme["bg"], fg=current_theme["fg"])
    input_text.config(bg=current_theme["entry_bg"], fg=current_theme["fg"], 
                     insertbackground=current_theme["fg"])
    output_text.config(bg=current_theme["output_bg"], fg=current_theme["fg"])
    btn_encrypt.config(bg=current_theme["primary"], fg=current_theme["button_fg"], 
                      activebackground=current_theme["button_active"])
    btn_decrypt.config(bg=current_theme["secondary"], fg=current_theme["button_fg"], 
                      activebackground=current_theme["button_active"])
    btn_copy.config(bg=current_theme["button_fg"], fg=current_theme["copy_btn_fg"], 
                   activebackground=current_theme["button_fg"])
    button_frame.config(bg=current_theme["bg"])

# ---------- Main Application Setup / إعداد التطبيق الرئيسي ----------
root = tk.Tk()
root.title("AES | Encrypt and Decrypt")

# Center the window with slightly larger size
# توسيط النافذة بحجم أكبر قليلاً
window_width = 800
window_height = 600
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)
root.geometry(f"{window_width}x{window_height}+{x}+{y}")
root.resizable(False, False)  # Disable window resizing / تعطيل تغيير حجم النافذة
root.configure(bg=current_theme["bg"])

font_main = ("Segoe UI", 11)

# ---------- Top Bar / الشريط العلوي ----------
# Note: Top bar color remains fixed / ملاحظة: لون الشريط العلوي يبقى ثابتاً
top_bar = tk.Frame(root, bg=light_theme["top_bar"], height=40)
top_bar.pack(fill=tk.X)

# Language toggle button / زر تبديل اللغة
lang_button = tk.Button(top_bar, text="🌍", command=toggle_language, 
                       bg=light_theme["top_bar"], fg="white", 
                       font=("Segoe UI", 14), width=3, relief="flat", bd=0)
lang_button.pack(side=tk.RIGHT, padx=10, pady=5)

# Theme toggle button / زر تبديل السمة
theme_button = tk.Button(top_bar, text="🌙", command=toggle_theme, 
                        bg=light_theme["top_bar"], fg="white", 
                        font=("Segoe UI", 14), width=3, relief="flat", bd=0)
theme_button.pack(side=tk.RIGHT, padx=10, pady=5)

# ---------- User Interface / واجهة المستخدم ----------

# Input label and text area / تسمية ومربع نص الإدخال
input_label = tk.Label(root, text=lang_dict[current_lang]["input_text"], 
                      font=("Segoe UI", 12), bg=current_theme["bg"], fg=current_theme["fg"])
input_label.pack(pady=(15, 5))

input_text = scrolledtext.ScrolledText(root, height=6, width=80, 
                                     bg=current_theme["entry_bg"], fg=current_theme["fg"], 
                                     font=font_main, relief=tk.FLAT, borderwidth=5, wrap=tk.WORD)
input_text.pack(pady=5, fill=tk.BOTH, expand=True)
input_text.config(insertbackground=current_theme["fg"])  # Cursor color / لون المؤشر
add_context_menu(input_text)

# Buttons frame / إطار الأزرار
button_frame = tk.Frame(root, bg=current_theme["bg"])
button_frame.pack(pady=15, fill=tk.X)

# Decrypt button / زر فك التشفير
btn_decrypt = tk.Button(button_frame, text=lang_dict[current_lang]["btn_decrypt"], command=decrypt_text,
                       bg=current_theme["secondary"], fg=current_theme["button_fg"], font=font_main, width=15,
                       relief="flat", bd=2, padx=20, pady=10, highlightthickness=0, 
                       activebackground=current_theme["button_active"])
btn_decrypt.pack(side=tk.LEFT, padx=10, expand=True)

# Encrypt button / زر التشفير
btn_encrypt = tk.Button(button_frame, text=lang_dict[current_lang]["btn_encrypt"], command=encrypt_text,
                       bg=current_theme["primary"], fg=current_theme["button_fg"], font=font_main, width=15,
                       relief="flat", bd=2, padx=20, pady=10, highlightthickness=0, 
                       activebackground=current_theme["button_active"])
btn_encrypt.pack(side=tk.LEFT, padx=10, expand=True)

# Output label and text area / تسمية ومربع نص الإخراج
output_label = tk.Label(root, text=lang_dict[current_lang]["output_text"], 
                       font=("Segoe UI", 12), bg=current_theme["bg"], fg=current_theme["fg"])
output_label.pack(pady=(10, 5))

output_text = scrolledtext.ScrolledText(root, height=6, width=80, 
                                      bg=current_theme["output_bg"], fg=current_theme["fg"], 
                                      font=font_main, state=tk.DISABLED, 
                                      relief=tk.FLAT, borderwidth=5, wrap=tk.WORD)
output_text.pack(fill=tk.BOTH, expand=True)
add_context_menu(output_text)

# Copy button / زر النسخ
btn_copy = tk.Button(root, text=lang_dict[current_lang]["btn_copy"], command=copy_output,
                    bg=current_theme["button_fg"], fg=current_theme["copy_btn_fg"], 
                    font=font_main, width=15, relief="flat",
                    bd=2, padx=20, pady=10, highlightthickness=0, 
                    activebackground=current_theme["button_fg"])
btn_copy.pack(pady=(10, 20))

# Start the application / بدء التطبيق
root.mainloop()