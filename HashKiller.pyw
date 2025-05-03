
#OFFICIAL HASHKILLER CODE
#PART OF THE HASHKILLER PROJECT

import hashlib
import tkinter as tk
from tkinter import messagebox, filedialog, ttk, font
import threading
import time
from PIL import Image, ImageTk
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter.font as tkFont
import threading
from concurrent.futures import ThreadPoolExecutor
import zlib
from hashlib import scrypt
import os
from passlib.context import CryptContext
import bcrypt
import GPUtil
import psutil

def get_cpu_count():
    """Get the number of logical CPU cores."""
    return os.cpu_count()

def get_gpu_count():
    """Get the number of available GPUs."""
    gpus = GPUtil.getGPUs()
    return len(gpus)

def calculate_resources():
    """Calculate the number of CPU resources to use."""
    cpu_count = os.cpu_count()  
    cpu_threads = max(1, cpu_count // 2) 
    return cpu_threads

executor = None

def initialize_executor():
    global executor
    cpu_threads = calculate_resources()  
    executor = ThreadPoolExecutor(max_workers=cpu_threads)

def on_crack():
    global is_cracking, current_hash_index, hashes_to_crack

    if not tree.get_children():
        messagebox.showwarning("Warning", "No hashes loaded to crack.")
        return

    stop_button.config(state=tk.NORMAL)
    resume_button.config(state=tk.DISABLED)
    load_button.config(state=tk.DISABLED)
    crack_button.config(state=tk.DISABLED)
    reset_button.config(state=tk.DISABLED)

    hashes_to_crack = [(tree.item(item)["values"][1], tree.item(item)["values"][2], item) for item in tree.get_children()]
    is_cracking = True

    crack_hashes_concurrently(hashes_to_crack, HARD_CODED_PASSLIST_FILE)

is_cracking = False   

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        if self.tooltip_window is not None:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True) 
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(self.tooltip_window, text=self.text, background=root.cget("background"), foreground="black", relief="solid", borderwidth=1)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

def guess_hash_type(hash_value):
    if len(hash_value) == 32:
        return 'MD5'
    elif len(hash_value) == 40:
        return 'SHA1' 
    elif len(hash_value) == 64:
        return 'SHA256'  
    elif len(hash_value) == 128:
        return 'SHA512' 
    elif len(hash_value) == 56:
        return 'SHA224'  
    elif len(hash_value) == 96:
        return 'SHA384'
    elif len(hash_value) == 60 and hash_value.startswith(("$2a$", "$2b$", "$2y$", "$2x$", "$2c$", "$2$")):
        return 'Bcrypt'
    elif len (hash_value) == 8:
        return 'CRC32'
    elif len (hash_value) == 2 and all (c in '0123456789abcdefABCDEF' for c in hash_value):
        return 'CRC8' 
    elif len (hash_value) == 4:
        return 'CRC16' 
    elif len (hash_value) == 16:
        return 'CRC64'
    elif len (hash_value) == 0:
        return 'Empty'
    else:
        return 'Unknown'

def hash_password(password, hash_type):
    hash_type = hash_type.lower()
    if hash_type == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_type == 'sha224':
        return hashlib.sha224(password.encode()).hexdigest()
    elif hash_type == 'sha384':
        return hashlib.sha384(password.encode()).hexdigest()
    else:
        return 'Unknown'
    
def load_hashes():
    file_path = filedialog.askopenfilename(title="Select Hash File", filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return

    try:
        for row in tree.get_children():
            tree.delete(row) 

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip() 
                if ':' in line:  
                    parts = line.split(':')  
                    username, hash_value = parts[0], parts[1]
                else:
                    username, hash_value = "Unknown", line  

                hash_type = guess_hash_type(hash_value)

                if hash_type != 'Unknown':
                    tree.insert("", "end", values=(username, hash_value, hash_type, ""))
                else:
                    tree.insert("", "end", values=(username, hash_value, hash_type, ""))

    except Exception as e:
        messagebox.showerror("Error", f"Failed to load hashes: {e}")

title_added = False

TITLE = r"""
 _   _           _     _   ___ _ _           
| | | |         | |   | | / (_) | |          
| |_| | __ _ ___| |__ | |/ / _| | | ___ _ __ 
|  _  |/ _` / __| '_ \|    \| | | |/ _ \ '__|
| | | | (_| \__ \ | | | |\  \ | | |  __/ |   
\_| |_/\__,_|___/_| |_\_| \_/_|_|_|\___|_|

"""

passwords_tried_line = 9  
output_window = None
output_text_content = ""
title_added = False

def show_output_window():
    global output_window  
    global output_text_widget 
    global title_added 

    if output_window is not None and output_window.winfo_exists():
        output_window.lift()  
        return  

    output_window = tk.Toplevel(root)
    output_window.title("Billboard")
    output_window.geometry("650x350")

    frame = tk.Frame(output_window)
    frame.pack(expand=True, fill=tk.BOTH)

    output_text_widget = tk.Text(frame, wrap=tk.WORD, state=tk.NORMAL)  
    output_text_widget.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    scrollbar = tk.Scrollbar(frame, command=output_text_widget.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    output_text_widget.config(yscrollcommand=scrollbar.set)  

    if not title_added: 
        output_text_widget.insert(tk.END, TITLE + "\n")  
        title_added = True  

    output_text_widget.insert(tk.END, output_text_content) 
    output_text_widget.config(state=tk.DISABLED)  

    output_window.protocol("WM_DELETE_WINDOW", on_output_window_close)

def on_output_window_close():
    global output_window
    global output_text_content 

    output_text_content = output_text_widget.get("1.0", tk.END) 
    output_window.withdraw()  
    output_window = None  

def refresh_output():
    global output_text_widget, output_text_content, found_passwords, password_count, global_password_count

    if output_window is not None and output_window.winfo_exists():
        output_text_widget.config(state=tk.NORMAL)  
         
        output_text_widget.delete("1.0", tk.END)  
        
        output_text_widget.insert(tk.END, TITLE + "\n")  

        found_passwords = [] 
        
        password_count = 0  
        global_password_count = 0 
        
        output_text_content = TITLE + "\n"  
        
        output_text_widget.config(state=tk.DISABLED)


def reset_all():
    global password_count, global_password_count
    refresh_output()
    password_count = 0
    global_password_count = 0
    on_restart()
    
def start_new_session():
    global found_passwords, session_active, output_text_content
    found_passwords = []  
    session_active = True 
    output_text_content = ""  
    refresh_output()  

def update_output(password_count_text, found_password_text):
    global output_text_widget 
    global output_text_content 
    global session_active  
    global password_count  
    global global_password_count  

    if 'output_text_widget' in globals() and output_text_widget:  
        output_text_widget.config(state=tk.NORMAL) 
        
        if 'found_passwords' not in globals():
            global found_passwords
            found_passwords = [] 

        if found_password_text:
            found_passwords.append(found_password_text) 

        output_text_widget.delete("1.0", tk.END)  

        output_text_widget.insert(tk.END, TITLE + "\n")  
        output_text_content = TITLE + "\n"  

        global_password_count += 1 
        output_text_widget.insert(tk.END, f"Total passwords tried: {global_password_count}\n")
        output_text_content += f"Total passwords tried: {global_password_count}\n"  

        if found_passwords: 
            output_text_widget.insert(tk.END, "\n".join(found_passwords) + "\n")
            output_text_content += "\n".join(found_passwords) + "\n" 

        output_text_widget.config(state=tk.DISABLED)

stop_event = threading.Event()
pause_event = threading.Event()
current_hash_index = 0  
is_cracking = False
paused = False
global_password_count = 0
hashes_to_crack = []

HARD_CODED_PASSLIST_FILE = "wordlist.txt"

def hash_crc8(data):
    crc = 0x00
    for byte in data.encode('utf-8'):
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x31
            else:
                crc <<= 1
            crc &= 0xFF
    return format(crc, '02x')

def hash_crc16(password):
    crc = 0xFFFF
    for byte in password.encode('utf-8'):
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return format(crc, '04x')

def hash_crc64(password):
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in password.encode('utf-8'):
        crc ^= byte
        for _ in range(8):
            if crc & 0x0000000000000001:
                crc = (crc >> 1) ^ 0x42F0E1EBA9EA3693
            else:
                crc >>= 1
    return format(crc, '016x')

def hash_crc32(password):
    return format(zlib.crc32(password.encode('utf-8')) & 0xffffffff, '08x')

def crack_hash(hash_value, passlist_file, hash_type, item):
    global current_hash_index, global_password_count
    cracked = False
    found_password_text = ""

    username = tree.item(item)["values"][0]

    try:
        with open(passlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for password in f: 
                if stop_event.is_set():
                    update_output("Cracking paused by the user.", found_password_text)
                    return 

                while pause_event.is_set():
                    threading.Event().wait(0.1) 

                password = password.strip() 
                if not password:
                    continue

                global_password_count += 1

                if global_password_count % 10000 == 0:
                    update_output(f"Total passwords tried: {global_password_count}", found_password_text)

                if hash_type == 'Bcrypt':
                    if bcrypt.checkpw(password.encode('utf-8'), hash_value.encode('utf-8')):
                        found_password_text = f"Password cracked: {password} "
                        tree.item(item, values=(username, hash_value, hash_type, password))
                        cracked = True
                        update_output(f"Total passwords tried: {global_password_count}", found_password_text)
                        break
                    
                elif hash_type == 'CRC32':
                    computed_hash = hash_crc32(password)
                    if computed_hash == hash_value.lower():
                        found_password_text = f"Password cracked: {password} "
                        tree.item(item, values=(username, hash_value, hash_type, password))
                        cracked = True
                        update_output(f"Total passwords tried: {global_password_count}", found_password_text)
                        break
                elif hash_type == 'CRC8':
                    computed_hash = hash_crc8(password)
                    if computed_hash == hash_value.lower():
                        found_password_text = f"Password cracked: {password} "
                        tree.item(item, values=(username, hash_value, hash_type, password))
                        cracked = True
                        update_output(f"Total passwords tried: {global_password_count}", found_password_text)
                        break
                elif hash_type == 'CRC16':
                    computed_hash = hash_crc16(password)
                    if computed_hash == hash_value.lower():
                        found_password_text = f"Password cracked: {password} "
                        tree.item(item, values=(username, hash_value, hash_type, password))
                        cracked = True
                        update_output(f"Total passwords tried: {global_password_count}", found_password_text)
                        break
                elif hash_type == 'CRC64':
                    computed_hash = hash_crc64(password)
                    if computed_hash == hash_value.lower():
                        found_password_text = f"Password cracked: {password} "
                        tree.item(item, values=(username, hash_value, hash_type, password))
                        cracked = True
                        update_output(f"Total passwords tried: {global_password_count}", found_password_text)
                        break

                else:
                    hashed_password = hash_password(password, hash_type)

                    if hashed_password and hashed_password.lower() == hash_value.lower():
                        found_password_text = f"Password cracked: {password} "
                        tree.item(item, values=(username, hash_value, hash_type, password))
                        cracked = True
                        update_output(f"Total passwords tried: {global_password_count}", found_password_text)
                        break  

    except Exception as e:
        update_output(f"Error during cracking: {e}", found_password_text)

    if not cracked:
        found_password_text = "Hash couldn't be cracked"
        update_output(f"Total passwords tried: {global_password_count}", found_password_text)
        tree.item(item, values=(username, hash_value, hash_type, "Hash couldn't be cracked"))

    on_crack_complete()

def on_crack():
    global is_cracking, current_hash_index, hashes_to_crack

    if not tree.get_children():
        messagebox.showwarning("Warning", "No hashes loaded to crack.")
        return

    stop_button.config(state=tk.NORMAL)
    resume_button.config(state=tk.DISABLED)
    load_button.config(state=tk.DISABLED)
    crack_button.config(state=tk.DISABLED)
    reset_button.config(state=tk.DISABLED)

    hashes_to_crack = [(tree.item(item)["values"][1], tree.item(item)["values"][2], item) for item in tree.get_children()]
    is_cracking = True
    current_hash_index = 0  

    initialize_executor()

    crack_next_hash()

def crack_next_hash():
    global current_hash_index, hashes_to_crack, is_cracking

    if current_hash_index < len(hashes_to_crack) and is_cracking:
        hash_value, hash_type, item = hashes_to_crack[current_hash_index]
        passlist_file = HARD_CODED_PASSLIST_FILE

        executor.submit(crack_hash, hash_value, passlist_file, hash_type, item)
    else:
        is_cracking = False
        stop_button.config(state=tk.DISABLED)
        resume_button.config(state=tk.DISABLED)
        load_button.config(state=tk.DISABLED)
        crack_button.config(state=tk.DISABLED)
        reset_button.config(state=tk.NORMAL)

def on_crack_complete():
    global current_hash_index
    current_hash_index += 1  
    crack_next_hash() 

def on_stop():
    global is_cracking, paused
    stop_event.set()  
    paused = False
    is_cracking = False 
    resume_button.config(state=tk.NORMAL)  
    stop_button.config(state=tk.DISABLED)  
    reset_button.config(state=tk.NORMAL)  

def on_resume():
    global is_cracking, paused
    if not is_cracking:  
        stop_event.clear()
        paused = False 
        is_cracking = True
        
        stop_button.config(state=tk.NORMAL)
        resume_button.config(state=tk.DISABLED)
        reset_button.config(state=tk.DISABLED)

        crack_next_hash()

def on_restart():
    global is_cracking, current_hash_index, hashes_to_crack, stop_event

    stop_event.set()
    is_cracking = False
    current_hash_index = 0
    hashes_to_crack.clear()

    for row in tree.get_children():
        tree.delete(row)

    load_button.config(state=tk.NORMAL)
    crack_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    resume_button.config(state=tk.DISABLED)
    reset_button.config(state=tk.NORMAL)

    stop_event.clear()

    refresh_output()

def on_pause():
    global paused
    if is_cracking and not paused:
        pause_event.set()
        paused = True
        stop_button.config(state=tk.DISABLED)
        resume_button.config(state=tk.NORMAL)

def on_closing():
    if is_cracking:
        if messagebox.askyesno("Warning", "Cracking is in progress. Do you really want to close the application?"):
            stop_event.set()
            root.destroy()
    else:
        root.destroy()

def copy_selection(event):
    selected_item = tree.selection()
    if selected_item:
        item_text = tree.item(selected_item, 'values')
        text_to_copy = "\t".join(item_text)
        root.clipboard_clear()
        root.clipboard_append(text_to_copy)  
        root.update()

root = tk.Tk()
root.title("HashKiller")
root.geometry("1000x550")

root.iconbitmap("Icons/HashKiller_Icon.ico")

root.protocol("WM_DELETE_WINDOW", on_closing)

button_frame = tk.Frame(root)
button_frame.pack(pady=10, anchor='w')  

button_width = 80  
button_height = 80 

load_image = tk.PhotoImage(file="Images/log_image.png") 
crack_image = tk.PhotoImage(file="Images/Crack_image.png") 
stop_image = tk.PhotoImage(file="Images/Pause.png") 
resume_image = tk.PhotoImage(file="Images/resume.png") 
reset_image = tk.PhotoImage(file="Images/reset.png")
output_image = tk.PhotoImage(file="Images/inspect.png")

load_button = tk.Button(button_frame, image=load_image, width=button_width, height=button_height, command=load_hashes,
                        bg=button_frame.cget("bg"), activebackground=button_frame.cget("bg"),
                        borderwidth=0, relief='flat', highlightthickness=0)
load_button.pack(side=tk.LEFT, padx=10, pady=5) 
ToolTip(load_button, "Load the file with the hashes")

crack_button = tk.Button(button_frame, image=crack_image, width=button_width, height=button_height, command=on_crack,
                        bg=button_frame.cget("bg"), activebackground=button_frame.cget("bg"),
                        borderwidth=0, relief='flat', highlightthickness=0)
crack_button.pack(side=tk.LEFT, padx=10, pady=5)  
ToolTip(crack_button, "Start Cracking")

stop_button = tk.Button(button_frame, image=stop_image, width=button_width, height=button_height, command=on_stop, state=tk.DISABLED,
                        bg=button_frame.cget("bg"), activebackground=button_frame.cget("bg"),
                        borderwidth=0, relief='flat', highlightthickness=0)
stop_button.pack(side=tk.LEFT, padx=10, pady=5) 
ToolTip(stop_button, "Pause the Cracking Process")

resume_button = tk.Button(button_frame, image=resume_image, width=button_width, height=button_height, command=on_resume, state=tk.DISABLED,
                        bg=button_frame.cget("bg"), activebackground=button_frame.cget("bg"),
                        borderwidth=0, relief='flat', highlightthickness=0)
resume_button.pack(side=tk.LEFT, padx=10, pady=5)
ToolTip(resume_button, "Resume the Cracking Process")

reset_button = tk.Button(button_frame, image=reset_image, width=button_width, height=button_height, command=reset_all,
                        bg=button_frame.cget("bg"), activebackground=button_frame.cget("bg"),
                        borderwidth=0, relief='flat', highlightthickness=0)
reset_button.pack(side=tk.LEFT, padx=10, pady=5) 
ToolTip(reset_button, "Clean the console")

output_button = tk.Button(button_frame, image=output_image, width=button_width, height=button_height, command=show_output_window,
                        bg=button_frame.cget("bg"), activebackground=button_frame.cget("bg"),
                        borderwidth=0, relief='flat', highlightthickness=0)
output_button.pack(side=tk.LEFT, padx=10, pady=5)
ToolTip(output_button, "See the billboard outputs")

columns = ("Username", "Hash", "Hash Type", "Cracked Password")
tree = ttk.Treeview(root, columns=columns, show='headings', height=15)

for col in columns:
    tree.heading(col, text=col, anchor='center')
    tree.column(col, anchor='center', width=200) 

scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side='right', fill='y')

tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

tree.bind("<Control-c>", copy_selection)

stop_button.config(state=tk.DISABLED)
resume_button.config(state=tk.DISABLED)

root.mainloop()
