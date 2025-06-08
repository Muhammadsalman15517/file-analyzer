# gui_app.py

import tkinter as tk
from tkinter import filedialog, messagebox
from file_scan import scan_file

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def start_scan():
    file_path = file_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file")
        return

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "Scanning...\n")
    root.update()

    try:
        sha256, result = scan_file(file_path)
        output = f"SHA256: {sha256}\n\nScan Result:\n"
        for k, v in result.items():
            output += f"{k.capitalize()}: {v}\n"
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, output)
    except Exception as e:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Error: {str(e)}")

# GUI Layout
root = tk.Tk()
root.title("File Scanner - VirusTotal")
root.geometry("600x400")
root.configure(bg="#f4f4f4")

tk.Label(root, text="Select File to Scan:", bg="#f4f4f4").pack(pady=10)
file_entry = tk.Entry(root, width=50)
file_entry.pack(pady=5)
tk.Button(root, text="Browse", command=browse_file).pack()

tk.Button(root, text="Start Scan", command=start_scan, bg="#007acc", fg="white").pack(pady=10)

output_text = tk.Text(root, height=15, width=70)
output_text.pack(pady=10)

root.mainloop()
