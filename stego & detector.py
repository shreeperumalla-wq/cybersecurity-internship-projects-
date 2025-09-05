from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image
import os

# --- Encode Function ---
def encode_message(image_path, message):
    try:
        image = Image.open(image_path)
        if image.mode != 'RGB':
            image = image.convert('RGB')

        input_ext = os.path.splitext(image_path)[1].lower()
        if input_ext in [".jpg", ".jpeg"]:
            messagebox.showwarning("Warning", "JPEG is lossy. Encoding may not survive compression.")

        encoded = image.copy()
        w, h = encoded.size
        pixels = encoded.load()
        message += "###"
        bin_msg = ''.join(format(ord(c), '08b') for c in message)

        if len(bin_msg) > w * h:
            raise ValueError("Message too large to fit in image.")

        idx = 0
        for y in range(h):
            for x in range(w):
                if idx >= len(bin_msg): break
                r, g, b = pixels[x, y]
                b = (b & ~1) | int(bin_msg[idx])
                pixels[x, y] = (r, g, b)
                idx += 1
            if idx >= len(bin_msg): break

        # Save in the same format by default
        def_ext = input_ext if input_ext in [".jpg", ".jpeg", ".png"] else ".png"
        save_path = filedialog.asksaveasfilename(defaultextension=def_ext,
                                                 filetypes=[("PNG Image", "*.png"), ("JPEG Image", "*.jpg *.jpeg")])

        if save_path:
            ext = os.path.splitext(save_path)[1].lower()
            fmt = "PNG" if ext == ".png" else "JPEG"
            encoded.save(save_path, fmt)
            messagebox.showinfo("Success", f"Message encoded and saved as {fmt}:\n{save_path}")
            message_entry.delete("1.0", END)  # Clear message box
        else:
            messagebox.showwarning("Cancelled", "No file saved.")
    except Exception as e:
        messagebox.showerror("Error", f"Encoding failed:\n{e}")

# --- Decode Function ---
def decode_message(img_path):
    try:
        img = Image.open(img_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        bin_str = ""
        pixels = img.load()
        w, h = img.size
        done = False

        for y in range(h):
            for x in range(w):
                _, _, b = pixels[x, y]
                bin_str += str(b & 1)
                if len(bin_str) % 8 == 0 and len(bin_str) >= 24:
                    last_chars = ''.join([chr(int(bin_str[i:i+8], 2)) for i in range(len(bin_str)-24, len(bin_str), 8)])
                    if last_chars == "###":
                        done = True
                        break
            if done: break

        chars = []
        for i in range(0, len(bin_str), 8):
            byte = bin_str[i:i+8]
            if len(byte) < 8: break
            ch = chr(int(byte, 2))
            if ''.join(chars[-2:] + [ch]) == "###":
                break
            chars.append(ch)

        msg = "".join(chars)
        if msg:
            decoded_text.delete("1.0", END)
            decoded_text.insert(END, msg)
        else:
            messagebox.showinfo("Result", "No hidden message found.")
    except Exception as e:
        messagebox.showerror("Error", f"Decoding failed:\n{e}")

# --- Detect Function ---
def detect_stego(img_path):
    try:
        img = Image.open(img_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        bin_str = ""
        pixels = img.load()
        w, h = img.size
        chars = []
        for y in range(h):
            for x in range(w):
                _, _, b = pixels[x, y]
                bin_str += str(b & 1)
                if len(bin_str) >= 24:
                    last_3 = ''.join([chr(int(bin_str[i:i+8], 2)) for i in range(len(bin_str)-24, len(bin_str), 8)])
                    if last_3 == "###":
                        messagebox.showinfo("Detect", "🔍 Hidden message detected!")
                        return
        messagebox.showinfo("Detect", "❌ No hidden message found.")
    except Exception as e:
        messagebox.showerror("Error", f"Detection failed:\n{e}")

def browse(entry):
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg")])
    entry.delete(0, END)
    entry.insert(0, path)

# --- GUI Setup ---
app = Tk()
app.title("Steganography & Detection Tool")
app.geometry("500x720")
app.config(bg="#F0F8FF")

Label(app, text="Image File:", bg="#F0F8FF", font=("Arial", 12)).pack(pady=5)
img_in = Entry(app, width=50, font=("Arial", 11)); img_in.pack()
Button(app, text="Browse", command=lambda: browse(img_in), bg="#4682B4", fg="white", font=("Arial", 10)).pack(pady=5)

Label(app, text="Message to Hide:", bg="#F0F8FF", font=("Arial", 12)).pack(pady=5)
message_entry = Text(app, height=5, width=50, font=("Arial", 11)); message_entry.pack(pady=5)
Button(app, text="Encode and Save", command=lambda: encode_message(img_in.get(), message_entry.get("1.0", END).strip()),
       bg="green", fg="white", font=("Arial", 12)).pack(pady=10)

Label(app, text="Decode or Detect Message:", bg="#F0F8FF", font=("Arial", 12)).pack(pady=5)
img_dec = Entry(app, width=50, font=("Arial", 11)); img_dec.pack()
Button(app, text="Browse", command=lambda: browse(img_dec), bg="#4682B4", fg="white", font=("Arial", 10)).pack(pady=5)
Button(app, text="Decode Message", command=lambda: decode_message(img_dec.get()),
       bg="orange", fg="black", font=("Arial", 12)).pack(pady=5)
Button(app, text="Detect Steganography", command=lambda: detect_stego(img_dec.get()),
       bg="#8B0000", fg="white", font=("Arial", 12)).pack(pady=10)

Label(app, text="Decoded Message:", bg="#F0F8FF", font=("Arial", 12)).pack()
decoded_text = Text(app, height=5, width=50, font=("Arial", 11)); decoded_text.pack(pady=5)

app.mainloop()
