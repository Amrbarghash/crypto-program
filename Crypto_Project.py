import tkinter as tk
from tkinter import ttk, messagebox
import random
import re
import numpy as np

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Project ")
        self.root.geometry("1000x800")
        
        # Create notebook for different ciphers
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create frames for each cipher
        self.create_caesar_frame()
        self.create_vigenere_frame()
        self.create_playfair_frame()
        self.create_monoalphabetic_frame()
        self.create_railfence_frame()
        self.create_rowtransposition_frame()
        self.create_multilayer_frame()
        
    def create_caesar_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Caesar Cipher")
        
        # Input
        ttk.Label(frame, text="Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.caesar_plaintext = tk.Text(frame, height=5, width=50)
        self.caesar_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Key
        ttk.Label(frame, text="Shift Key (1-25):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.caesar_key = ttk.Spinbox(frame, from_=1, to=25, width=5)
        self.caesar_key.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.caesar_key.set(3)
        
        # Buttons
        ttk.Button(frame, text="Encrypt", command=self.caesar_encrypt).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(frame, text="Decrypt", command=self.caesar_decrypt).grid(row=3, column=1, padx=5, pady=5)
        
        # Output
        ttk.Label(frame, text="Ciphertext:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.caesar_ciphertext = tk.Text(frame, height=5, width=50)
        self.caesar_ciphertext.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        
    def create_vigenere_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Vigenère Cipher")
        
        # Input
        ttk.Label(frame, text="Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.vigenere_plaintext = tk.Text(frame, height=5, width=50)
        self.vigenere_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Key
        ttk.Label(frame, text="Keyword:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.vigenere_key = ttk.Entry(frame, width=20)
        self.vigenere_key.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.vigenere_key.insert(0, "KEY")
        
        # Buttons
        ttk.Button(frame, text="Encrypt", command=self.vigenere_encrypt).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(frame, text="Decrypt", command=self.vigenere_decrypt).grid(row=3, column=1, padx=5, pady=5)
        
        # Output
        ttk.Label(frame, text="Ciphertext:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.vigenere_ciphertext = tk.Text(frame, height=5, width=50)
        self.vigenere_ciphertext.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        
    def create_playfair_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Playfair Cipher")
        
        # Input
        ttk.Label(frame, text="Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.playfair_plaintext = tk.Text(frame, height=5, width=50)
        self.playfair_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Key
        ttk.Label(frame, text="Keyword:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.playfair_key = ttk.Entry(frame, width=20)
        self.playfair_key.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.playfair_key.insert(0, "PLAYFAIR")
        
        # Buttons
        ttk.Button(frame, text="Encrypt", command=self.playfair_encrypt).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(frame, text="Decrypt", command=self.playfair_decrypt).grid(row=3, column=1, padx=5, pady=5)
        
        # Output
        ttk.Label(frame, text="Ciphertext:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.playfair_ciphertext = tk.Text(frame, height=5, width=50)
        self.playfair_ciphertext.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        
    def create_monoalphabetic_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Monoalphabetic Cipher")
        
        # Input
        ttk.Label(frame, text="Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.mono_plaintext = tk.Text(frame, height=5, width=50)
        self.mono_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Key
        ttk.Label(frame, text="Substitution Key:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.mono_key = ttk.Entry(frame, width=50)
        self.mono_key.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
        # Generate random key button
        ttk.Button(frame, text="Generate Random Key", command=self.generate_mono_key).grid(row=4, column=0, padx=5, pady=5)
        
        # Buttons
        ttk.Button(frame, text="Encrypt", command=self.mono_encrypt).grid(row=5, column=0, padx=5, pady=5)
        ttk.Button(frame, text="Decrypt", command=self.mono_decrypt).grid(row=5, column=1, padx=5, pady=5)
        
        # Output
        ttk.Label(frame, text="Ciphertext:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
        self.mono_ciphertext = tk.Text(frame, height=5, width=50)
        self.mono_ciphertext.grid(row=7, column=0, columnspan=2, padx=5, pady=5)
        
    def create_railfence_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Rail Fence Cipher")
        
        # Input
        ttk.Label(frame, text="Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.railfence_plaintext = tk.Text(frame, height=5, width=50)
        self.railfence_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Key
        ttk.Label(frame, text="Number of Rails (2-10):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.railfence_key = ttk.Spinbox(frame, from_=2, to=10, width=5)
        self.railfence_key.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.railfence_key.set(3)
        
        # Buttons
        ttk.Button(frame, text="Encrypt", command=self.railfence_encrypt).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(frame, text="Decrypt", command=self.railfence_decrypt).grid(row=3, column=1, padx=5, pady=5)
        
        # Output
        ttk.Label(frame, text="Ciphertext:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.railfence_ciphertext = tk.Text(frame, height=5, width=50)
        self.railfence_ciphertext.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        
    def create_rowtransposition_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Row Transposition Cipher")
        
        # Input
        ttk.Label(frame, text="Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.rowtrans_plaintext = tk.Text(frame, height=5, width=50)
        self.rowtrans_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Key
        ttk.Label(frame, text="Key (e.g., 3 1 4 2):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.rowtrans_key = ttk.Entry(frame, width=20)
        self.rowtrans_key.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.rowtrans_key.insert(0, "3 1 4 2")
        
        # Buttons
        ttk.Button(frame, text="Encrypt", command=self.rowtrans_encrypt).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(frame, text="Decrypt", command=self.rowtrans_decrypt).grid(row=3, column=1, padx=5, pady=5)
        
        # Output
        ttk.Label(frame, text="Ciphertext:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.rowtrans_ciphertext = tk.Text(frame, height=5, width=50)
        self.rowtrans_ciphertext.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
    
    def create_multilayer_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Multi-Layer Encryption")
        
        # Input
        ttk.Label(frame, text="Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.multi_plaintext = tk.Text(frame, height=5, width=70)
        self.multi_plaintext.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        # Encryption sequence selection
        ttk.Label(frame, text="Encryption Sequence:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.sequence_vars = []
        self.sequence_combos = []
        
        # Create 3 layers of encryption selection
        for i in range(3):
            var = tk.StringVar()
            self.sequence_vars.append(var)
            combo = ttk.Combobox(frame, textvariable=var, width=15)
            combo['values'] = ('None', 'Caesar', 'Vigenère', 'Playfair', 'Monoalphabetic', 'Rail Fence', 'Row Transposition')
            combo.set('None')
            combo.grid(row=3+i, column=0, padx=5, pady=5)
            self.sequence_combos.append(combo)
            
            # Key input for each layer
            ttk.Label(frame, text=f"Layer {i+1} Key:").grid(row=3+i, column=1, padx=5, pady=5, sticky=tk.W)
            key_entry = ttk.Entry(frame, width=20)
            key_entry.grid(row=3+i, column=2, padx=5, pady=5, sticky=tk.W)
            setattr(self, f"multi_key_{i}", key_entry)
        
        # Buttons
        ttk.Button(frame, text="Encrypt", command=self.multi_encrypt).grid(row=6, column=0, padx=5, pady=10)
        ttk.Button(frame, text="Decrypt", command=self.multi_decrypt).grid(row=6, column=1, padx=5, pady=10)
        
        # Output
        ttk.Label(frame, text="Ciphertext:").grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)
        self.multi_ciphertext = tk.Text(frame, height=5, width=70)
        self.multi_ciphertext.grid(row=8, column=0, columnspan=3, padx=5, pady=5)
        
        # Process steps
        ttk.Label(frame, text="Encryption Steps:").grid(row=9, column=0, padx=5, pady=5, sticky=tk.W)
        self.multi_steps = tk.Text(frame, height=10, width=70, state=tk.DISABLED)
        self.multi_steps.grid(row=10, column=0, columnspan=3, padx=5, pady=5)
    
    # Caesar Cipher Methods
    def caesar_encrypt(self):
        plaintext = self.caesar_plaintext.get("1.0", tk.END).upper().strip()
        try:
            key = int(self.caesar_key.get())
        except ValueError:
            messagebox.showerror("Error", "Key must be an integer between 1 and 25")
            return
        
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                shifted = ord(char) + key
                if shifted > ord('Z'):
                    shifted -= 26
                ciphertext += chr(shifted)
            else:
                ciphertext += char
        
        self.caesar_ciphertext.delete("1.0", tk.END)
        self.caesar_ciphertext.insert("1.0", ciphertext)
    
    def caesar_decrypt(self):
        ciphertext = self.caesar_ciphertext.get("1.0", tk.END).upper().strip()
        try:
            key = int(self.caesar_key.get())
        except ValueError:
            messagebox.showerror("Error", "Key must be an integer between 1 and 25")
            return
        
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                shifted = ord(char) - key
                if shifted < ord('A'):
                    shifted += 26
                plaintext += chr(shifted)
            else:
                plaintext += char
        
        self.caesar_plaintext.delete("1.0", tk.END)
        self.caesar_plaintext.insert("1.0", plaintext)
    
    # Vigenère Cipher Methods
    def vigenere_encrypt(self):
        plaintext = self.vigenere_plaintext.get("1.0", tk.END).upper().strip()
        key = self.vigenere_key.get().upper().strip()
        
        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters")
            return
        
        ciphertext = ""
        key_index = 0
        for char in plaintext:
            if char.isalpha():
                # Calculate shift for this character
                shift = ord(key[key_index % len(key)]) - ord('A')
                
                # Apply shift
                shifted = ord(char) + shift
                if shifted > ord('Z'):
                    shifted -= 26
                ciphertext += chr(shifted)
                
                # Move to next key character
                key_index += 1
            else:
                ciphertext += char
        
        self.vigenere_ciphertext.delete("1.0", tk.END)
        self.vigenere_ciphertext.insert("1.0", ciphertext)
    
    def vigenere_decrypt(self):
        ciphertext = self.vigenere_ciphertext.get("1.0", tk.END).upper().strip()
        key = self.vigenere_key.get().upper().strip()
        
        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters")
            return
        
        plaintext = ""
        key_index = 0
        for char in ciphertext:
            if char.isalpha():
                # Calculate shift for this character
                shift = ord(key[key_index % len(key)]) - ord('A')
                
                # Apply shift (in reverse)
                shifted = ord(char) - shift
                if shifted < ord('A'):
                    shifted += 26
                plaintext += chr(shifted)
                
                # Move to next key character
                key_index += 1
            else:
                plaintext += char
        
        self.vigenere_plaintext.delete("1.0", tk.END)
        self.vigenere_plaintext.insert("1.0", plaintext)
    
    # Playfair Cipher Methods
    def create_playfair_matrix(self, key):
        # Remove duplicate letters from key
        key = key.upper().replace("J", "I")
        key_chars = []
        for char in key:
            if char not in key_chars and char.isalpha():
                key_chars.append(char)
        
        # Add remaining letters of the alphabet
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        for char in alphabet:
            if char not in key_chars:
                key_chars.append(char)
        
        # Create 5x5 matrix
        matrix = [key_chars[i*5:(i+1)*5] for i in range(5)]
        return matrix
    
    def playfair_prepare_text(self, text):
        # Remove non-alphabetic characters and convert to uppercase
        text = re.sub(r'[^A-Za-z]', '', text.upper())
        text = text.replace("J", "I")
        
        # Split into digraphs, adding X if necessary
        digraphs = []
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                # Last character left, add X
                digraphs.append(text[i] + "X")
                i += 1
            elif text[i] == text[i+1]:
                # Double letter, insert X
                digraphs.append(text[i] + "X")
                i += 1
            else:
                digraphs.append(text[i] + text[i+1])
                i += 2
        return digraphs
    
    def playfair_find_position(self, matrix, char):
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == char:
                    return (row, col)
        return (None, None)
    
    def playfair_encrypt_digraph(self, matrix, digraph):
        a, b = digraph[0], digraph[1]
        row_a, col_a = self.playfair_find_position(matrix, a)
        row_b, col_b = self.playfair_find_position(matrix, b)
        
        # Same row
        if row_a == row_b:
            return matrix[row_a][(col_a + 1) % 5] + matrix[row_b][(col_b + 1) % 5]
        # Same column
        elif col_a == col_b:
            return matrix[(row_a + 1) % 5][col_a] + matrix[(row_b + 1) % 5][col_b]
        # Rectangle
        else:
            return matrix[row_a][col_b] + matrix[row_b][col_a]
    
    def playfair_decrypt_digraph(self, matrix, digraph):
        a, b = digraph[0], digraph[1]
        row_a, col_a = self.playfair_find_position(matrix, a)
        row_b, col_b = self.playfair_find_position(matrix, b)
        
        # Same row
        if row_a == row_b:
            return matrix[row_a][(col_a - 1) % 5] + matrix[row_b][(col_b - 1) % 5]
        # Same column
        elif col_a == col_b:
            return matrix[(row_a - 1) % 5][col_a] + matrix[(row_b - 1) % 5][col_b]
        # Rectangle
        else:
            return matrix[row_a][col_b] + matrix[row_b][col_a]
    
    def playfair_encrypt(self):
        plaintext = self.playfair_plaintext.get("1.0", tk.END).strip()
        key = self.playfair_key.get().strip()
        
        if not key:
            messagebox.showerror("Error", "Please enter a key")
            return
        
        matrix = self.create_playfair_matrix(key)
        digraphs = self.playfair_prepare_text(plaintext)
        
        ciphertext = ""
        for digraph in digraphs:
            ciphertext += self.playfair_encrypt_digraph(matrix, digraph) + " "
        
        self.playfair_ciphertext.delete("1.0", tk.END)
        self.playfair_ciphertext.insert("1.0", ciphertext.strip())
    
    def playfair_decrypt(self):
        ciphertext = self.playfair_ciphertext.get("1.0", tk.END).strip()
        key = self.playfair_key.get().strip()
        
        if not key:
            messagebox.showerror("Error", "Please enter a key")
            return
        
        matrix = self.create_playfair_matrix(key)
        digraphs = self.playfair_prepare_text(ciphertext)
        
        plaintext = ""
        for digraph in digraphs:
            plaintext += self.playfair_decrypt_digraph(matrix, digraph)
        
        # Remove any trailing X that was added during encryption
        if plaintext.endswith("X"):
            plaintext = plaintext[:-1]
        
        self.playfair_plaintext.delete("1.0", tk.END)
        self.playfair_plaintext.insert("1.0", plaintext)
    
    # Monoalphabetic Cipher Methods
    def generate_mono_key(self):
        alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        random.shuffle(alphabet)
        self.mono_key.delete(0, tk.END)
        self.mono_key.insert(0, "".join(alphabet))
    
    def mono_encrypt(self):
        plaintext = self.mono_plaintext.get("1.0", tk.END).upper().strip()
        key = self.mono_key.get().upper().strip()
        
        if len(key) != 26 or not key.isalpha():
            messagebox.showerror("Error", "Key must be 26 unique letters")
            return
        
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                index = ord(char) - ord('A')
                ciphertext += key[index]
            else:
                ciphertext += char
        
        self.mono_ciphertext.delete("1.0", tk.END)
        self.mono_ciphertext.insert("1.0", ciphertext)
    
    def mono_decrypt(self):
        ciphertext = self.mono_ciphertext.get("1.0", tk.END).upper().strip()
        key = self.mono_key.get().upper().strip()
        
        if len(key) != 26 or not key.isalpha():
            messagebox.showerror("Error", "Key must be 26 unique letters")
            return
        
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                index = key.index(char)
                plaintext += chr(ord('A') + index)
            else:
                plaintext += char
        
        self.mono_plaintext.delete("1.0", tk.END)
        self.mono_plaintext.insert("1.0", plaintext)
    
    # Rail Fence Cipher Methods
    def railfence_encrypt(self):
        plaintext = self.railfence_plaintext.get("1.0", tk.END).strip()
        try:
            rails = int(self.railfence_key.get())
        except ValueError:
            messagebox.showerror("Error", "Number of rails must be an integer")
            return
        
        if rails < 2 or rails > 10:
            messagebox.showerror("Error", "Number of rails must be between 2 and 10")
            return
        
        # Create the rail pattern
        pattern = []
        down = True
        current_rail = 0
        
        for i in range(len(plaintext)):
            pattern.append((current_rail, i))
            if down:
                if current_rail == rails - 1:
                    down = False
                    current_rail -= 1
                else:
                    current_rail += 1
            else:
                if current_rail == 0:
                    down = True
                    current_rail += 1
                else:
                    current_rail -= 1
        
        # Sort by rail number and then by original position
        pattern.sort()
        
        # Build ciphertext
        ciphertext = ""
        for pos in pattern:
            ciphertext += plaintext[pos[1]]
        
        self.railfence_ciphertext.delete("1.0", tk.END)
        self.railfence_ciphertext.insert("1.0", ciphertext)
    
    def railfence_decrypt(self):
        ciphertext = self.railfence_ciphertext.get("1.0", tk.END).strip()
        try:
            rails = int(self.railfence_key.get())
        except ValueError:
            messagebox.showerror("Error", "Number of rails must be an integer")
            return
        
        if rails < 2 or rails > 10:
            messagebox.showerror("Error", "Number of rails must be between 2 and 10")
            return
        
        # Create the rail pattern
        pattern = []
        down = True
        current_rail = 0
        
        for i in range(len(ciphertext)):
            pattern.append((current_rail, i))
            if down:
                if current_rail == rails - 1:
                    down = False
                    current_rail -= 1
                else:
                    current_rail += 1
            else:
                if current_rail == 0:
                    down = True
                    current_rail += 1
                else:
                    current_rail -= 1
        
        # Sort the pattern to get the original order
        sorted_pattern = sorted(pattern, key=lambda x: x[1])
        
        # Reconstruct the plaintext
        plaintext = [''] * len(ciphertext)
        for i in range(len(ciphertext)):
            plaintext[sorted_pattern[i][1]] = ciphertext[i]
        
        self.railfence_plaintext.delete("1.0", tk.END)
        self.railfence_plaintext.insert("1.0", "".join(plaintext))
    
    # Row Transposition Cipher Methods
    def rowtrans_encrypt(self):
        plaintext = self.rowtrans_plaintext.get("1.0", tk.END).upper().strip()
        key_str = self.rowtrans_key.get().strip()
        
        # Remove non-alphabetic characters
        plaintext = re.sub(r'[^A-Z]', '', plaintext)
        
        try:
            key = [int(num) for num in key_str.split()]
        except ValueError:
            messagebox.showerror("Error", "Key must be space-separated integers (e.g., '3 1 4 2')")
            return
        
        # Fill the matrix
        num_cols = len(key)
        num_rows = (len(plaintext) + num_cols - 1) // num_cols
        matrix = [[''] * num_cols for _ in range(num_rows)]
        
        index = 0
        for row in range(num_rows):
            for col in range(num_cols):
                if index < len(plaintext):
                    matrix[row][col] = plaintext[index]
                    index += 1
                else:
                    matrix[row][col] = 'X'  # Padding
        
        # Read columns in key order
        ciphertext = ""
        for col in sorted(range(1, num_cols + 1), key=lambda x: key.index(x)):
            for row in range(num_rows):
                ciphertext += matrix[row][col - 1]
        
        self.rowtrans_ciphertext.delete("1.0", tk.END)
        self.rowtrans_ciphertext.insert("1.0", ciphertext)
    
    def rowtrans_decrypt(self):
        ciphertext = self.rowtrans_ciphertext.get("1.0", tk.END).upper().strip()
        key_str = self.rowtrans_key.get().strip()
        
        # Remove non-alphabetic characters
        ciphertext = re.sub(r'[^A-Z]', '', ciphertext)
        
        try:
            key = [int(num) for num in key_str.split()]
        except ValueError:
            messagebox.showerror("Error", "Key must be space-separated integers (e.g., '3 1 4 2')")
            return
        
        num_cols = len(key)
        num_rows = len(ciphertext) // num_cols
        
        if len(ciphertext) % num_cols != 0:
            messagebox.showerror("Error", "Ciphertext length must be a multiple of the key length")
            return
        
        # Reconstruct the matrix columns
        cols = []
        col_length = num_rows
        for i in range(num_cols):
            start = i * col_length
            end = start + col_length
            cols.append(ciphertext[start:end])
        
        # Reorder columns according to key
        ordered_cols = [None] * num_cols
        for i in range(num_cols):
            ordered_cols[key[i] - 1] = cols[i]
        
        # Read the matrix row-wise
        plaintext = ""
        for row in range(num_rows):
            for col in range(num_cols):
                plaintext += ordered_cols[col][row]
        
        # Remove any padding X's at the end
        plaintext = plaintext.rstrip('X')
        
        self.rowtrans_plaintext.delete("1.0", tk.END)
        self.rowtrans_plaintext.insert("1.0", plaintext)
    
    # Multi-Layer Encryption Methods
    def multi_encrypt(self):
        plaintext = self.multi_plaintext.get("1.0", tk.END).strip()
        steps = ["Original: " + plaintext]
        
        current_text = plaintext
        
        for i in range(3):
            cipher_type = self.sequence_vars[i].get()
            if cipher_type == 'None':
                continue
                
            key = getattr(self, f"multi_key_{i}").get().strip()
            
            if cipher_type == 'Caesar':
                try:
                    key = int(key)
                except ValueError:
                    messagebox.showerror("Error", f"Layer {i+1}: Caesar key must be an integer")
                    return
                
                # Caesar encryption
                ciphertext = ""
                for char in current_text.upper():
                    if char.isalpha():
                        shifted = ord(char) + key
                        if shifted > ord('Z'):
                            shifted -= 26
                        ciphertext += chr(shifted)
                    else:
                        ciphertext += char
                current_text = ciphertext
                steps.append(f"Caesar (shift {key}): {current_text}")
                
            elif cipher_type == 'Vigenère':
                if not key.isalpha():
                    messagebox.showerror("Error", f"Layer {i+1}: Vigenère key must be alphabetic")
                    return
                
                # Vigenère encryption
                ciphertext = ""
                key_index = 0
                for char in current_text.upper():
                    if char.isalpha():
                        shift = ord(key[key_index % len(key)]) - ord('A')
                        shifted = ord(char) + shift
                        if shifted > ord('Z'):
                            shifted -= 26
                        ciphertext += chr(shifted)
                        key_index += 1  # Increment key_index only for alphabetic characters
                    else:
                        ciphertext += char
                current_text = ciphertext
                steps.append(f"Vigenère (key '{key}'): {current_text}")
                
            elif cipher_type == 'Playfair':
                if not key:
                    messagebox.showerror("Error", f"Layer {i+1}: Playfair key cannot be empty")
                    return
                
                # Playfair encryption
                matrix = self.create_playfair_matrix(key)
                prepared_text = self.playfair_prepare_text(current_text)
                ciphertext = ""
                for digraph in prepared_text:
                    ciphertext += self.playfair_encrypt_digraph(matrix, digraph)
                current_text = ciphertext
                steps.append(f"Playfair (key '{key}'): {current_text}")
                
            elif cipher_type == 'Monoalphabetic':
                if len(key) != 26 or not key.isalpha():
                    messagebox.showerror("Error", f"Layer {i+1}: Monoalphabetic key must be 26 unique letters")
                    return
                
                # Monoalphabetic encryption
                ciphertext = ""
                for char in current_text.upper():
                    if char.isalpha():
                        index = ord(char) - ord('A')
                        ciphertext += key[index]
                    else:
                        ciphertext += char
                current_text = ciphertext
                steps.append(f"Monoalphabetic: {current_text}")
                
            elif cipher_type == 'Rail Fence':
                try:
                    rails = int(key)
                except ValueError:
                    messagebox.showerror("Error", f"Layer {i+1}: Rail Fence key must be an integer")
                    return
                
                if rails < 2 or rails > 10:
                    messagebox.showerror("Error", f"Layer {i+1}: Number of rails must be between 2 and 10")
                    return
                
                # Rail Fence encryption
                pattern = []
                down = True
                current_rail = 0
                
                for pos in range(len(current_text)):
                    pattern.append((current_rail, pos))
                    if down:
                        if current_rail == rails - 1:
                            down = False
                            current_rail -= 1
                        else:
                            current_rail += 1
                    else:
                        if current_rail == 0:
                            down = True
                            current_rail += 1
                        else:
                            current_rail -= 1
                
                pattern.sort()
                ciphertext = ""
                for pos in pattern:
                    ciphertext += current_text[pos[1]]
                current_text = ciphertext
                steps.append(f"Rail Fence ({rails} rails): {current_text}")
                
            elif cipher_type == 'Row Transposition':
                try:
                    key = [int(num) for num in key.split()]
                except ValueError:
                    messagebox.showerror("Error", f"Layer {i+1}: Row Transposition key must be space-separated integers")
                    return
                
                # Row Transposition encryption
                plaintext = re.sub(r'[^A-Z]', '', current_text.upper())
                num_cols = len(key)
                num_rows = (len(plaintext) + num_cols - 1) // num_cols
                matrix = [[''] * num_cols for _ in range(num_rows)]
                
                index = 0
                for row in range(num_rows):
                    for col in range(num_cols):
                        if index < len(plaintext):
                            matrix[row][col] = plaintext[index]
                            index += 1
                        else:
                            matrix[row][col] = 'X'
                
                ciphertext = ""
                for col in sorted(range(1, num_cols + 1), key=lambda x: key.index(x)):
                    for row in range(num_rows):
                        ciphertext += matrix[row][col - 1]
                current_text = ciphertext
                steps.append(f"Row Transposition (key '{' '.join(map(str, key))}'): {current_text}")
        
        self.multi_ciphertext.delete("1.0", tk.END)
        self.multi_ciphertext.insert("1.0", current_text)
        
        self.multi_steps.config(state=tk.NORMAL)
        self.multi_steps.delete("1.0", tk.END)
        self.multi_steps.insert("1.0", "\n".join(steps))
        self.multi_steps.config(state=tk.DISABLED)
    
    def multi_decrypt(self):
        ciphertext = self.multi_ciphertext.get("1.0", tk.END).strip()
        steps = ["Encrypted: " + ciphertext]
        
        current_text = ciphertext
        
        # Process layers in reverse order
        for i in reversed(range(3)):
            cipher_type = self.sequence_vars[i].get()
            if cipher_type == 'None':
                continue
                
            key = getattr(self, f"multi_key_{i}").get().strip()
            
            if cipher_type == 'Caesar':
                try:
                    key = int(key)
                except ValueError:
                    messagebox.showerror("Error", f"Layer {i+1}: Caesar key must be an integer")
                    return
                
                # Caesar decryption
                plaintext = ""
                for char in current_text.upper():
                    if char.isalpha():
                        shifted = ord(char) - key
                        if shifted < ord('A'):
                            shifted += 26
                        plaintext += chr(shifted)
                    else:
                        plaintext += char
                current_text = plaintext
                steps.append(f"Caesar (shift {key}): {current_text}")
                
            elif cipher_type == 'Vigenère':
                if not key.isalpha():
                    messagebox.showerror("Error", f"Layer {i+1}: Vigenère key must be alphabetic")
                    return
                
                # Vigenère decryption
                plaintext = ""
                key_index = 0
                for char in current_text.upper():
                    if char.isalpha():
                        shift = ord(key[key_index % len(key)]) - ord('A')
                        shifted = ord(char) - shift
                        if shifted < ord('A'):
                            shifted += 26
                        plaintext += chr(shifted)
                        key_index += 1
                    else:
                        plaintext += char
                current_text = plaintext
                steps.append(f"Vigenère (key '{key}'): {current_text}")
                
            elif cipher_type == 'Playfair':
                if not key:
                    messagebox.showerror("Error", f"Layer {i+1}: Playfair key cannot be empty")
                    return
                
                # Playfair decryption
                matrix = self.create_playfair_matrix(key)
                prepared_text = self.playfair_prepare_text(current_text)
                plaintext = ""
                for digraph in prepared_text:
                    plaintext += self.playfair_decrypt_digraph(matrix, digraph)
                if plaintext.endswith("X"):
                    plaintext = plaintext[:-1]
                current_text = plaintext
                steps.append(f"Playfair (key '{key}'): {current_text}")
                
            elif cipher_type == 'Monoalphabetic':
                if len(key) != 26 or not key.isalpha():
                    messagebox.showerror("Error", f"Layer {i+1}: Monoalphabetic key must be 26 unique letters")
                    return
                
                # Monoalphabetic decryption
                plaintext = ""
                for char in current_text.upper():
                    if char.isalpha():
                        index = key.index(char)
                        plaintext += chr(ord('A') + index)
                    else:
                        plaintext += char
                current_text = plaintext
                steps.append(f"Monoalphabetic: {current_text}")
                
            elif cipher_type == 'Rail Fence':
                try:
                    rails = int(key)
                except ValueError:
                    messagebox.showerror("Error", f"Layer {i+1}: Rail Fence key must be an integer")
                    return
                
                if rails < 2 or rails > 10:
                    messagebox.showerror("Error", f"Layer {i+1}: Number of rails must be between 2 and 10")
                    return
                
                # Rail Fence decryption
                pattern = []
                down = True
                current_rail = 0
                
                for pos in range(len(current_text)):
                    pattern.append((current_rail, pos))
                    if down:
                        if current_rail == rails - 1:
                            down = False
                            current_rail -= 1
                        else:
                            current_rail += 1
                    else:
                        if current_rail == 0:
                            down = True
                            current_rail += 1
                        else:
                            current_rail -= 1
                
                sorted_pattern = sorted(pattern, key=lambda x: x[1])
                plaintext = [''] * len(current_text)
                for i in range(len(current_text)):
                    plaintext[sorted_pattern[i][1]] = current_text[i]
                current_text = "".join(plaintext)
                steps.append(f"Rail Fence ({rails} rails): {current_text}")
                
            elif cipher_type == 'Row Transposition':
                try:
                    key = [int(num) for num in key.split()]
                except ValueError:
                    messagebox.showerror("Error", f"Layer {i+1}: Row Transposition key must be space-separated integers")
                    return
                
                # Row Transposition decryption
                ciphertext = re.sub(r'[^A-Z]', '', current_text.upper())
                num_cols = len(key)
                num_rows = len(ciphertext) // num_cols
                
                if len(ciphertext) % num_cols != 0:
                    messagebox.showerror("Error", f"Layer {i+1}: Ciphertext length must be a multiple of the key length")
                    return
                
                cols = []
                col_length = num_rows
                for i in range(num_cols):
                    start = i * col_length
                    end = start + col_length
                    cols.append(ciphertext[start:end])
                
                ordered_cols = [None] * num_cols
                for i in range(num_cols):
                    ordered_cols[key[i] - 1] = cols[i]
                
                plaintext = ""
                for row in range(num_rows):
                    for col in range(num_cols):
                        plaintext += ordered_cols[col][row]
                plaintext = plaintext.rstrip('X')
                current_text = plaintext
                steps.append(f"Row Transposition (key '{' '.join(map(str, key))}'): {current_text}")
        
        self.multi_plaintext.delete("1.0", tk.END)
        self.multi_plaintext.insert("1.0", current_text)
        
        self.multi_steps.config(state=tk.NORMAL)
        self.multi_steps.delete("1.0", tk.END)
        self.multi_steps.insert("1.0", "\n".join(reversed(steps)))
        self.multi_steps.config(state=tk.DISABLED)

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()