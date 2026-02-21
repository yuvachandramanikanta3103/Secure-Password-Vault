import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import bcrypt
import base64
import csv

import db
import crypto

APP_TITLE = "Secure Password Vault"


class VaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("760x520")
        db.initialize_db()
        self.master_hash = db.get_master_hash()
        if not self.master_hash:
            self.show_setup_screen()
        else:
            self.show_login_screen()

    def clear(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_setup_screen(self):
        self.clear()
        lbl = ttk.Label(self, text="Create Master Password", font=(None, 16))
        lbl.pack(pady=12)
        pw1 = ttk.Entry(self, show="*")
        pw1.pack(pady=6)
        pw2 = ttk.Entry(self, show="*")
        pw2.pack(pady=6)

        def create_master():
            p1 = pw1.get().strip()
            p2 = pw2.get().strip()
            if not p1 or not p2:
                messagebox.showerror("Error", "Please enter password in both fields")
                return
            if p1 != p2:
                messagebox.showerror("Error", "Passwords do not match")
                return
            hashed = bcrypt.hashpw(p1.encode(), bcrypt.gensalt())
            db.save_master_hash(hashed)
            messagebox.showinfo("Success", "Master password created. Please login.")
            self.master_hash = db.get_master_hash()
            self.show_login_screen()

        btn = ttk.Button(self, text="Create", command=create_master)
        btn.pack(pady=8)

    def show_login_screen(self):
        self.clear()
        lbl = ttk.Label(self, text="Enter Master Password", font=(None, 16))
        lbl.pack(pady=12)
        pw = ttk.Entry(self, show="*")
        pw.pack(pady=6)

        def try_login():
            entered = pw.get().strip()
            if not entered:
                messagebox.showerror("Error", "Enter master password")
                return
            if bcrypt.checkpw(entered.encode(), self.master_hash):
                # login success
                self.master_password = entered
                self.show_main_screen()
            else:
                messagebox.showerror("Error", "Incorrect master password")

        btn = ttk.Button(self, text="Login", command=try_login)
        btn.pack(pady=8)

    def show_main_screen(self):
        self.clear()
        header = ttk.Frame(self)
        header.pack(fill=tk.X, pady=6)
        ttk.Label(header, text=APP_TITLE, font=(None, 18)).pack(side=tk.LEFT, padx=8)
        ttk.Button(header, text="Add Entry", command=self.add_entry_dialog).pack(side=tk.RIGHT, padx=6)
        ttk.Button(header, text="Export CSV", command=self.export_csv).pack(side=tk.RIGHT, padx=6)

        search_frame = ttk.Frame(self)
        search_frame.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Button(search_frame, text="Find", command=self.refresh_list).pack(side=tk.LEFT)

        # treeview
        cols = ("id", "account", "username")
        self.tree = ttk.Treeview(self, columns=cols, show='headings')
        self.tree.heading('id', text='ID')
        self.tree.heading('account', text='Account')
        self.tree.heading('username', text='Username')
        self.tree.column('id', width=40)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        self.tree.bind('<Double-1>', self.on_item_double)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=8, pady=6)
        ttk.Button(btn_frame, text="Refresh", command=self.refresh_list).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="View", command=self.view_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Edit", command=self.edit_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Delete", command=self.delete_selected).pack(side=tk.LEFT, padx=6)

        self.refresh_list()

    def refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = db.fetch_all()
        q = self.search_var.get().strip().lower()
        for r in rows:
            rid, acct, user, encpw, notes = r
            if q and q not in acct.lower() and q not in (user or '').lower():
                continue
            self.tree.insert('', 'end', values=(rid, acct, user))

    def add_entry_dialog(self):
        dlg = EntryDialog(self, title="Add Entry")
        self.wait_window(dlg)
        if getattr(dlg, 'saved', False):
            acct = dlg.account_name.get().strip()
            user = dlg.username.get().strip()
            pw = dlg.password.get().strip()
            notes = dlg.notes_value
            if not acct or not pw:
                messagebox.showerror("Error", "Account and Password required")
                return
            enc = crypto.encrypt(pw, self.master_password)
            # store as text
            db.add_entry(acct, user, enc.decode(), notes)
            self.refresh_list()

    def get_selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an entry first")
            return None
        item = self.tree.item(sel[0])
        return item['values'][0]

    def view_selected(self):
        eid = self.get_selected_id()
        if not eid:
            return
        row = db.fetch_by_id(eid)
        if not row:
            messagebox.showerror("Error", "Entry not found")
            return
        _, acct, user, encpw, notes = row
        try:
            plaintext = crypto.decrypt(encpw.encode(), self.master_password)
        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))
            return
        info = f"Account: {acct}\nUsername: {user}\nPassword: {plaintext}\n\nNotes:\n{notes}"
        messagebox.showinfo("View Entry", info)

    def edit_selected(self):
        eid = self.get_selected_id()
        if not eid:
            return
        row = db.fetch_by_id(eid)
        if not row:
            messagebox.showerror("Error", "Entry not found")
            return
        _, acct, user, encpw, notes = row
        try:
            plaintext = crypto.decrypt(encpw.encode(), self.master_password)
        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))
            return
        dlg = EntryDialog(self, title="Edit Entry", account=acct, username=user, password=plaintext, notes=notes)
        self.wait_window(dlg)
        if getattr(dlg, 'saved', False):
            acct = dlg.account_name.get().strip()
            user = dlg.username.get().strip()
            pw = dlg.password.get().strip()
            notes = dlg.notes_value
            if not acct or not pw:
                messagebox.showerror("Error", "Account and Password required")
                return
            enc = crypto.encrypt(pw, self.master_password)
            db.update_entry(eid, acct, user, enc.decode(), notes)
            self.refresh_list()

    def delete_selected(self):
        eid = self.get_selected_id()
        if not eid:
            return
        if messagebox.askyesno("Delete", "Delete selected entry? This cannot be undone."):
            db.delete_entry(eid)
            self.refresh_list()

    def on_item_double(self, event):
        self.view_selected()

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files','*.csv')])
        if not path:
            return
        rows = db.fetch_all()
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['id','account_name','username','encrypted_password','notes'])
            for r in rows:
                writer.writerow(r)
        messagebox.showinfo('Exported', f'Exported {len(rows)} rows to {path}')

class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title="Entry", account='', username='', password='', notes=''):
        super().__init__(parent)
        self.title(title)
        self.account_name = tk.StringVar(value=account)
        self.username = tk.StringVar(value=username)
        self.password = tk.StringVar(value=password)
        self.notes_value = notes

        frm = ttk.Frame(self)
        frm.pack(padx=12, pady=12, fill=tk.BOTH, expand=True)
        ttk.Label(frm, text='Account Name').pack(anchor='w')
        ttk.Entry(frm, textvariable=self.account_name).pack(fill=tk.X)
        ttk.Label(frm, text='Username').pack(anchor='w', pady=(8,0))
        ttk.Entry(frm, textvariable=self.username).pack(fill=tk.X)
        ttk.Label(frm, text='Password').pack(anchor='w', pady=(8,0))
        ttk.Entry(frm, textvariable=self.password, show='*').pack(fill=tk.X)
        ttk.Label(frm, text='Notes').pack(anchor='w', pady=(8,0))
        self.notes = tk.Text(frm, height=6)
        self.notes.pack(fill=tk.BOTH)
        if notes:
            self.notes.insert('1.0', notes)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text='Save', command=self.save).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text='Cancel', command=self.cancel).pack(side=tk.LEFT)

    def save(self):
        self.notes_value = self.notes.get('1.0', tk.END).strip()
        self.saved = True
        self.destroy()

    def cancel(self):
        self.saved = False
        self.destroy()

if __name__ == '__main__':
    app = VaultApp()
    app.mainloop()
