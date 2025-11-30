import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from pypdf import PdfWriter, PdfReader
from pypdf.constants import UserAccessPermissions

from typing import List, Dict


def merge_pdfs(
        input_files: List[Dict[str, str | int | List[int]]], 
        output_file: str, 
        password=None, 
        permissions_flag=None,
        enable_page_selection=False
) -> None:
    """
    Merges multiple PDF files into a single PDF file. If password is not None,
    then the out file is encrypted with the given password
    and permissions are set according to the permissions_flag.
    """
    merger = PdfWriter()
    for file_data in input_files:
        path = file_data['path']
        if enable_page_selection and file_data.get('selected_pages') is not None:
            # Append specific pages
            # pypdf append takes (fileobj, pages)
            # pages can be a list of page indices
            merger.append(fileobj=path, pages=file_data['selected_pages'])
        else:
            merger.append(fileobj=path)
    
    if password:
        merger.encrypt(password, permissions_flag=permissions_flag)
        
    merger.write(output_file)
    merger.close()

class GUI:
    def __init__(self) -> None:
        """
        Initializes the main GUI window and its components.
        """
        self.root = tk.Tk()
        self.root.title("PDF Merger")
        self.root.geometry("900x600")
        self.root.iconphoto(True, tk.PhotoImage(file="images/pdfmerger_icon.png"))
        
        # Apply a theme
        style = ttk.Style()
        style.theme_use('clam')
        
        self.file_list = []
        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self) -> None:
        """
        Creates and places all GUI widgets.
        """
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Top Buttons ---
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(btn_frame, text="Add PDF Files", command=self.add_files).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Remove Selected", command=self.remove_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear All", command=self.clear_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Help", command=self.help).pack(side=tk.RIGHT, padx=0)

        # --- File Table ---
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ("order", "filename", "size", "pages")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("order", text="Item")
        self.tree.heading("filename", text="Filename")
        self.tree.heading("size", text="Size")
        self.tree.heading("pages", text="Pages")
        
        self.tree.column("order", width=40, anchor=tk.CENTER)
        self.tree.column("filename", width=400, anchor=tk.W)
        self.tree.column("size", width=80, anchor=tk.CENTER)
        self.tree.column("pages", width=60, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Reorder Buttons ---
        reorder_frame = ttk.Frame(main_frame)
        reorder_frame.pack(fill=tk.X, pady=5)
        ttk.Button(reorder_frame, text="Move Up", command=self.move_up).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(reorder_frame, text="Move Down", command=self.move_down).pack(side=tk.LEFT, padx=5)
        ttk.Button(reorder_frame, text="Move First", command=self.move_first).pack(side=tk.LEFT, padx=5)
        ttk.Button(reorder_frame, text="Move Last", command=self.move_last).pack(side=tk.LEFT, padx=5)

        # --- Output Settings ---
        settings_frame = ttk.LabelFrame(main_frame, text="Output Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=10)
        
        self.open_after_save = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Open file after saving", variable=self.open_after_save).pack(anchor=tk.W)

        # Container for side-by-side frames
        options_container = ttk.Frame(settings_frame)
        options_container.pack(fill=tk.X, pady=5)

        # --- Security Frame ---
        security_frame = ttk.LabelFrame(options_container, text="Security", padding="10")
        security_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Password
        pwd_frame = ttk.Frame(security_frame)
        pwd_frame.pack(fill=tk.X, pady=2)
        
        self.use_security = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar()
        
        cb_pwd = ttk.Checkbutton(pwd_frame, text="Toggle password/security", variable=self.use_security, command=self.toggle_security)
        cb_pwd.pack(side=tk.LEFT)
        
        self.password_entry = ttk.Entry(pwd_frame, textvariable=self.password_var, show="*", state="disabled")
        self.password_entry.pack(side=tk.LEFT, padx=10)

        # Permissions
        perm_frame = ttk.Frame(security_frame)
        perm_frame.pack(fill=tk.X, pady=2)
        
        self.allow_editing = tk.BooleanVar(value=False)
        self.allow_copying = tk.BooleanVar(value=False)
        self.allow_printing = tk.BooleanVar(value=False)
        
        self.allow_editing_cb = ttk.Checkbutton(perm_frame, text="Allow Editing", variable=self.allow_editing, state="disabled")
        self.allow_editing_cb.pack(side=tk.LEFT, padx=(0, 10))
        self.allow_copying_cb = ttk.Checkbutton(perm_frame, text="Allow Copying", variable=self.allow_copying, state="disabled")
        self.allow_copying_cb.pack(side=tk.LEFT, padx=10)
        self.allow_printing_cb = ttk.Checkbutton(perm_frame, text="Allow Printing", variable=self.allow_printing, state="disabled")
        self.allow_printing_cb.pack(side=tk.LEFT, padx=10)

        # --- Page Selection Frame ---
        page_selection_frame = ttk.LabelFrame(options_container, text="Page Selection", padding="10")
        page_selection_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # --- Page Selection Settings ---
        self.enable_page_selection = tk.BooleanVar(value=False)
        self.select_btn_text = tk.StringVar(value="Select Pages for Selected File")
        
        ttk.Checkbutton(page_selection_frame, text="Enable Page Selection", variable=self.enable_page_selection, command=self.toggle_page_selection).pack(anchor=tk.W)
        
        def change_select_btn_text():
            """
            Return the correct text for select pages button based on the selected file.
            """
            selected = self.tree.selection()
            if selected:
                idx = self.tree.index(selected[0])
                filename = self.file_list[idx]['filename']
                if len(filename) > 45:
                    filename = filename[:42] + "..."
                return f"Select Pages for: {filename}"
            return "Select Pages for Selected File"

        self.tree.bind("<<TreeviewSelect>>", lambda e: self.select_btn_text.set(change_select_btn_text()))

        self.select_pages_btn = ttk.Button(page_selection_frame, textvariable=self.select_btn_text, command=self.open_page_selector, state="disabled")
        self.select_pages_btn.pack(fill=tk.X, pady=5)

        # --- Save Button ---
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        save_btn = ttk.Button(action_frame, text="Merge & Save PDF", command=self.save_file)
        save_btn.pack(side=tk.RIGHT)

    def add_files(self) -> None:
        """
        Adds selected PDF files to the list.
        """
        files = filedialog.askopenfilenames(filetypes=[("PDF Files", "*.pdf")])
        for path in files:
            try:
                size = os.path.getsize(path)
                size_str = f"{size / 1024:.1f} KB"
                
                # Get page count
                try:
                    reader = PdfReader(path)
                    if reader.is_encrypted:
                        try:
                            reader.decrypt("")
                        except:
                            pass
                    pages = len(reader.pages)
                except Exception:
                    pages = "?"

                self.file_list.append({
                    "path": path,
                    "filename": os.path.basename(path),
                    "size": size_str,
                    "pages": pages,
                    "selected_pages": None # None means all pages
                })
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load {os.path.basename(path)}\n{e}")
        
        self.refresh_tree()

    def remove_file(self) -> None:
        """
        Removes the selected file from the treeview.
        """
        selected = self.tree.selection()
        if selected:
            idx = self.tree.index(selected[0])
            del self.file_list[idx]
            self.refresh_tree()

    def clear_files(self) -> None:
        """
        Clears all files from the treeview.
        """
        self.file_list = []
        self.refresh_tree()

    def help(self) -> None:
        """
        Displays the help window.
        """
        help_window = tk.Toplevel(self.root)
        help_window.title("Help")
        help_window.geometry("400x300")
        help_window.config(bg="#dcdad5")

        # Help Text
        ttk.Label(help_window, text="Nothing Here...").pack(pady=10)

    def toggle_page_selection(self) -> None:
        """
        Enables or disables the page selection button based on the checkbox state.
        """
        if self.enable_page_selection.get():
            self.select_pages_btn.config(state="normal")
        else:
            self.select_pages_btn.config(state="disabled")

    def open_page_selector(self) -> None:
        """
        Opens a new window to select pages for the selected PDF file.
        """
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file from the list first.")
            return
        
        idx = self.tree.index(selected[0])
        file_data = self.file_list[idx]
        
        if file_data['pages'] == "?":
            messagebox.showerror("Error", "Cannot select pages for this file (unknown page count).")
            return
            
        num_pages = int(file_data['pages'])
        
        # Create Toplevel window
        selector = tk.Toplevel(self.root)
        selector.title(f"Select Pages - {file_data['filename']}")
        selector.geometry("500x500")
        
        # Main container
        main_frame = ttk.Frame(selector, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollable frame for checkboxes
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Checkboxes
        self.page_vars = []
        current_selection = file_data.get('selected_pages')
        
        # Grid configuration
        columns = 9
        
        for i in range(num_pages):
            var = tk.BooleanVar()
            # If current_selection is None, it means all pages are selected by default
            # If it is a list, check if i is in it
            if current_selection is None:
                var.set(True)
            else:
                var.set(i in current_selection)
            
            self.page_vars.append(var)
            cb = ttk.Checkbutton(scrollable_frame, text=str(i+1), variable=var)
            cb.grid(row=i // columns, column=i % columns, padx=5, pady=5, sticky="w")
            
        # Buttons Frame
        btn_frame = ttk.Frame(selector, padding="10")
        btn_frame.pack(fill=tk.X)
        
        def deselect_all():
            """
            sets all checkboxes to False
            """
            for var in self.page_vars:
                var.set(False)
                
        def select_all():
            """
            sets all checkboxes to True
            """
            for var in self.page_vars:
                var.set(True)
                
        def save_selection():
            """Saves the selected pages back to the file_list. 
            If all checkboxes are selected, sets to None.
            """
            selected_indices = [i for i, var in enumerate(self.page_vars) if var.get()]
            # If all selected, set to None to indicate default
            if len(selected_indices) == num_pages:
                self.file_list[idx]['selected_pages'] = None
            else:
                self.file_list[idx]['selected_pages'] = selected_indices
            selector.destroy()
            
        ttk.Button(btn_frame, text="Deselect All", command=deselect_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Select All", command=select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=save_selection).pack(side=tk.RIGHT, padx=5)

    def toggle_security(self) -> None:
        """
        Enables or disables security options based on the checkbox state.
        """
        if self.use_security.get():
            self.password_entry.config(state="normal")
            self.allow_editing_cb.config(state="normal")
            self.allow_copying_cb.config(state="normal")
            self.allow_printing_cb.config(state="normal")
        else:
            self.password_entry.config(state="disabled")
            self.allow_editing_cb.config(state="disabled")
            self.allow_copying_cb.config(state="disabled")
            self.allow_printing_cb.config(state="disabled")
            self.password_var.set("")
            self.allow_editing.set(False)
            self.allow_copying.set(False)
            self.allow_printing.set(False)

    def move_up(self) -> None:
        """
        Moves the selected file up in the list.
        """
        selected = self.tree.selection()
        if selected:
            idx = self.tree.index(selected[0])
            if idx > 0:
                self.file_list[idx], self.file_list[idx-1] = self.file_list[idx-1], self.file_list[idx]
                self.refresh_tree()
                self.tree.selection_set(self.tree.get_children()[idx-1])

    def move_down(self) -> None:
        """
        Moves the selected file down in the list.
        """
        selected = self.tree.selection()
        if selected:
            idx = self.tree.index(selected[0])
            if idx < len(self.file_list) - 1:
                self.file_list[idx], self.file_list[idx+1] = self.file_list[idx+1], self.file_list[idx]
                self.refresh_tree()
                self.tree.selection_set(self.tree.get_children()[idx+1])

    def move_first(self) -> None:
        """
        Moves the selected file to the top of the list.
        """
        selected = self.tree.selection()
        if selected:
            idx = self.tree.index(selected[0])
            self.file_list[idx], self.file_list[0] = self.file_list[0], self.file_list[idx]
            self.refresh_tree()
            self.tree.selection_set(self.tree.get_children()[0])
    
    def move_last(self) -> None:
        """
        Moves the selected file to the bottom of the list.
        """
        selected = self.tree.selection()
        if selected:
            idx = self.tree.index(selected[0])
            self.file_list[idx], self.file_list[-1] = self.file_list[-1], self.file_list[idx]
            self.refresh_tree()
            self.tree.selection_set(self.tree.get_children()[-1])

    def open_on_save(self, output_path: str) -> None:
        """
        Opens the merged PDF file after saving.
        """
        try:
            os.startfile(output_path)
        except AttributeError:
            # Fallback for non-Windows
            import subprocess, sys
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            subprocess.call([opener, output_path])

    def refresh_tree(self) -> None:
        """
        Updates the treeview display.
        """
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, f in enumerate(self.file_list):
            self.tree.insert("", "end", values=(i+1, f['filename'], f['size'], f['pages']))

    def save_file(self) -> None:
        """
        Saves the merged PDF file.
        """
        if not self.file_list:
            messagebox.showwarning("Warning", "No files to merge!")
            return
            
        output_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if output_path:
            try:
                # Pass the full file_list to merge_pdfs
                password = self.password_var.get() if self.use_security.get() else None
                permissions = None
                
                if password:
                    permissions = 0
                    if self.allow_printing.get():
                        permissions |= UserAccessPermissions.PRINT
                    if self.allow_editing.get():
                        permissions |= UserAccessPermissions.MODIFY
                    if self.allow_copying.get():
                        permissions |= UserAccessPermissions.EXTRACT
                
                merge_pdfs(
                    self.file_list, 
                    output_path, 
                    password, 
                    permissions, 
                    enable_page_selection=self.enable_page_selection.get()
                )
                
                if self.open_after_save.get():
                    self.open_on_save(output_path)
                else:
                    messagebox.showinfo("Success", "Files merged successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to merge files:\n{e}")

if __name__ == "__main__":
    gui = GUI()