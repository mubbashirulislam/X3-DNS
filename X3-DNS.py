import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from ttkthemes import ThemedStyle
import dns.resolver
import threading
import queue
import datetime
import re

class DNSCheckerApp(tk.Tk):
    def __init__(self):
        """Initialize the main DNS Checker App window and its widgets."""
        super().__init__()

        # Window settings
        self.title("X3-DNS Checker")
        self.geometry("1920x1080")
        self.configure(bg='#0f0f0f')

        # Setup themed styles for the app
        self.style = ThemedStyle(self)
        self.style.set_theme("equilux")  # Dark theme for the UI

        # List of vulnerabilities to check
        self.vulnerabilities = ['SPF', 'DKIM', 'DMARC', 'DNSSEC', 'MX', 'CAA']
        self.vulnerability_vars = {v: tk.BooleanVar(value=True) for v in self.vulnerabilities}  # Checkboxes for each vulnerability

        # Queue to update the results asynchronously
        self.update_queue = queue.Queue()

        # Call setup methods
        self.setup_styles()
        self.create_widgets()

        # Start checking for UI updates
        self.check_updates()

        # Handle window close event
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.is_batch_processing = False  # Flag for batch processing

    def setup_styles(self):
        """Setup the visual styles for widgets in the app."""
        self.style.configure('TFrame', background='#0f0f0f')
        self.style.configure('TLabel', background='#0f0f0f', foreground='#e0e0e0', font=('Roboto', 11))
        self.style.configure('Header.TLabel', font=('Roboto', 24, 'bold'), foreground='#00eeff')
        self.style.configure('TButton', font=('Roboto', 11, 'bold'), padding=[15, 8], background='#1e1e1e', foreground='#e0e0e0')
        self.style.map('TButton', background=[('active', '#1e1e1e')], foreground=[('active', '#e0e0e0')])
        self.style.configure('TEntry', fieldbackground='#1e1e1e', foreground='#e0e0e0', padding=[8, 8])
        self.style.configure('TCheckbutton', background='#0f0f0f', foreground='#e0e0e0', font=('Roboto', 11))
        self.style.map('TCheckbutton', background=[('active', '#1e1e1e')])

    def create_widgets(self):
        """Create and layout all the widgets in the app."""
        main_frame = ttk.Frame(self, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create sections for the app
        self.create_header(main_frame)
        self.create_input_section(main_frame)
        self.create_vulnerability_options(main_frame)
        self.create_results_section(main_frame)
        self.create_action_buttons(main_frame)

    def create_header(self, parent):
        """Create the header section of the app."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(header_frame, text="X3-DNS Checker", style='Header.TLabel').pack(side=tk.LEFT)
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side=tk.RIGHT)
        ttk.Label(info_frame, text="Developer: X3NIDE", style='TLabel').pack(anchor=tk.E)
        ttk.Label(info_frame, text="GitHub: https://github.com/mubbashirulislam", style='TLabel').pack(anchor=tk.E)

    def create_input_section(self, parent):
        """Create the input section for domain entry and buttons."""
        input_frame = ttk.Frame(parent)
        input_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(input_frame, text="Domain:").pack(side=tk.LEFT)

        # Entry box for domain input
        self.domain_entry = ttk.Entry(input_frame, width=50, font=('Roboto', 11))
        self.domain_entry.pack(side=tk.LEFT, padx=(15, 15), expand=True, fill=tk.X)

        # Button to check DNS for entered domain
        ttk.Button(input_frame, text="Check DNS", command=self.check_dns, style='TButton').pack(side=tk.LEFT)
        
        # Button to load domains from file
        ttk.Button(input_frame, text="Load Domains", command=self.load_domains, style='TButton').pack(side=tk.LEFT, padx=(15, 0))

    def create_vulnerability_options(self, parent):
        """Create checkboxes for selecting vulnerabilities to check."""
        vuln_frame = ttk.Frame(parent)
        vuln_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(vuln_frame, text="Select vulnerabilities to check:", font=('Roboto', 12, 'bold')).pack(anchor=tk.W, pady=(0, 10))

        checkbox_frame = ttk.Frame(vuln_frame)
        checkbox_frame.pack(fill=tk.X)

        # Create a checkbox for each vulnerability
        for vuln in self.vulnerabilities:
            cb = ttk.Checkbutton(checkbox_frame, text=vuln, variable=self.vulnerability_vars[vuln], style='TCheckbutton')
            cb.pack(side=tk.LEFT, padx=(0, 20))

    def create_results_section(self, parent):
        """Create a section to display DNS checking results."""
        result_frame = ttk.Frame(parent)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))

        ttk.Label(result_frame, text="Results:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        # Scrollable text area to display results
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=20, bg='#1e1e1e', fg='#e0e0e0', font=('Roboto Mono', 11))
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Text tag styles for highlighting results
        self.result_text.tag_configure('domain', foreground='#00eeff', font=('Roboto Mono', 14, 'bold'))
        self.result_text.tag_configure('separator', foreground='#404040')
        self.result_text.tag_configure('green', foreground='#2ecc71')
        self.result_text.tag_configure('red', foreground='#e74c3c')
        self.result_text.tag_configure('yellow', foreground='#f39c12')
        self.result_text.tag_configure('summary', foreground='#f39c12', font=('Roboto Mono', 12, 'bold'))
        self.result_text.tag_configure('header', foreground='#3498db', font=('Roboto Mono', 12, 'bold'))

    def create_action_buttons(self, parent):
        """Create action buttons for saving, clearing, searching, and sorting results."""
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=(30, 0))

        # Button to save report
        ttk.Button(action_frame, text="Save Report", command=self.save_report, style='TButton').pack(side=tk.LEFT)

        # Button to clear results
        ttk.Button(action_frame, text="Clear Results", command=self.clear_results, style='TButton').pack(side=tk.LEFT, padx=(15, 0))

        # Button to search in results
        ttk.Button(action_frame, text="Search", command=self.search_results, style='TButton').pack(side=tk.LEFT, padx=(15, 0))

        # Button to sort vulnerable domains
        ttk.Button(action_frame, text="Sort Vulnerable Domains", command=self.sort_vulnerable_domains, style='TButton').pack(side=tk.LEFT, padx=(15, 0))

    def check_dns(self):
        """Perform DNS check for the entered domain."""
        domain = self.domain_entry.get().strip()

        # Validate domain input
        if not domain:
            messagebox.showwarning("Input Error", "Please enter a domain name.")
            return
        if not self.is_valid_domain(domain):
            messagebox.showerror("Invalid Domain", f"'{domain}' is not a valid domain name.")
            return

        # Clear previous results and start DNS check in a new thread
        self.update_queue.put(('delete', '1.0', tk.END))
        threading.Thread(target=self.check_domain_dns, args=(domain,), daemon=True).start()

    def is_valid_domain(self, domain):
        """Check if the domain is valid using a regex."""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None

    def check_domain_dns(self, domain):
        """Perform DNS checks for the specified domain based on selected vulnerabilities."""
        results = {}
        for vuln in self.vulnerabilities:
            if self.vulnerability_vars[vuln].get():
                if vuln == 'DKIM':
                    results[vuln] = self.check_dkim(domain)
                elif vuln == 'DMARC':
                    results[vuln] = self.dns_query('TXT', f"_dmarc.{domain}", vuln)
                else:
                    results[vuln] = self.dns_query(vuln, domain, vuln)

        self.update_result_description(domain, results)

    def dns_query(self, record_type, domain, label):
        """Perform a DNS query for a specific record type."""
        try:
            records = dns.resolver.resolve(domain, record_type)
            return f"Record Found: {', '.join([str(record) for record in records])}", True
        except dns.resolver.NoAnswer:
            return f"No Record Found", False
        except dns.resolver.NXDOMAIN:
            return f"Domain does not exist", False
        except Exception as e:
            return f"Error: {str(e)}", False

    def check_dkim(self, domain):
        """Check for DKIM records on the domain."""
        selectors = ['default', 'google', 'dkim', 'mail', 'k1']
        for selector in selectors:
            try:
                dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for record in dkim_records:
                    if "v=DKIM1" in str(record):
                        return f"Record Found (selector: {selector}): {record}", True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                return f"Error: {str(e)}", False
        return "No Record Found", False

    def update_result_description(self, domain, results):
        """Update the results section with DNS check details."""
        vulnerabilities = []

        self.update_queue.put(('insert', tk.END, f"DNS Check Results for ({domain})\n", 'domain'))

        for label, (result, found) in results.items():
            self.update_queue.put(('insert', tk.END, f"{label}:\n", 'header'))
            status = "✓ Secure" if found else "✗ Vulnerable"
            status_tag = 'green' if found else 'red'
            self.update_queue.put(('insert', tk.END, f"  Status: {status}\n", status_tag))
            self.update_queue.put(('insert', tk.END, f"  Details: {result}\n\n"))

            if not found:
                vulnerabilities.append(label)

        self.update_queue.put(('insert', tk.END, "Summary:\n", 'summary'))
        if vulnerabilities:
            self.update_queue.put(('insert', tk.END, f"  Vulnerabilities detected: {', '.join(vulnerabilities)}\n", 'red'))
            self.update_queue.put(('insert', tk.END, "  Recommendation: Address the identified vulnerabilities to improve DNS security.\n", 'yellow'))
        else:
            self.update_queue.put(('insert', tk.END, "  No vulnerabilities detected. Good DNS security practices are in place.\n", 'green'))

        self.update_queue.put(('insert', tk.END, "\n" + "="*50 + "\n\n", 'separator'))

    def load_domains(self):
        """Load domains from a text file."""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])

        if file_path:
            with open(file_path, 'r') as file:
                domains = [domain.strip() for domain in file.readlines() if domain.strip()]

            self.update_queue.put(('delete', '1.0', tk.END))
            self.is_batch_processing = True
            threading.Thread(target=self.process_domains, args=(domains,), daemon=True).start()

    def process_domains(self, domains):
        """Process DNS checks for multiple domains."""
        total_domains = len(domains)
        for i, domain in enumerate(domains, 1):
            if self.is_valid_domain(domain):
                self.check_domain_dns(domain)
            else:
                self.update_queue.put(('insert', tk.END, f"Skipping invalid domain: {domain}\n", 'red'))

        self.is_batch_processing = False

    def save_report(self):
        """Save the DNS check results to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], initialfile="x3_dns_report.txt")
        if file_path:
            content = self.result_text.get('1.0', tk.END)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"X3-DNS Checker Report\nGenerated on: {datetime.datetime.now()}\n\n")
                f.write(content)
            messagebox.showinfo("Report Saved", f"Report saved to {file_path}")

    def clear_results(self):
        """Clear the results and input fields."""
        self.domain_entry.delete(0, tk.END)
        self.update_queue.put(('delete', '1.0', tk.END))

    def search_results(self):
        """Search for a term in the results."""
        search_term = self.domain_entry.get().strip()
        if search_term:
            # Remove any previous highlights
            self.result_text.tag_remove("search", '1.0', tk.END)

            # Search and highlight matches
            start_pos = '1.0'
            while True:
                start_pos = self.result_text.search(search_term, start_pos, stopindex=tk.END)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(search_term)}c"
                self.result_text.tag_add("search", start_pos, end_pos)
                self.result_text.tag_configure("search", background="yellow", foreground="black")
                start_pos = end_pos

    def sort_vulnerable_domains(self):
        """Sort and display only vulnerable domains from the results."""
        content = self.result_text.get('1.0', tk.END)
        sorted_results = []

        # Extract vulnerable domain results
        lines = content.split('\n')
        for i in range(len(lines)):
            if "✗ Vulnerable" in lines[i]:
                sorted_results.append("\n".join(lines[i-1:i+2]))

        if sorted_results:
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert(tk.END, "\n".join(sorted_results), 'red')

    def check_updates(self):
        """Check for queued updates and apply them to the result box."""
        try:
            while True:
                method, *args = self.update_queue.get_nowait()
                if method == 'insert':
                    self.result_text.insert(*args)
                elif method == 'delete':
                    self.result_text.delete(*args)
                self.update_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.after(100, self.check_updates)

    def on_closing(self):
        """Handle window close event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.destroy()

if __name__ == "__main__":
    app = DNSCheckerApp()
    app.mainloop()
