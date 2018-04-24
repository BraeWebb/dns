import tkinter as tk
from tkinter import messagebox as alert

from dns import DNSReader, DomainType


class IPInput(tk.Frame):
    def __init__(self, master, load_func=None, **kwargs):
        super().__init__(master, **kwargs)

        self._load_callback = load_func

        self._label = tk.Label(self, text="Enter A Hostname")
        self._label.pack()

        self._field = tk.Entry(self, width=40)
        self._field.bind("<Return>", self._submit)
        self._field.pack(side=tk.LEFT)

        self._submit_button = tk.Button(self, text="Submit", command=self._submit)
        self._submit_button.pack(side=tk.LEFT)

    def _submit(self, _=None):
        hostname = self._field.get()
        if self._load_callback is not None:
            self._load_callback(hostname)
        # self._field.config(state=tk.DISABLED)
        # self._submit_button.config(state=tk.DISABLED)
        self.focus()

    def enable(self, hostname=None):
        if hostname is not None:
            self._field.delete(0, tk.END)
            self._field.insert(0, hostname)


class IPColumn(tk.Frame):
    def __init__(self, master, label, width, callback=None, **kwargs):
        super().__init__(master, **kwargs)

        self._callback = callback

        frame = tk.Label(self, text=label, bd=1, relief=tk.SUNKEN, width=width)
        frame.grid(row=0, column=0)

        self._ips = tk.Listbox(self, width=width, bd=1, relief=tk.SUNKEN)
        self._ips.grid(row=1, column=0)

        self._ips.bind("<Double-Button-1>", self.select_ip)

        self._data = []

    def load(self, ips):
        self._ips.delete(0, tk.END)

        self._data = ips

        for ip in ips:
            self._ips.insert(tk.END, ip)

    def select_ip(self, event=None):
        sel = self._ips.curselection()

        if sel:
            if self._callback:
                self._callback(self._data[sel[0]-1])


class IPGrid(tk.Frame):
    def __init__(self, master, columns, **kwargs):
        super().__init__(master, **kwargs)

        self._master = master

        self._columns = {}

        for i, (name, width) in enumerate(columns.items()):
            self._columns[name] = IPColumn(self, name, width, master.load_ip)
            self._columns[name].grid(row=0, column=i)

    def load(self, data):
        for name, records in data.items():
            self._columns[name].load(records)


class MailGrid(tk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self._columns = {}

        columns = {
            "IPv4 Addresses": 20,
            "IPv6 Addresses": 40,
        }

        for i, (name, width) in enumerate(columns.items()):
            self._columns[name] = IPColumn(self, name, width, master.load_ip)
            self._columns[name].grid(row=0, column=i)

    def load(self, data):
        for name, records in data.items():
            self._columns[name].load(records)


class DNSWindow(tk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self._input = IPInput(self, load_func=self.load_ip)
        self._input.pack(side=tk.TOP)

        self._cname = tk.Label(self, text="Canonical Name:")
        self._cname.pack()

        data = {
            "IPv4 Addresses": 20,
            "IPv6 Addresses": 40,
        }

        mail_columns = {
            "MX Address": 40,
            "IPv4 Addresses": 20,
            "IPv6 Addresses": 40
        }

        self._results = IPGrid(self, data)
        self._results.pack(side=tk.TOP, padx=30)

        self._mail_results = IPGrid(self, mail_columns)
        self._mail_results.pack(side=tk.TOP, padx=30, pady=30)

    def load_ip(self, hostname):
        packet = DNSReader(hostname)
        packet.add_query(DomainType.A)
        packet.add_query(DomainType.AAAA)
        packet.add_query(DomainType.MX)

        answers = packet.answers

        if len(answers) == 0:
            alert.showinfo("No Results", f"No results found for {hostname}")

        data = {
            "IPv4 Addresses": answers.get(DomainType.A, ["N/A"]),
            "IPv6 Addresses": answers.get(DomainType.AAAA, ["N/A"]),
        }
        self._input.enable(hostname=hostname)
        self._results.load(data)

        mails = {}

        for mail in answers.get(DomainType.MX, []):
            mx_packet = DNSReader(mail)
            mx_packet.add_query(DomainType.A)
            mx_packet.add_query(DomainType.AAAA)

            mx_answers = mx_packet.answers

            mails[mail] = (
                mx_answers.get(DomainType.A, ["N/A"]).pop(),
                mx_answers.get(DomainType.AAAA, ["N/A"]).pop()
            )

        data = {
            "MX Address": mails.keys(),
            "IPv4 Addresses": [x[0] for x in mails.values()],
            "IPv6 Addresses": [x[1] for x in mails.values()],
        }

        self._mail_results.load(data)


        self._cname.config(text=f"Canonical Name: {', '.join(answers.get(DomainType.CNAME, []))}")


def main():
    root = tk.Tk()
    root.title("DNS Viewer")
    window = DNSWindow(root)
    window.pack()
    root.mainloop()


if __name__ == "__main__":
    main()