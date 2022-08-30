from itertools import count
import socket
from time import perf_counter
from threading import Thread
from queue import Queue, Empty
import threading
import argparse
import nmap
import sqlite3
import csv
import os
from tkinter import ttk
from tkinter import *
import sys

delta1 = perf_counter()

class SqliteDB:
    """sqlite3 database"""

    DB_LOC = '/tmp/phs.db'

    def __init__(self): 
        self.connection = sqlite3.connect(self.DB_LOC)
        self.cu = self.connection.cursor()

    def select(self, command):
        self.cu.execute(command)
        result = self.cu.fetchall()
        return result
    
    def insert(self, command):
        self.cu.execute(command)

    def insert_many(self, command, iter):
        self.cu.execute(command, iter)

    def write_close(self):
        self.connection.commit()
        self.connection.close()

x = SqliteDB()


# initiate an empty list where open ports will be stored
open_ports = []

# add the ports range(default is 1-65535) to the queue
def port_scan_get(queue):
    for port in ports:
        queue.put(port)

# gets items from the queue and processes it
def port_scan_process(queue):
    while True:
        try:
            # get the item from the queue
            i = queue.get()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socketTimeout = 5
            s.settimeout(socketTimeout)
            result = s.connect_ex((host, i))
            # if the port is open, add it to the list
            if result == 0:
                open_ports.append(i)
            s.close()
        except Empty:
            continue
        else:
            queue.task_done()

def nmap_details():
    
    # scan the open ports and get the CSV file
    nm = nmap.PortScanner()
    for i in open_ports:
        nm.scan(host, str(i))
        csv_nmap_data = nm.csv()

        # save the CSV file locally under /tmp
        with open('/tmp/a.csv', 'a', newline='') as file:
            file.write(csv_nmap_data)
        file.close()
    # get rid of the CSV header 
    with open('/tmp/a.csv', 'r') as inp, open('/tmp/b.csv', 'w') as out:
        writer = csv.writer(out)
        for row in csv.reader(inp, delimiter=';'):
            if row[2] != "hostname_type":
                writer.writerow(row)
    
    # insert the processed information into the nmp table
    with open('/tmp/b.csv') as file:
        reader = csv.reader(file)
        for i in reader:
            x.insert_many("INSERT INTO nmap VALUES (date('now'), time('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", i)

# define a tkinter based visual solution
def display_records():

    # define the title and style
    my_win = Tk()
    my_win.title('Port Multithread Scanner')
    #my_win.geometry('1366x768')
    style = ttk.Style()
    style.theme_use('default')

    # configure the colors
    style.configure("Treeview", background="#D3D3D3", foreground="black", rowheight=30, fieldbackground="#D3D3D3")
    style.map('Treemap', background=[('selected', "#798082")])

    # create a treeview frame
    tree_frame = Frame(my_win)
    tree_frame.pack(fill="both", expand=True, pady=15)

    # create the scrollbars, for X and Y axis
    tree_scroll = Scrollbar(tree_frame)
    tree_scroll.pack(side=RIGHT, fill=Y)    

    tree_scroll1 = Scrollbar(tree_frame, orient='horizontal')
    tree_scroll1.pack(side=BOTTOM, fill=X)

    # create the treeview
    tr = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set, selectmode="extended")
    tr = ttk.Treeview(tree_frame, xscrollcommand=tree_scroll1.set, selectmode="extended")
    tr.pack()   

    # configure the scrollbar   
    tree_scroll.config(command=tr.yview)
    tree_scroll1.config(command=tr.xview)

    x.select("SELECT * FROM nmap;")

    # format the columns
    tr['columns'] = ("Date", "Time", "Host", "Hostname", "Hostname Type", "Protocol", "Port", "Name", "State", "Product", "Extra Info", "Reason", "Version", "Conf", "Cpe")
    tr.column("#0", width=0, stretch=NO)
    tr.column("Date", anchor=W, width=90)
    tr.column("Time", anchor=W, width=90)
    tr.column("Host", anchor=W, width=100)
    tr.column("Hostname", anchor=W, width=130)
    tr.column("Hostname Type", anchor=CENTER, width=60)
    tr.column("Protocol", anchor=CENTER, width=70)
    tr.column("Port", anchor=CENTER, width=60)
    tr.column("Name", anchor=CENTER, width=70)
    tr.column("State", anchor=CENTER, width=60)
    tr.column("Product", anchor=W, width=130)
    tr.column("Extra Info", anchor=W, width=120)
    tr.column("Reason", anchor=W, width=70)
    tr.column("Version", anchor=W, width=100)
    tr.column("Conf", anchor=CENTER, width=50)
    tr.column("Cpe", anchor=W, width=100)

    # create the headings
    tr.heading("Date", text="Date", anchor=W)
    tr.heading("Time", text="Time", anchor=W)
    tr.heading("Host", text="Host", anchor=W)
    tr.heading("Hostname", text="Hostname", anchor=W)
    tr.heading("Hostname Type", text="Hostname Type", anchor=W)
    tr.heading("Protocol", text="Protocol", anchor=W)
    tr.heading("Port", text="Port", anchor=W)
    tr.heading("Name", text="Name", anchor=W)
    tr.heading("State", text="State", anchor=W)
    tr.heading("Product", text="Product", anchor=W)
    tr.heading("Extra Info", text="Extra Info", anchor=W)
    tr.heading("Reason", text="Reason", anchor=W)
    tr.heading("Version", text="Version", anchor=W)
    tr.heading("Conf", text="Conf", anchor=W)
    tr.heading("Cpe", text="Cpe", anchor=W)

    # add the data to the screen
    global counter
    counter = 0

    for record in x.select("SELECT * from nmap;"):
        tr.insert(parent='', index='end', iid=counter, text='', values=(record[0], record[1], record[2], record[3], 
        record[4], record[5], record[6], record[7], record[8], record[9], record[10], record[11], record[12], record[13], record[14]))
        counter += 1

    my_win.mainloop()

def main():

    # check if the remote server is up

    check_up = os.system("ping -c 1 " + host + " >/dev/null 2>&1")
    if check_up == 0:
        pass
    else:
        print("The host in unreachable...")
        sys.exit()

    queue = Queue()

    # create a thread and start it
    t_get = Thread(target=port_scan_get, args=(queue,))
    t_get.start()

    # create 4 threads and start them; can be customized
    # ideally 2 threads per core
    t_process = [threading.Thread(target=port_scan_process, args=(queue,), daemon=True) for _ in range(3)]
    for t in t_process:
        t.start()

    # wait for all ports to be added to the queue
    t_get.join()
    # wait for the queue to be completed
    queue.join()

    x.insert(""" CREATE TABLE if not exists nmap (
        d real,
        t real,
        host integer,
        hostname text,
        hostname_type text,
        protocol text,
        port integer,
        name text,
        state text,
        product text,
        extrainfo text,
        reason text,
        version integer,
        conf integer,
        cpe text)
    """)

    nmap_details()

    # remove the CSV files previously created
    os.remove('/tmp/a.csv')
    os.remove('/tmp/b.csv')


if __name__ == '__main__':

    # create the parser
    parser = argparse.ArgumentParser(description="Port Multithreading Scanner")
    # add the arguments
    parser.add_argument("host", help="Host to scan")
    parser.add_argument("--ports", "-p", dest="p_range", default="1-65535", help="Port range to scan, default range 1-65535")
    parser.add_argument("--gui", "-g", dest="command", action="store_const", const="gui", help="Display the SQL DB records in Tkinter")
    # execute the parse_args() method
    args = parser.parse_args()
    host, p_range = args.host, args.p_range
    # customize the port range(default is 1-65353)
    s_port, e_port = p_range.split("-")
    s_port, e_port = int(s_port), int(e_port)

    ports = [ p for p in range(s_port, e_port)]

    #host_up()
    main()

    delta2 = perf_counter()

    # if --gui/-g is given, the tkinter interface will open up
    if args.command == "gui":
        display_records()

    # commit and close the DB
    x.write_close()

print(f"{len(open_ports)} ports open: {open_ports}")
print("Scan completed in: ", float(delta2 - delta1))
print("The entries were added to the SQL DB in " + SqliteDB.DB_LOC)