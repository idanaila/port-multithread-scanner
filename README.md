# Port Multithread Scanner
Port scanner with DB and GUI

![pic1](https://user-images.githubusercontent.com/47727784/187430413-ff9dc40e-cc86-450b-8c63-029549e4d43d.png)

## Dependencies
```
nmap
```
## Functionality
```
Can be executed without specifing the port range and gui; by default is 1-65535
By adding the --gui while running the program will open the visual interface(see snapshot above)

$ python3 phs.py -h
usage: classes_phs.py [-h] [--ports P_RANGE] [--gui] host

Port Multithreading Scanner

positional arguments:
  host                  Host to scan

optional arguments:
  -h, --help            show this help message and exit
  --ports P_RANGE, -p P_RANGE
                        Port range to scan, default range 1-65535
  --gui, -g             Display the SQL DB records in Tkinter
  
$ python3 phs.py -p 1-100 192.168.0.1
2 ports open: [22, 80]
Scan completed in:  7.472748913998657
The entries were added to the SQL DB in /tmp/phs.db
```
