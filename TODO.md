# TODO LIST:
In no specific order

- [ ] ping scan
- [ ] service scan ?
- [ ] os detection
- [ ] mac address finding
- [ ] improve most_used_ports()
- [ ] remove nmap's dependences
- [ ] IPv6 support
- [ ] fixe all warnings/errors found by static analysis tools like pycodestyle, mypy, pylint
- [ ] run security tools like (FIXME)
- [ ] make tests
- [ ] make docs/wiki
- [ ] fixe all FIXME and TODO in code
- [ ] make function docstring
- [ ] refactor all the code with OOP
- raise PermissionError (root permission) for all scan except connect scan
- supprimer le init() des scans avec un moyen plus correct


## Some documentation:
* Threading: 
    * https://www.ploggingdev.com/2017/01/multiprocessing-and-multithreading-in-python-3/
    * https://pymotw.com/3/threading/
    * https://www.tutorialspoint.com/python3/python_multithreading.htm
    * http://www.tcpcatcher.org/port_scanner.php
    * https://gist.github.com/presci/2661576


## Some interesting Nmap option:

TARGET SPECIFICATION:

HOST DISCOVERY:

SCAN TECHNIQUES:
* -sY (SCTP INIT scan)
* -sW (TCP Window scan)
* -sM (TCP Maimon scan)
* -sZ (SCTP COOKIE ECHO scan)
* -sI <zombie host>[:<probeport>] (idle scan)
* -sO (IP protocol scan)
* -b <FTP relay host> (FTP bounce scan)

PORT SPECIFICATION AND SCAN ORDER:

SERVICE/VERSION DETECTION:
* -sV: Probe opened ports to determine service/version info

SCRIPT SCAN:

OS DETECTION:
* -O: Enable OS detection

TIMING AND PERFORMANCE:

FIREWALL/IDS EVASION AND SPOOFING:

OUTPUT:

MISC:
* -A: Enable OS detection, version detection, script scanning, and traceroute
