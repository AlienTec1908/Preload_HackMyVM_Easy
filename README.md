# Preload - HackMyVM (Easy)

![Preload.png](Preload.png)

## Übersicht

*   **VM:** Preload
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Preload)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-04-20
*   **Original-Writeup:** https://alientec1908.github.io/Preload_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Preload" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer Server-Side Template Injection (SSTI)-Schwachstelle in einer Python/Flask-Webanwendung, die auf Port 50000 lief. Durch Injektion eines präparierten Payloads in den `cmd`-Parameter konnte eine PHP-Reverse-Shell heruntergeladen und ausgeführt werden, was zu einer Shell als Benutzer `paul` führte. Die finale Rechteausweitung zu Root gelang durch Ausnutzung einer unsicheren `sudo`-Konfiguration, die dem Benutzer `paul` erlaubte, mehrereAbs Standardbefehle (`cat`, `cut` etc.) als Root ohne Passwort auszuführen und – entscheidend – die Umgebungsvariable `olut, Ben! Hier ist der Entwurf für das README zur "Preload"-Maschine.

```markdown
# Preload - HackMyVM (Easy)

![Preload.png](Preload.png)

## Übersicht

*   **LD_PRELOAD` zu erhalten (`env_keep+=LD_PRELOAD`). Durch Erstellen einer benutzerdefinierten Shared Library (`shellVM:** Preload
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Preload)
*   **Schwierigkeit:** Easy
*   **Autor.so`), die beim Laden eine Root-Shell startet, und anschließendes Ausführen eines der erlaubten `sudo`-Befehle mit der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-04-20
*   **Original-Writeup:** https://alientec1908.github.io/Preload_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge gesetzter `LD_PRELOAD`-Variable, konnte Root-Zugriff erlangt werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor war es, Root-Rechte auf der Maschine "Preload" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer Server-Side Template Injection (SSTI)-Schwachstelle in einer Python/Flask-Webanwendung, die auf Port übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `telnet`
*   `curl`
*   `wfuzz`
*   Python3 (`http.server`, `pty` Modul)
*   `nc` (netcat)
* 50000 lief (nachdem der ursprüngliche Port 5000 einen Fehler zeigte, der auf den Port 50000 hinwies). Durch einen präparierten GET-Request mit einem SSTI-Payload im   `php` (für Reverse Shell)
*   `stty`
*   `sudo`
*   `nano` (oder `vi`)
*   `gcc`
*   Standard Linux-Befehle (`cat`, `cut`, `grep`, `tail`, `head`, `ss`, `ls`, `mkdir`, `wget`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Preload" gliederte sich `cmd`-Parameter konnte eine PHP-Reverse-Shell heruntergeladen und ausgeführt werden, was zu einer Shell als Benutzer `paul` führte. Die finale Rechteausweitung zu Root gelang durch Ausnutzung einer unsicheren `sudo`-Kon in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.129) mit `arp-scan` identifiziert. Hostname `preload.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.4p1), Port 80 (HTTP, Nginx 1.1figuration. Der Benutzer `paul` durfte mehrere Standardbefehle als `root` ohne Passwort ausführen, und entscheidend war, dass die Umgebungsvariable `LD_PRELOAD` beim `sudo`-Aufruf erhalten blieb (`env_keep+=LD_PRELOAD`). Durch Erstellen einer bösartigen Shared Library (`.so`-Datei),8.0) und Port 5000 (LANDesk remote management? - später als fehlerhafter Python/Flask-Dienst identifiziert).
    *   `gobuster` und `nikto` auf Port 8 die beim Laden eine Root-Shell startet, und anschließendes Ausführen eines der erlaubten `sudo`-Befehle mit gesetzter `LD_PRELOAD`-Variable wurde Root-Zugriff erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture0 zeigten keine relevanten Funde außer der Standard-Nginx-Seite.
    *   Eine `telnet`-Verbindung zu Port 5000 lieferte einen Python-Traceback, der eine Flask-Anwendung (`/home/paul/code.py`) offenbarte, die versuchte, auf Port 50000 zu la-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortuschen, aber an `OSError: [Errno 98] Address already in use` scheiterte.
    *   Einungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `telnet`
*   `curl`
*   `wfuzz`
*   Python3 (`http.server`, `pty` Modul)
*   `nc` (netcat)
* `curl`-Aufruf auf `http://192.168.2.129:50000/` lieferte einen "Internal Server Error".
    *   `wfuzz` auf Port 50000   `php` (für Reverse Shell)
*   `stty`
*   `sudo`
*   `nano` (oder `vi`)
*   `gcc`
*   Standard Linux-Befehle (`cat`, `cut fand den GET-Parameter `cmd`.

2.  **Initial Access (SSTI zu RCE als `paul`):**
    *   Mittels `curl "http://192.168.2.129:50000/?cmd=\{\{request.application.__globals__.__builtins__.__import__(%27os`, `grep`, `tail`, `head`, `ss`, `ls`, `mkdir`, `wget`, `id`, `export`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Preload" gliederte sich in%27).popen('id').read()\}\}"` wurde eine Server-Side Template Injection (SSTI)- folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.129) mit `arp-scan` identifiziert. Hostname `preload.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.4p1), Port 80 (HTTP, Nginx 1.1Schwachstelle (Jinja2/Flask) im `cmd`-Parameter bestätigt. Der Befehl wurde als Benutzer `paul` ausgeführt.
    *   Über die SSTI wurde mittels `wget` eine PHP-Reverse-Shell-Datei (`r`) vom Angreifer-Server8.0) und Port 5000 (als "landesk-rc" identifiziert).
    *   `gobuster` und `nikto` auf Port 80 zeigten keine signifikanten Funde außer einer Standard-Nginx-Seite.
    *    (Python `http.server`) nach `/tmp/reverse.php` auf dem Zielsystem heruntergeladen.
    *   Die `/tmp/reverse.php`-Datei wurde mittels SSTI und `php -f /tmp/reverse.php` ausgeführtEin `telnet`-Versuch auf Port 5000 lieferte einen Python-Traceback einer Flask-Anwendung (`/home/paul/code.py`), die versuchte, auf Port 50000 zu lauschen,.
    *   Eine Reverse Shell als Benutzer `paul` wurde auf einem Netcat-Listener (Port 9001) empfangen und stabilisiert.
    *   Die User-Flag (`52f83ff6877e42f613 aber mit "Address already in use" fehlschlug. Der Benutzer `paul` wurde dadurch bekannt.
    *   `wfuzz` auf `http://192.168.2.129:50000/` fandbcd2444c22528c`) wurde in `/home/paul/us3r.txt` gefunden.

3.  **Privilege Escalation (von `paul` zu `root` via `LD_PRELOAD`):**
    *   `sudo -l` als `paul` zeigte, dass mehrere Standardbefehle (`cat`, `cut den GET-Parameter `cmd`.

2.  **Initial Access (SSTI zu RCE als `paul`):**
    *   Mittels `curl "http://192.168.2.129:50000/?cmd=\{\`, `grep`, `tail`, `head`, `ss`) als `root` ohne Passwort ausgeführt werden durften und die Umgebungsvariable `LD_PRELOAD` erhalten blieb (`env_keep+=LD_PRELOAD`).
    *   Eine C-Datei (`shell.c`) wurde in `/tmp` auf dem Zielsystem erstellt, die eine `_init()`-Funktion enthielt, welche `setgid(0); setuid(0); system("/bin/sh");` ausführt.
    *{request.application.__globals__.__builtins__.__import__(%27os%27).popen('id').read()\}\}"` wurde eine Server-Side Template Injection (SSTI)-Schwachstelle in der Flask-Anwendung bestätigt. Der Befehl `id` wurde als Benutzer `paul` ausgeführt.
    *   Über die SSTI-Schwachstelle wurde mit `wget` eine PHP-Reverse-Shell-Datei (`r`) vom Angreifer-Server nach `/tmp/reverse   Der C-Code wurde mit `gcc -fPIC -shared -o shell.so shell.c -nostartfiles` zu einer Shared Library (`shell.so`) kompiliert.
    *   Durch Ausführen von `sudo LD_PRELOAD=/tmp.php` auf das Zielsystem heruntergeladen.
    *   Die heruntergeladene PHP-Shell wurde via SSTI mit `php -f /tmp/reverse.php` ausgeführt.
    *   Eine Reverse Shell als Benutzer `paul` wurde auf einem Netcat-Listener (Port 9001) empfangen und stabilisiert.
    */shell.so /usr/bin/cat` (oder einem anderen erlaubten Befehl) wurde die `shell.so`-Bibliothek als `root` geladen. Die `_init()`-Funktion wurde ausgeführt und startete eine Root-Shell.
    *   Die Root-Flag (`09f7e02f1290be211   Die User-Flag (`52f83ff6877e42f613bcd2444c22528c`) wurde in `/home/paul/us3r.txt` gefunden.

3.  **Privilege Escalation (von `paul` zu `root` via `LD_PRELOAD`):**da707a266f153b3`) wurde in `/root/20o7.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Server-Side Template Injection (SSTI):** Eine Python/Flask-Anwendung war anfällig für SSTI, was Remote Code Execution (RCE) ermöglicht
    *   `sudo -l` als `paul` zeigte, dass mehrere Befehle (`cat`, `cut`, `grep`, `tail`, `head`, `ss`) als `root` ohne Passwort ausgeführt werden durften. Entscheidend war die Option `env_keep+=LD_PRELOAD`.
    *   Im Verzeichnis `/tmp` wurde eine C-e.
*   **Unsichere `sudo`-Konfiguration (`LD_PRELOAD`):** Die `sudoers`-Datei erlaubte das Erhalten der `LD_PRELOAD`-Umgebungsvariable beim Ausführen von Befehlen als `root`. Dies ermöglichte das Laden einer bösartigen Shared Library und somit die Ausführung von Code alsDatei (`shell.c`) erstellt, die eine `_init()`-Funktion enthielt, welche `setgid(0); setuid(0); system("/bin/sh");` aufruft.
    *   Diese Datei wurde mit `gcc -fPIC -shared -o shell.so shell.c -nostartfiles` zu einer Shared Library (`shell.so`) kompiliert.
    *   Durch Ausführen eines der erlaubten ` `root`.
*   **Informationslecks durch Fehlermeldungen:** Ein Python-Traceback auf Port 5000 enthüllte den Pfad zu einem Skript, den Benutzernamen `paul` und den eigentlichen Port (50000) der Anwendung.
*   **Dienste auf Nicht-Standard-Ports:** Die Flasksudo`-Befehle mit gesetzter `LD_PRELOAD`-Variable wurde die präparierte Library geladen und die `_init()`-Funktion als Root ausgeführt: `sudo LD_PRELOAD=/tmp/shell.so /usr/bin/cat`.
    *   Dies führte zu einer Root-Shell (`uid=0(root)`).
    *   Die Root-Flag (`09f7e02f1290be211da707a266f-Anwendung lief auf Port 50000.

## Flags

*   **User Flag (`/home/paul/us3r.txt`):** `52f83ff6877e42f613bcd2444c22528c`
*   **Root Flag (`/root/20o7.txt`):** `09f7e02f1290be21153b3`) wurde in `/root/20o7.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure (Traceback):** Ein Python-Traceback auf Port 5000 verriet den Pfad zu einem Anwendungsskript (`/home/paul/code.py`), den Benutzernamen `paul` und den eigentlich vorgesehenen Port (50000) der Flask-Anwendung.
*   **Server-Side Template Injection (S1da707a266f153b3`

## Tags

`HackMyVM`, `Preload`, `Easy`, `SSTI`, `Flask Exploit`, `LD_PRELOAD`, `sudo Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Nginx`
