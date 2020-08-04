# Pets AP13 - Demonstrator

Das Ziel des Demonstrators ist es, die in EAST-ADL modellierten Sicherheitsmaßnahmen umzusetzen.
Als Beispiel wurde der Use-Case "Firmware-Update eines Steuergeräts über den CAN Bus" gewählt.
Bei der Modellierung mit EAST-ADL wurden folgende Schwachstellen identifiziert:

* Auslesen der Firmware während des Update Prozesses
* Manipulierte Firmware auf dem Steuergerät installieren 

Um diese Sicherheitslücken zu schließen implementiert der Demonstrator folgende Sicherheitsmechanismen:

* Verschlüsselung der Datenübertragung (AES-256)
* Firmware-Signatur (SHA-256 RSA-2048)
* UDS Security Access

Hierbei werden zwei Steuergeräte (*ova_controller.py* / *update_controller.py*) simuliert, die mit den im Automobilbereich verwendeten Protokollen ISO-TP und UDS kommunizieren. Dabei wartet der Update Controller ständig auf eine neue Firmware, welche vom OVA Controller übermittelt wird. Dieser sendet dafür das Skript *firmware.sh* im Ordner *firmware_gateway*, das nach der Übertragung ins *firmware_ecu* Verzeichnis geschrieben wird. Die übertragene Firmware wird vom Bash Skript *selfdriving_controller.sh* permanent ausgeführt.


# Usage

Um die verschiedenen Sicherheitsmechanismen zu veranschaulichen...


Beide Skripte (ova_controller.py/update_controller.py) müssen mit identischen Flags gestartet werden.
update_controller.py 

