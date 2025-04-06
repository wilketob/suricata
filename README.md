# Suricata Rules for File Spoofing Detection

## Solution Approach

The Suricata rules provided here aim to detect and optionally block such attacks by analyzing network traffic. The core mechanism is based on **detecting inconsistencies between the declared file extension** of a transferred file and its **actual file signature (Magic Bytes)** at the beginning of the file.

## Included Rules (Example: `FileSpoof.rules`)

The primary rule set (`FileSpoof.rules`) contains rules for detecting various file spoofing scenarios, including:

* **Disguised Executables:** Detects files with EXE/DLL Magic Bytes (`4D 5A`) but have a different file extension (e.g., `.png`, `.jpg`, `.pdf`, etc.).
* **Disguised Archives:** Detects files with ZIP (`50 4B`) or RAR (`52 61 72 21`) Magic Bytes but have a non-matching file extension.
* **Invalid Image/PDF Files:** Detects files with extensions like `.png`, `.jpg`, or `.pdf` whose Magic Bytes at the beginning of the file do *not* match the expected signatures (i.e., checks if a file claiming to be a PNG actually starts with the PNG signature).

The rules utilize specific Suricata keywords such as `content` (with `offset` and `depth` for targeted Magic Byte checks), `file.name`, `flowbits` (for linking conditions), and `file.data` (for correct analysis of the file payload),

## Integration with OPNsense

The rules were primarily developed and tested for use with Suricata within the OPNsense firewall environment. Here’s how you can integrate them:

1.  **Deploy Rule File:** Download the `.rules` file from this repository and place it on a web server accessible by your OPNsense instance (e.g., `http://<your_server>/suricata/FileSpoof.rules`).
2.  **Create Metadata XML:** Create an XML file on your OPNsense firewall in the directory `/usr/local/opnsense/scripts/suricata/metadata/rules/`. Name the file, for example, `wilketob-filespoof.xml`. Adjust the content according to your setup (especially `location url` and `prefix`):

    ```xml
    <?xml version="1.0"?>
    <ruleset documentation_url="[https://github.com/wilketob/suricata](https://github.com/wilketob/suricata)">
        <location url="http://<your_server>/suricata" prefix="wilketob"/>
        <files>
            <file description="FileSpoof Rules by T. Wilke" url="inline::FileSpoof.rules">FileSpoof.rules</file>
            </files>
    </ruleset>
    ```

3.  **Add Rule Set in OPNsense:**
    * Go to the OPNsense web interface: `Services -> Intrusion Detection -> Administration`.
    * Navigate to the `Download` tab.
    * Click `Download & Update Rules`. The new rule set (e.g., "wilketob/FileSpoof Rules by T. Wilke") should now appear in the list. Enable it (check the box) and click `Download & Update Rules` again.
4.  **Enable and Configure Rules:**
    * Navigate to the `Rules` tab.
    * Search/filter for the rule set (e.g., by SID `1000xxx` or description).
    * Enable the desired rules.
    * Using the edit icon, you can adjust the default action of the rule (e.g., change from `alert` to `drop` to actively block traffic if IPS is enabled). Ensure IPS mode is enabled under `Settings` if you intend to use `drop` actions.

## Important Notes

* **Testing:** These rules were evaluated in a specific test environment. Test them thoroughly in your own setup before deploying them productively with `drop` actions to identify potential false positives.
* **Performance:** Depending on your network traffic and hardware, enabling additional rules might impact Suricata's performance.
* **Encrypted Traffic:** These rules primarily rely on analyzing unencrypted traffic (e.g., HTTP). Analyzing encrypted traffic (HTTPS) requires appropriate TLS/SSL inspection configured in Suricata/OPNsense, which has additional configuration and performance implications.
* **Evolution:** These rules represent the state of development as of 2025. New attack techniques may require adjustments.


## Author

* **Tobias Wilke** - ([@wilketob](https://github.com/wilketob))
