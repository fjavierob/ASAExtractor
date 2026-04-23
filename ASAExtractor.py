"""
ASAExtractor - Cisco ASA configuration extractor and normalizer
Tested against ASA 9.16(4)
"""

import json
import os


class ASAExtractor:

    def __init__(self, filename: str):
        """
        Load and validate the ASA config file.

        Args:
            filename: Path to the ASA configuration file.

        Raises:
            FileNotFoundError: If the file does not exist at the given path.
            ValueError: If the file is empty or does not appear to be an ASA config.
            PermissionError: If the file cannot be read due to OS permissions.
        """
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Config file not found: '{filename}'")

        if not os.path.isfile(filename):
            raise ValueError(f"Path is not a file: '{filename}'")

        if not os.access(filename, os.R_OK):
            raise PermissionError(f"Cannot read file (check permissions): '{filename}'")

        with open(filename, "r", encoding="utf-8", errors="replace") as f:
            self.lines = f.readlines()

        if not self.lines:
            raise ValueError(f"Config file is empty: '{filename}'")

        # Lightweight ASA sanity check — at least one of these should appear
        # in any real ASA config. Avoids silently parsing a wrong file.
        asa_indicators = {"access-list", "interface", "nameif", "object", "access-group"}
        joined = " ".join(self.lines[:300])  # check only the first 300 lines for speed
        if not any(indicator in joined for indicator in asa_indicators):
            raise ValueError(
                f"File does not appear to be a Cisco ASA configuration: '{filename}'"
            )

        self.filename = filename

        # Extracted and normalized data — populated by extract_* methods
        self.protocol_objects: list[dict]   = []
        self.protocol_groups: list[dict]    = []
        self.network_objects: list[dict]    = []
        self.network_groups: list[dict]     = []
        self.service_objects: list[dict]    = []
        self.service_groups: list[dict]     = []
        self.firewall_rules: list[dict]     = []

    # ------------------------------------------------------------------
    # Extraction methods
    # ------------------------------------------------------------------

    def extract_protocols(self):
        """
        Extract protocol objects and object-groups from the config.
        Populates self.protocol_objects and self.protocol_groups.
        """
        raise NotImplementedError

    def extract_networks(self):
        """
        Extract network objects and object-groups from the config.
        Populates self.network_objects and self.network_groups.
        """
        raise NotImplementedError

    def extract_services(self):
        """
        Extract service objects and object-groups from the config.
        Populates self.service_objects and self.service_groups.
        """
        raise NotImplementedError

    def extract_aces(self):
        """
        Extract ACEs from the config and normalize them as firewall rules.
        Depends on extract_protocols(), extract_networks(), extract_services()
        having been called first.
        Populates self.firewall_rules.
        """
        raise NotImplementedError

    def extract_all(self):
        """
        Run all extraction methods in the correct dependency order.
        Safe entry point for full extraction.
        """
        raise NotImplementedError

    def to_json(self, output_dir: str = "."):
        """
        Serialize all extracted data to JSON files in output_dir.
        One file per object/rule type.
        """
        raise NotImplementedError


# ------------------------------------------------------------------
# Quick smoke test
# ------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    SAMPLE = """\
interface GigabitEthernet0/0
 nameif outside
 security-level 0
!
object network WEB_SERVER
 host 192.168.15.20
object-group network INTERNAL_NETS
 network-object 192.168.0.0 255.255.0.0
access-list outside extended permit tcp any4 host 192.168.15.20 eq 443
access-group outside in interface outside
"""
    # Write to a temp file and instantiate
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as tf:
        tf.write(SAMPLE)
        tmp_path = tf.name

    try:
        asa = ASAExtractor(tmp_path)
        print(f"OK — loaded {len(asa.lines)} lines from '{asa.filename}'")
        print(f"Attributes: protocol_objects={asa.protocol_objects}, "
              f"network_objects={asa.network_objects}, "
              f"firewall_rules={asa.firewall_rules}")

        # Test FileNotFoundError
        try:
            ASAExtractor("/nonexistent/path/config.cfg")
        except FileNotFoundError as e:
            print(f"OK — FileNotFoundError: {e}")

        # Test empty file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as ef:
            empty_path = ef.name
        try:
            ASAExtractor(empty_path)
        except ValueError as e:
            print(f"OK — ValueError (empty): {e}")

        # Test wrong file content
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as wf:
            wf.write("hello world\nthis is not a config\n")
            wrong_path = wf.name
        try:
            ASAExtractor(wrong_path)
        except ValueError as e:
            print(f"OK — ValueError (wrong content): {e}")

    finally:
        os.unlink(tmp_path)