"""
ASAExtractor - Cisco ASA configuration extractor and normalizer
Tested against ASA 9.16(4)
"""

import json
import logging
import os

logger = logging.getLogger(__name__)


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
        logger.info(f"Initializing ASAExtractor with file: '{filename}'")

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
        joined = " ".join(self.lines[:200])
        if not any(indicator in joined for indicator in asa_indicators):
            raise ValueError(
                f"File does not appear to be a Cisco ASA configuration: '{filename}'"
            )

        self.filename = filename
        logger.info(f"Successfully loaded {len(self.lines)} lines from '{filename}'")

        # Extracted and normalized data — populated by extract_* methods
        self.protocol_objects: list[dict] = []
        self.protocol_groups: list[dict] = []
        self.network_objects: list[dict] = []
        self.network_groups: list[dict] = []
        self.service_objects: list[dict] = []
        self.service_groups: list[dict] = []
        self.firewall_rules: list[dict] = []

    # ------------------------------------------------------------------
    # Extraction methods (to be implemented in subsequent steps)
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