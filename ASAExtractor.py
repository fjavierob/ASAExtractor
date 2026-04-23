"""
ASAExtractor - Cisco ASA configuration extractor and normalizer
Tested against ASA 9.16(4)
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known protocol name → number map (IANA assigned)
# ---------------------------------------------------------------------------
PROTOCOL_NAMES = {
    "ip": 0, "icmp": 1, "igmp": 2, "ggp": 3, "ipip": 4, "tcp": 6,
    "egp": 8, "udp": 17, "hmp": 20, "xns-idp": 22, "rdp": 27,
    "idpr": 35, "rsvp": 46, "gre": 47, "esp": 50, "ah": 51,
    "skip": 57, "icmp6": 58, "eigrp": 88, "ospf": 89, "nos": 94,
    "pim": 103, "pcp": 108, "ipcomp": 108, "vrrp": 112, "l2tp": 115,
}

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
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_protocol(self, token: str) -> dict:
        """
        Normalize a protocol token (name or number) to a standard service dict.

        Named protocols  → {"predefined": True,  "name": "tcp"}
        Numeric protocols → {"predefined": False, "name": "6", "protocol_number": 6}
        """
        token_lower = token.lower()
        if token_lower in PROTOCOL_NAMES:
            return {"predefined": True, "name": token_lower}
        if token.isdigit():
            return {"predefined": False, "name": token, "protocol_number": int(token)}
        # Unknown name — treat as predefined (ASA may know it even if we don't)
        logger.warning(f"Unknown protocol token '{token}' — treating as predefined name")
        return {"predefined": True, "name": token_lower}

    def _get_block_lines(self, start_index: int) -> list[str]:
        """
        Return the indented sub-lines belonging to a block starting at start_index.
        Stops at the first non-indented, non-empty line after the header.
        """
        block = []
        for line in self.lines[start_index + 1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue
            if line[0] in (" ", "\t"):
                block.append(stripped)
            else:
                break
        return block

    def _iter_blocks(self, keyword: str, subtype: str = None):
        """
        Iterate over top-level config blocks matching a keyword and optional subtype.

        Yields (line_index, tokens, block_lines) for each matching block, where:
            line_index  — 0-based index of the block header line in self.lines
            tokens      — whitespace-split tokens of the header line
            block_lines — list of stripped sub-command lines belonging to the block
                          as returned by _get_block_lines()

        Args:
            keyword:  First token to match (e.g. "object-group", "object", "access-list").
            subtype:  Optional second token to match (e.g. "protocol", "network", "service").
                      When None, all blocks matching keyword are yielded regardless of subtype.

        Example usage:
            for i, tokens, block in self._iter_blocks("object-group", "protocol"):
                group_name = tokens[2]

            for i, tokens, block in self._iter_blocks("object", "network"):
                obj_name = tokens[2]

            for i, tokens, block in self._iter_blocks("access-list"):
                acl_name = tokens[1]
        """
        kw = keyword.lower()
        st = subtype.lower() if subtype else None

        for i, line in enumerate(self.lines):
            tokens = line.strip().split()
            if not tokens:
                continue
            if tokens[0].lower() != kw:
                continue
            if st and (len(tokens) < 2 or tokens[1].lower() != st):
                continue
            yield i, tokens, self._get_block_lines(i)

    # ------------------------------------------------------------------
    # Extraction methods
    # ------------------------------------------------------------------

    def extract_protocols(self):
        """
        Extract object-group protocol blocks from the config.
        Populates self.protocol_groups.

        Standard format per group:
            {
                "name": "TCPUDP",
                "protocols": [
                    {"predefined": True, "name": "tcp"},
                    {"predefined": True, "name": "udp"}
                ]
            }

        Notes:
            - There is no singular 'object protocol' in ASA syntax — only groups.
            - protocol_objects will always remain empty; kept for structural consistency.
            - Nested group-object references are resolved and flattened inline.
        """
        logger.info("Starting protocol group extraction")

        # First pass: collect all raw groups (name → list of raw protocol tokens/refs)
        # We need two passes to correctly resolve nested group-object references.
        raw_groups: dict[str, list] = {}

        for i, tokens, block in self._iter_blocks("object-group", "protocol"):
            if len(tokens) < 3:
                logger.warning(f"Malformed object-group protocol header at line {i + 1} — skipping")
                continue

            group_name = tokens[2]
            logger.debug(f"Found protocol group '{group_name}' at line {i + 1}")

            raw_members = []
            for sub_line in block:
                sub_tokens = sub_line.split()
                if not sub_tokens:
                    continue

                cmd = sub_tokens[0].lower()

                if cmd == "protocol-object" and len(sub_tokens) >= 2:
                    raw_members.append(("protocol", sub_tokens[1]))
                    logger.debug(f"  protocol-object: '{sub_tokens[1]}'")

                elif cmd == "group-object" and len(sub_tokens) >= 2:
                    raw_members.append(("group-ref", sub_tokens[1]))
                    logger.debug(f"  group-object (ref): '{sub_tokens[1]}'")

                elif cmd == "description":
                    logger.debug(f"  description (ignored): '{' '.join(sub_tokens[1:])}'")

                else:
                    logger.warning(
                        f"Unrecognized sub-command '{sub_line}' "
                        f"in protocol group '{group_name}' — skipping"
                    )

            raw_groups[group_name] = raw_members

        if not raw_groups:
            logger.info("No protocol groups found in config")
            return

        # Second pass: resolve group-object references and build final dicts.
        # Iterates until all refs are resolved or no progress is made (guards
        # against circular references, which ASA rejects but a corrupt config
        # could theoretically contain).
        resolved: dict[str, list[dict]] = {}

        def resolve_group(name: str, visited: set) -> list[dict]:
            """Recursively resolve a protocol group to a flat list of protocol dicts."""
            if name in resolved:
                return resolved[name]

            if name in visited:
                logger.error(
                    f"Circular group-object reference detected for '{name}' — skipping"
                )
                return []

            if name not in raw_groups:
                logger.warning(
                    f"group-object reference '{name}' not found in config — skipping"
                )
                return []

            visited = visited | {name}
            protocols = []

            for kind, value in raw_groups[name]:
                if kind == "protocol":
                    protocols.append(self._normalize_protocol(value))
                elif kind == "group-ref":
                    nested = resolve_group(value, visited)
                    protocols.extend(nested)

            resolved[name] = protocols
            return protocols

        for group_name in raw_groups:
            protocols = resolve_group(group_name, set())
            self.protocol_groups.append({
                "name": group_name,
                "protocols": protocols
            })
            logger.debug(
                f"Protocol group '{group_name}' resolved: "
                f"{[p['name'] for p in protocols]}"
            )

        logger.info(f"Extracted {len(self.protocol_groups)} protocol group(s)")

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