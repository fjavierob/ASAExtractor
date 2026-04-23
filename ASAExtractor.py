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

PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "dns": 53, "www": 80, "http": 80, "pop3": 110,
    "sunrpc": 111, "ident": 113, "nntp": 119, "ntp": 123,
    "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139,
    "imap4": 143, "snmp": 161, "snmptrap": 162, "xdmcp": 177,
    "bgp": 179, "irc": 194, "ldap": 389, "https": 443, "sftp": 990,
    "exec": 512, "login": 513, "cmd": 514, "syslog": 514, "lpd": 515,
    "talk": 517, "rip": 520, "uucp": 540, "klogin": 543, "kshell": 544,
    "rtsp": 554, "ldaps": 636, "kerberos": 88, "sqlnet": 1521,
    "pptp": 1723, "h323": 1720, "rdp": 3389, "sip": 5060,
    "aol": 5190, "radius": 1645, "radius-acct": 1646,
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

    def _is_predefined_port(self, token: str) -> bool:
        """Return True if token is a well-known named port."""
        return token.lower() in PORT_NAMES

    def _normalize_port_token(self, token: str) -> str:
        """
        Return the port token as it should be stored.
        Named tokens (e.g. 'https', 'www') are lowercased for consistency.
        Numeric tokens (e.g. '443', '8088') are returned unchanged.
        No conversion between names and numbers in either direction.
        """
        return token.lower() if token.lower() in PORT_NAMES else token

    def _parse_port_clause(self, tokens: list, start: int) -> tuple:
        """
        Parse a port clause starting at tokens[start].
        Handles: eq <port>  |  range <p1> <p2>
        Returns (port_string, next_index) where port_string is:
            "80"         for eq numeric
            "www"        for eq named
            "1024-65535" for range
            "ldaps"      for range ldaps ldaps (degenerate range, collapsed to single port)
        """
        if start >= len(tokens):
            return "", start
        op = tokens[start].lower()
        if op == "eq" and start + 1 < len(tokens):
            return self._normalize_port_token(tokens[start + 1]), start + 2
        if op == "range" and start + 2 < len(tokens):
            p1 = self._normalize_port_token(tokens[start + 1])
            p2 = self._normalize_port_token(tokens[start + 2])
            # Collapse range X X → X (single port written as degenerate range)
            if p1 == p2:
                return p1, start + 3
            return f"{p1}-{p2}", start + 3
        logger.warning(f"Unsupported port operator '{op}' — skipping port clause")
        return "", start + 1

    def _build_service_dict(self, name: str, protocol: str,
                            src_port: str, dst_port: str,
                            description: str = "") -> dict:
        """
        Build a normalized service dict, omitting absent port keys.
        A service is predefined if it has a single well-known dst port name
        with no src port.
        """
        if (dst_port and not src_port
                and self._is_predefined_port(dst_port)
                and not any(c in dst_port for c in ("-", ","))):
            return {"predefined": True, "name": dst_port.lower()}

        svc = {
            "predefined": False,
            "name": name,
            "protocol": protocol.lower(),
        }
        if src_port:
            svc["src_port"] = src_port
        if dst_port:
            svc["dst_port"] = dst_port
        if description:
            svc["description"] = description
        return svc

    def _parse_service_line(self, tokens: list, name: str,
                            description: str = "") -> dict:
        """
        Parse a 'service <protocol> [source ...] [destination ...]' token list.
        tokens[0] is expected to be 'service'.
        Returns a normalized service dict or None on parse failure.
        """
        if len(tokens) < 2:
            logger.warning(f"Malformed service line for '{name}' — skipping")
            return None

        protocol = tokens[1].lower()
        src_port = ""
        dst_port = ""
        i = 2

        while i < len(tokens):
            direction = tokens[i].lower()
            if direction == "source" and i + 1 < len(tokens):
                src_port, i = self._parse_port_clause(tokens, i + 1)
            elif direction == "destination" and i + 1 < len(tokens):
                dst_port, i = self._parse_port_clause(tokens, i + 1)
            else:
                logger.warning(
                    f"Unexpected token '{tokens[i]}' parsing service '{name}' — skipping token"
                )
                i += 1

        return self._build_service_dict(name, protocol, src_port, dst_port, description)

    def _auto_service_name(self, protocol: str, src_port: str, dst_port: str) -> str:
        """
        Generate an auto name for inline services created from service groups.
        Format: <PROTOCOL><PORT> or <PROTOCOL><START>-<END>
        Uses dst_port if present, otherwise src_port.
        """
        port = dst_port or src_port
        return f"{protocol.upper()}{port.upper()}" if port else protocol.upper()

    def _register_service(self, svc: dict) -> str:
        """
        Add a service dict to self.service_objects if not already present (by name).
        Returns the service name.
        """
        name = svc["name"]
        if not any(s["name"] == name for s in self.service_objects):
            self.service_objects.append(svc)
            logger.debug(f"  Registered service '{name}'")
        else:
            logger.debug(f"  Service '{name}' already exists — skipping duplicate")
        return name

    def extract_services(self):
        """
        Extract service objects and object-groups from the config.
        Populates self.service_objects and self.service_groups.

        Service object standard format:
            Predefined: {"predefined": True, "name": "https"}
            Custom:     {"predefined": False, "name": "UDP4000-5000",
                         "protocol": "udp", "src_port": "4000-5000",
                         "dst_port": "4000-5000"}
            Optional:   "description" key present when defined in config

        Service group standard format:
            {"name": "DM_INLINE_TCP_3", "services": ["www", "https"]}

        Notes:
            - Inline services from service-object and port-object lines are
              auto-created, registered in service_objects, then referenced by
              name in the group.
            - service-object object <n> lines trust the name exists and add
              it directly to the group without creating a new object.
            - Deduplication by name: no duplicate service objects created.
            - group-object references inside service groups are kept as-is
              in the services list; full flattening is left to the consumer.
        """
        logger.info("Starting service extraction")

        # ------------------------------------------------------------------
        # Pass 1: object service blocks
        # ------------------------------------------------------------------
        for i, tokens, block in self._iter_blocks("object", "service"):
            if len(tokens) < 3:
                logger.warning(f"Malformed object service header at line {i + 1} — skipping")
                continue

            obj_name = tokens[2]
            logger.debug(f"Found service object '{obj_name}' at line {i + 1}")

            description = ""
            service_tokens = None

            for sub_line in block:
                sub_tokens = sub_line.split()
                if not sub_tokens:
                    continue
                cmd = sub_tokens[0].lower()
                if cmd == "service":
                    service_tokens = sub_tokens
                elif cmd == "description":
                    description = " ".join(sub_tokens[1:])
                else:
                    logger.warning(
                        f"Unrecognized sub-command '{sub_line}' "
                        f"in service object '{obj_name}' — skipping"
                    )

            if service_tokens is None:
                logger.warning(f"No service definition found in object '{obj_name}' — skipping")
                continue

            svc = self._parse_service_line(service_tokens, obj_name, description)
            if svc:
                # For named objects always preserve the config name
                if not svc["predefined"]:
                    svc["name"] = obj_name
                self._register_service(svc)

        logger.info(f"Extracted {len(self.service_objects)} service object(s) from object blocks")

        # ------------------------------------------------------------------
        # Pass 2: object-group service blocks
        # ------------------------------------------------------------------
        for i, tokens, block in self._iter_blocks("object-group", "service"):
            if len(tokens) < 3:
                logger.warning(f"Malformed object-group service header at line {i + 1} — skipping")
                continue

            group_name = tokens[2]
            proto_binding = tokens[3].lower() if len(tokens) > 3 else ""
            logger.debug(
                f"Found service group '{group_name}' at line {i + 1}"
                + (f" (proto binding: {proto_binding})" if proto_binding else "")
            )

            group_services: list = []

            for sub_line in block:
                sub_tokens = sub_line.split()
                if not sub_tokens:
                    continue
                cmd = sub_tokens[0].lower()

                # service-object object <n>  →  trust name, add directly
                if (cmd == "service-object"
                        and len(sub_tokens) >= 3
                        and sub_tokens[1].lower() == "object"):
                    ref_name = sub_tokens[2]
                    group_services.append(ref_name)
                    logger.debug(f"  service-object object ref: '{ref_name}'")

                # service-object <protocol> [src] [dst]  →  auto-create + register
                elif cmd == "service-object" and len(sub_tokens) >= 2:
                    protocol = sub_tokens[1].lower()
                    src_port = ""
                    dst_port = ""
                    j = 2
                    while j < len(sub_tokens):
                        direction = sub_tokens[j].lower()
                        if direction == "source" and j + 1 < len(sub_tokens):
                            src_port, j = self._parse_port_clause(sub_tokens, j + 1)
                        elif direction == "destination" and j + 1 < len(sub_tokens):
                            dst_port, j = self._parse_port_clause(sub_tokens, j + 1)
                        else:
                            j += 1

                    svc = self._build_service_dict(
                        self._auto_service_name(protocol, src_port, dst_port),
                        protocol, src_port, dst_port
                    )
                    svc_name = self._register_service(svc)
                    group_services.append(svc_name)
                    logger.debug(f"  service-object inline → '{svc_name}'")

                # port-object eq|range  →  protocol from proto_binding, auto-create + register
                elif cmd == "port-object" and len(sub_tokens) >= 2:
                    if not proto_binding:
                        logger.warning(
                            f"port-object in group '{group_name}' "
                            f"has no protocol binding on header — skipping"
                        )
                        continue
                    port_str, _ = self._parse_port_clause(sub_tokens, 1)
                    if not port_str:
                        continue
                    svc = self._build_service_dict(
                        self._auto_service_name(proto_binding, "", port_str),
                        proto_binding, "", port_str
                    )
                    svc_name = self._register_service(svc)
                    group_services.append(svc_name)
                    logger.debug(f"  port-object → '{svc_name}'")

                elif cmd == "group-object" and len(sub_tokens) >= 2:
                    ref_name = sub_tokens[1]
                    group_services.append(ref_name)
                    logger.debug(f"  group-object ref: '{ref_name}'")

                elif cmd == "description":
                    logger.debug(f"  description (ignored): '{" ".join(sub_tokens[1:])}'")

                else:
                    logger.warning(
                        f"Unrecognized sub-command '{sub_line}' "
                        f"in service group '{group_name}' — skipping"
                    )

            self.service_groups.append({"name": group_name, "services": group_services})
            logger.debug(f"Service group '{group_name}' → services: {group_services}")

        logger.info(
            f"Extracted {len(self.service_groups)} service group(s), "
            f"{len(self.service_objects)} total service object(s)"
        )


    def extract_networks(self):
        """
        Extract network objects and object-groups from the config.
        Populates self.network_objects and self.network_groups.
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