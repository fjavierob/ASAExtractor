import logging
import sys
import json
from ASAExtractor import ASAExtractor

logging.addLevelName(logging.WARNING, "WARN")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-5s  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)

ASA = ASAExtractor("config.cfg")
ASA.extract_protocols()
ASA.extract_services()
with open("services.json", "w") as f:
    json.dump(ASA.service_objects, f, indent=2)
with open("service-groups.json", "w") as f:
    json.dump(ASA.service_groups, f, indent=2)