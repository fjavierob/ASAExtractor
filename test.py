import logging
import sys
from ASAExtractor import ASAExtractor

logging.addLevelName(logging.WARNING, "WARN")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-5s  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)

ASA = ASAExtractor("config.cfg")