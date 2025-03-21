import logging

# Setup logger
logging.basicConfig(
        format="[%(asctime)s] [%(levelname)s -> %(name)s] %(message)s",
        level=logging.DEBUG
    )
logger = logging.getLogger(__name__)

for l in [
        "asyncio"
    ]:
    logging.getLogger(l).setLevel(logging.ERROR)