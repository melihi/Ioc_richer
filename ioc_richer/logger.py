import logging
import sys


def setup_logger(logger_name: str, logfile: str):
    """Create logger .

    Args :
        logger_name  : logger name .
        logfile  : log file name .

    """

    file_handler = logging.FileHandler(filename="./data/" + logfile)
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    handlers = [file_handler, stdout_handler]

    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s",
        handlers=handlers,
    )

    logger = logging.getLogger(logger_name)
    return logger
