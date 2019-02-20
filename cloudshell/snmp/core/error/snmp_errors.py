

class GeneralSNMPError(Exception):
    def __init__(self, message, logger):
        self.message = message
        logger.exception(self)
