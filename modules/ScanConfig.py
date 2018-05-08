

class ScanConfig:

    def __init__(self, config):
        self.name = config['name']
        self.family = config['family']
        self.enabled = True  # Might be useful later if we let users individually en/disable scans
        self.description = config['description']
        self.type = config['type']
        self.flags = config['flags']
        self.match_type = config['on_match']['type']
        self.match_label = config['on_match']['name']