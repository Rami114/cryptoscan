

class ScanConfig:

    def __init__(self, config):
        self.name = config['name']
        self.threshold = config['threshold']
        self.family = config['family']
        self.enabled = True  # Might be useful later if we let users individually en/disable scans
        self.description = config['description']
        self.type = config['type']
        self.size = config['size']
        self.flags = config['flags']
        self.inverse_flags = self._calculate_inverse_flags()
        self.match_type = config['on_match']['type']
        self.match_label = config['on_match']['name']
        # Primarily for chunked scan hits to be easily retrieved
        self.found = False

    def _calculate_inverse_flags(self):
        if self.size == 1:
            return self.flags
        # Break into self.sized chunks
        chunks = [self.flags[i * self.size:(i+1) * self.size] for i in range((len(self.flags) + self.size - 1) // self.size)]
        # Recompose with reverse ordered
        return [flag for chunk in chunks for flag in reversed(chunk)]

