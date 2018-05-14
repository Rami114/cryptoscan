

class ScanMatch:

    def __init__(self, scan):
        self.scan = scan


class DataConstantScanMatch(ScanMatch):

    def __init__(self, scan, address):
        ScanMatch.__init__(self, scan)
        self.address = address

class ILConstantScanMatch(ScanMatch):

    def __init__(self, scan, instruction, flag_chunk):
        ScanMatch.__init__(self, scan)
        self.instruction = instruction
        self.address = instruction.address
        self.flag_chunks = []
        self.add_matched_chunk(flag_chunk)

    def add_matched_chunk(self, flag_chunk):
        self.flag_chunks.extend(flag_chunk)
