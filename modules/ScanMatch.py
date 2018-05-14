

class ScanMatch:

    def __init__(self, scan):
        self.scan = scan


class DataConstantScanMatch(ScanMatch):

    def __init__(self, scan, address):
        ScanMatch.__init__(self, scan)
        self.address = address

class ILConstantScanMatch(ScanMatch):

    def __init__(self, scan, instruction):
        ScanMatch.__init__(self, scan)
        self.instruction = instruction
        self.address = instruction.address
