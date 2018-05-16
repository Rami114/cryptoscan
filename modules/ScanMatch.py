

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
        self.chunk_ids_found = []
        # We always add the initial chunk
        self.add_matched_chunk(flag_chunk, 0)

    def add_matched_chunk(self, flag_chunk, chunk_index):
        self.flag_chunks.extend(flag_chunk)
        # Clunky way of detecting previous chunks, could just use
        # the flags themselves
        self.chunk_ids_found.append(chunk_index)

    def found_chunk_id(self, chunk_id):
        return chunk_id in self.chunk_ids_found
