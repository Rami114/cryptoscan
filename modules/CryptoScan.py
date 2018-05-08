import binaryninja as bn
import os, json
from ScanConfig import ScanConfig
from ScanMatch import ScanMatch
from ScanReport import ScanReport


class CryptoScan:

    debug_address = None

    def __init__(self, bv):
        self.bv = bv
        self.br = bn.BinaryReader(self.bv, bn.Endianness.LittleEndian)
        self.log_info('Initialising Plugin')
        self.scanconfigs = []
        self.load_configs()
        self.log_info('Loaded {count} configurations'.format(count = len(self.scanconfigs)))

    def load_configs(self):
        cwd = os.path.dirname(os.path.realpath(__file__))
        config_path = os.path.join(cwd, '..', 'scans')
        json_files = [json_file for json_file in os.listdir(config_path) if json_file.endswith('.json')]
        for f in json_files:
            with open(os.path.join(config_path, f)) as json_file:
                json_config = json.load(json_file)
                if all(option in json_config for option in ['name',
                                                            'description',
                                                            'type',
                                                            'flags',
                                                            'on_match']):
                    config = ScanConfig(json_config)
                    self.scanconfigs.append(config)
                else:
                    self.log_error('Invalid config file: {filename}'.format(filename = json_file))

    def run_scan(self, options):
        results = []
        if options['static']:
            self.log_info('Running static constant scans')
            results = self.run_constant_scans()
        if options['signature']:
            self.log_info('Running signature scans')
            results.extend(self.run_signature_scans())
        if len(results) is not 0:
            self.log_info('Scan found {count} match{plural}'.format(count = len(results), plural = '' if len(results) == 1 else 'es'))
            self.apply_symbols(results)
            self.display_results(results)
        else:
            self.log_info('No scan results found')

    def run_constant_scans(self):
        results = []

        scans = [scan for scan in self.scanconfigs if scan.type == 'static' and scan.enabled]
        # We use the first int as a trigger to investigate any scan further
        triggers = [scan.flags[0] for scan in scans]

        # Single pass only, the approach is as follows:
        # We will scan a single byte at at timee. Once we hit a trigger byte,
        # we then scan ahead and check if subsequent bytes are valid flag bytes.
        # However, we do this by seeking past null-bytes, which copes with different
        # implementations of the constants (byte-array, int32, int64 and event int128)
        #
        # Downside: constants with explicit null byte sequences are a PITA
        while not self.br.eof:
            debug = False
            if self.debug_address is not None and self.br.offset == int(self.debug_address, 16):
                self.log_info("At debug address")
                debug = True

            b = self.next_byte()
            if b is None:
                break

            for index, trigger in enumerate(triggers):
                if debug:
                    self.log_info("Checking trigger {} for scan {} against byte {}".format(trigger, scans[index].name, hex(b)))
                if b == int(trigger, 16):

                    if debug:
                        self.log_info("Trigger match at debug address for scan {}".format(scans[index].name))

                    scan = scans[index]
                    # See how many more values we need
                    flag_count = len(scan.flags) - 1

                    # Fetch them
                    test_bytes = []
                    bytes_read = 0
                    for _ in range(flag_count):
                        test_byte, count = self.seek_next_byte()
                        bytes_read += count
                        if test_byte is not None:
                            test_bytes.append(test_byte)

                    # Sanity check we got enough bytes and confirm the match
                    if len(test_bytes) == flag_count and test_bytes == [int(tb, 16) for tb in scan.flags[1:]]:
                        # Save the match with the address
                        address = self.br.offset - (bytes_read+1)
                        result = ScanMatch(scan, address)
                        results.append(result)

                    # Track back irrespective
                    self.br.offset -= bytes_read

        return results

    def run_signature_scans(self):
        results = []
        for scan in [scan for scan in self.scanconfigs if scan.type == 'signature']:
            ''' Magic goes here - probably ask Josh some more '''
        return results

    def display_results(self, results):
        report = ScanReport(results)
        bn.show_markdown_report(report.title, report.markdown_report, report.text_report)

    def apply_symbols(self, results):
        for result in results:
            if result.scan.match_type == 'symbol':
                self.set_symbol(result.address, result.scan.match_label)

    def set_symbol(self, address, label):
        if self.bv.is_valid_offset(address):
            symbol = bn.Symbol(bn.SymbolType.ImportedDataSymbol, address, label)
            self.bv.define_user_symbol(symbol)
        else:
            self.log_error('Invalid address for symbol: {address}'.format(address = address))

    def seek_next_byte(self, max_dist = 15):
        # Finds the next non-zero byte, up to max_dist
        # Default is 15 to allow up to 128 bit offsets
        while not self.bv.is_valid_offset(self.br.offset) and not self.br.eof:
            self.br.seek_relative(1)
        dist = 0
        while not self.br.eof and dist <= max_dist:
            dist += 1
            byte = self.br.read(1)
            if byte is None:
                self.br.seek_relative(1)
                continue
            byte = int(byte.encode('hex'), 16)
            if byte != 0:
                return byte, dist
        return None, dist

    def next_byte(self):
        while not self.bv.is_valid_offset(self.br.offset) and not self.br.eof:
            self.br.seek_relative(1)
        if self.br.eof:
            return None
        byte = self.br.read(1)
        return int(byte.encode('hex'), 16)

    def log_info(self, msg):
        bn.log_info('[CryptoScan] {message}'.format(message = msg))

    def log_error(self, msg):
        bn.log_error('[CryptoScan] {message}'.format(message = msg))
