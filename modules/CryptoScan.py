import binaryninja as bn
from binaryninja.plugin import BackgroundTaskThread
import os, json, binascii
from .ScanConfig import ScanConfig
from .ScanMatch import DataConstantScanMatch, ILConstantScanMatch
from .ScanReport import ScanReport


class CryptoScan(BackgroundTaskThread):

    debug_address = None

    def __init__(self, bv, options):
        BackgroundTaskThread.__init__(self, 'Beginning scan for crypto constructs...', True)
        self.bv = bv
        self.options = options
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
                                                            'size',
                                                            'threshold',
                                                            'type',
                                                            'flags',
                                                            'on_match']):
                    config = ScanConfig(json_config)
                    self.scanconfigs.append(config)
                else:
                    self.log_error('Invalid config file: {filename}'.format(filename = json_file))

    def run(self):
        results = []

        if self.options['static']:
            self.log_progress('Running data constant scans...')
            results.extend(self.run_data_constant_scans())

        if self.options['il'] and not self.cancelled:
            self.log_progress('Running IL constant scans...')
            results.extend(self.run_il_constant_scans())

        if self.options['signature'] and not self.cancelled:
            self.log_progress('Running signature scans')
            results.extend(self.run_signature_scans())

        # Proceed to results, if cancelled display notification
        if self.cancelled:
            self.log_progress('Cancelling scan, checking for partial results...')

        results = self.prune_results(results)
        if len(results) != 0:
            self.log_progress('Scan found {count} match{plural}'.format(count = len(results),
                                                                    plural = '' if len(results) == 1 else 'es'))
            self.apply_symbols(results)
            self.display_results(results)
        elif not self.cancelled:
            self.log_progress('No scan results found')
            # Temporarily disabled pending better way to not block multiple command-line output
            #bn.show_message_box('CryptoScan results',
            #                    'No crypto constructs identified.',
            #                    bn.MessageBoxButtonSet.OKButtonSet,
            #                    bn.MessageBoxIcon.InformationIcon)

    # Todo: move to dedicated class for scanners
    def run_il_constant_scans(self):
        results = []
        const_instructions = []
        scans = [scan for scan in self.scanconfigs if scan.type == 'static' and scan.enabled]

        # Because of potential deep trees this isn't a true reflection of progress
        progress_trigger = 5
        num_instructions = len(list(self.bv.mlil_instructions))
        self.log_progress('Finding constants defined in IL')
        for instr_index, instruction in enumerate(self.bv.mlil_instructions):
            percentage = instr_index*100 / num_instructions
            if percentage >= progress_trigger:
                progress_trigger += 5
                while progress_trigger < percentage:
                    progress_trigger += 5
                self.log_progress('Finding constants defined in IL ({percentage:.3f}%)'.format(percentage = percentage))
            const_instructions.extend(self.recurse_retrieve_consts(instruction))

        # Second pass, actually evaluate the found constants
        self.log_progress('Evaluating found IL constants')
        progress_trigger = 5
        num_consts = len(const_instructions)
        for const_index, instr in enumerate(const_instructions):
            percentage = const_index*100 / num_consts
            if percentage >= progress_trigger:
                progress_trigger += 5
                while progress_trigger < percentage:
                    progress_trigger += 5
                self.log_progress('Evaluating found IL constants ({percentage:.3f}%)'.format(percentage = percentage))
            # Skip constants that aren't at least several bytes, or we will get tons of false positives
            if not instr.size > 1:
                continue
            for scan in scans:
                # Some constants are broken up across multiple instructions.
                # This chunking will detect all of them
                chunks = [scan.flags[i * instr.size:(i+1) * instr.size] for i in range((len(scan.flags) + 3) // 4)]
                for chunk_index, chunk in enumerate(chunks):
                    if len(chunk) == instr.size:
                        flag_value = ''.join((flag.replace('0x', '') for flag in chunk))
                        const_value = '{:x}'.format(instr.constant)
                        if const_value == flag_value:
                            # We found a hit, did we previously find a chunk from this scan?
                            if scan.found:
                                for index, result in enumerate(results):
                                    if scan.name == result.scan.name and \
                                                    result.instruction.function.source_function.name == \
                                                    instr.function.source_function.name and \
                                        not result.found_chunk_id(chunk_index):
                                        result.add_matched_chunk(list(chunk), chunk_index)
                                        results[index] = result
                            else:
                                scan.found = True
                                results.append(ILConstantScanMatch(scan, instr, chunk))

        return results

    def recurse_retrieve_consts(self, instruction):
        results = []
        if instruction.operation == bn.MediumLevelILOperation.MLIL_CONST:
            results.append(instruction)
        else:
            for operand in instruction.operands:
                if type(operand) == bn.MediumLevelILInstruction:
                    results.extend(self.recurse_retrieve_consts(operand))
        return results

    # Todo: move to dedicated class for scanners
    def run_data_constant_scans(self):
        results = []

        scans = [scan for scan in self.scanconfigs if scan.type == 'static' and scan.enabled]
        # We use the first int as a trigger to investigate any scan further
        triggers = [scan.flags[0] for scan in scans]

        # Where implementations can be multi-byte, we should check opposite byte order too
        multi_byte_scans = [scan for scan in self.scanconfigs if scan.size > 1]
        inverse_triggers = [scan.inverse_flags[0] for scan in multi_byte_scans]

        progress_trigger = 5
        start_offset = self.br.offset
        total_distance = len(self.bv)

        while not self.br.eof and not self.cancelled:
            debug = False

            if self.debug_address is not None and self.br.offset == int(self.debug_address, 16):
                self.log_info('At debug address')
                debug = True

            b = self.next_byte()

            percentage = (self.br.offset - start_offset)*100 / total_distance
            if percentage >= progress_trigger:
                progress_trigger += 5
                while progress_trigger < percentage:
                    progress_trigger += 5
                self.log_progress('Scanning data for constants ({percentage:.3f}%)'.format(percentage = percentage))

            if b is None:
                break

            for index, trigger in enumerate(triggers):
                if debug:
                    self.log_info('Checking trigger {} for scan {} against byte {}'.format(trigger,
                                                                                           scans[index].name, hex(b)))
                # TODO: refactor this, null-byte triggers will chew up an inordinate amount of time
                # Possible solutions include caching temporarily when hits are detected, grouping triggers
                # and terminating early if we check flag bytes 1 by 1
                if b == int(trigger, 16):

                    if debug:
                        self.log_info('Trigger match at debug address for scan {}'.format(scans[index].name))

                    scan = scans[index]
                    # See how many more values we need
                    flag_count = len(scan.flags) - 1

                    # Fetch them
                    test_bytes = []
                    bytes_read = 0
                    for i in range(flag_count):
                        null_wanted = False
                        if int(scan.flags[i+1], 16) == 0:
                            null_wanted = True
                        test_byte, count = self.seek_next_byte(allow_null = null_wanted)
                        bytes_read += count
                        if test_byte is not None:
                            test_bytes.append(test_byte)

                    # Sanity check we got enough bytes and confirm the match
                    if len(test_bytes) == flag_count and test_bytes == [int(tb, 16) for tb in scan.flags[1:]]:
                        # Save the match with the address
                        address = self.br.offset - (bytes_read+1)
                        result = DataConstantScanMatch(scan, address)
                        results.append(result)

                    # Track back irrespective
                    self.br.offset -= bytes_read

            # And reverse byte order
            for index, trigger in enumerate(inverse_triggers):
                if debug:
                    self.log_info('Checking inverse trigger {} for scan {} against byte {}'
                                  .format(trigger, multi_byte_scans[index].name, hex(b)))
                if b == int(trigger, 16):

                    if debug:
                        self.log_info('Inverse trigger match at debug address for scan {}'
                                      .format(multi_byte_scans[index].name))

                    scan = multi_byte_scans[index]
                    # See how many more values we need
                    flag_count = len(scan.inverse_flags) - 1

                    # Fetch them
                    test_bytes = []
                    bytes_read = 0
                    for i in range(flag_count):
                        null_wanted = False
                        if int(scan.inverse_flags[i+1], 16) == 0:
                            null_wanted = True
                        test_byte, count = self.seek_next_byte(allow_null = null_wanted)
                        bytes_read += count
                        if test_byte is not None:
                            test_bytes.append(test_byte)

                    # Sanity check we got enough bytes and confirm the match
                    if len(test_bytes) == flag_count and test_bytes == [int(tb, 16) for tb in scan.inverse_flags[1:]]:
                        # Save the match with the address
                        address = self.br.offset - (bytes_read+1)
                        result = DataConstantScanMatch(scan, address)
                        results.append(result)

                    # Track back irrespective
                    self.br.offset -= bytes_read

        return results

    def prune_results(self, results):
        valid_results = []
        for result in results:
            if isinstance(result, ILConstantScanMatch):
                max_match_len = len(result.scan.flags)
                matched_len = len(result.flag_chunks)
                match_rate =  (100*matched_len) / max_match_len
                if match_rate >= result.scan.threshold:
                    valid_results.append(result)
                else:
                    self.log_info("Scan {name} had match rate of {rate:.3f} vs threshold {threshold:.3f}".format(
                        name = result.scan.name,
                        rate = match_rate,
                        threshold = result.scan.threshold
                    ))
            else:
                # data constants are a straight pass
                # we only chunk during IL scans
                valid_results.append(result)
        return valid_results

    def run_signature_scans(self):
        results = []
        for scan in [scan for scan in self.scanconfigs if scan.type == 'signature']:
            ''' Magic goes here - probably ask Josh some more '''
        return results

    def display_results(self, results):
        report = ScanReport(results, self.cancelled)
        self.bv.show_markdown_report(report.title, report.markdown_report, report.text_report)

    def apply_symbols(self, results):
        for result in results:
            self.set_symbol(result.address, result.scan.match_label)

    def set_symbol(self, address, label):
        if self.bv.is_valid_offset(address):
            symbol = bn.Symbol(bn.SymbolType.ImportedDataSymbol, address, label)
            self.bv.define_user_symbol(symbol)
        else:
            self.log_error('Invalid address for symbol: {address}'.format(address = address))

    def seek_next_byte(self, max_dist = 15, allow_null = False):
        # Finds the next non-zero byte, up to max_dist
        # Default is 15 to allow up to 128 bit offsets
        # However, if we allow nulls (presumably because we're looking for one)
        # then we increase this limit as we will return early
        if allow_null:
            max_dist = (max_dist * 2) + 1
        while not self.bv.is_valid_offset(self.br.offset) and not self.br.eof:
            self.br.seek_relative(1)
        dist = 0
        while not self.br.eof and dist <= max_dist:
            dist += 1
            byte = self.br.read(1)
            if byte is None:
                self.br.seek_relative(1)
                continue
            byte = int(binascii.hexlify(byte), 16)
            if byte != 0 or allow_null:
                return byte, dist
        return None, dist

    def next_byte(self):
        while not self.bv.is_valid_offset(self.br.offset) and not self.br.eof:
            self.br.seek_relative(1)
        if self.br.eof:
            return None
        byte = self.br.read(1)
        return int(binascii.hexlify(byte), 16)

    def log_progress(self, msg):
        self.progress = '[CryptoScan] {message}'.format(message = msg)

    def log_info(self, msg):
        bn.log_info('[CryptoScan] {message}'.format(message = msg))

    def log_error(self, msg):
        bn.log_error('[CryptoScan] {message}'.format(message = msg))
