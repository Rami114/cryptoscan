from cryptoscan.modules.ScanMatch import ILConstantScanMatch, DataConstantScanMatch

class ScanReport:

    def __init__(self, raw_results, was_cancelled):
        self.raw_results = raw_results
        self.title = '{prefix}CryptoScan report - found {count} match{plural}'.format(
            count = len(raw_results),
            prefix = 'Partial ' if was_cancelled else '',
            plural = 'es' if len(raw_results) != 1 else '')
        self.text_report, self.markdown_report = self._compile_report()

    def _compile_report(self):
        text = self._compile_text_report()
        markdown = self._compile_markdown_report()
        return text, markdown

    def _compile_text_report(self):
        text = []
        data_results = [result for result in self.raw_results if isinstance(result, DataConstantScanMatch)]
        if len(data_results) != 0:
            text.append('Data Constants')
            text.append('--------------')
            text.append('')

            for result in data_results:
                text.append('Name: {name}\nFamily: {family}\nFlags: {flags}\nAddress: {address}\n'.format(
                    name = result.scan.name,
                    family = result.scan.family,
                    flags = '-'.join(result.scan.flags[:4]),
                    address = hex(result.address).rstrip("L")))
            text.append('')

        il_results = [result for result in self.raw_results if isinstance(result, ILConstantScanMatch)]
        if len(il_results) != 0:
            text.append('IL Constants')
            text.append('------------')
            text.append('')

            for result in il_results:
                text.append('Name: {name}\nFamily: {family}\nFlags: {flags}\n' +
                            'Address: {address}\nFunction: {function}\n'.format(
                    name = result.scan.name,
                    family = result.scan.family,
                    flags = '{flags} {summary}'.format(flags = '-'.join(result.flag_chunks[:4]),
                                                       summary = ' + {count} more'.format(
                                                           count = len(result.flag_chunks))),
                    address = hex(result.instruction.address).rstrip("L"),
                    function = result.instruction.function.source_function))

            text.append('')

        # text.append('Signatures')
        # text.append('----------')
        # text.append('')
        # Todo: how do we report on signature matches? Function names? Addresses? TBD
        # text.append('No results found.')

        return '\n'.join(text)

    def _compile_markdown_report(self):
        md = []

        data_results = [result for result in self.raw_results if isinstance(result, DataConstantScanMatch)]
        if len(data_results) != 0:
            md.append('## Data Constants')
            md.append('')
            md.append('| Name              |  \| | Family  |  \| | Flags |  \| | Address |')
            md.append('|:----------------- | --- |:-------:| --- |:-----:|     | -------:|')

            for result in data_results:
                md.append('| {name} |\|| {family} |\|| `{flags}` |\|| `{address}` |'.format(
                    name = result.scan.name,
                    family = result.scan.family,
                    flags = '-'.join(result.scan.flags[:4]),
                    address = hex(result.address).rstrip('L')))

            md.append('')

        il_results = [result for result in self.raw_results if isinstance(result, ILConstantScanMatch)]
        if len(il_results) != 0:
            md.append('## IL Constants')
            md.append('')
            md.append('| Name              |  \| | Family  |  \| | Flags |  \| | Address | \| | Function |')
            md.append('|:----------------- | --- |:-------:| --- |:-----:|     | -------:|    |:--------:|')

            for result in il_results:
                md.append('| {name} |\|| {family} |\|| `{flags}` |\|| `{address}` |\|| {function} |'.format(
                    name = result.scan.name,
                    family = result.scan.family,
                    flags = '{flags} {summary}'.format(flags = '-'.join(result.flag_chunks[:4]),
                                                       summary = ' + {count} more'.format(
                                                           count = len(result.flag_chunks))),
                    address = hex(result.instruction.address).rstrip("L"),
                    function = '{name} @ {address}'.format(
                        name = result.instruction.function.source_function.name,
                        address = hex(result.instruction.function.source_function.symbol.address).rstrip('L'))))

            md.append('')

        # md.append('## Signatures')
        # md.append('')
        # Todo: how do we report on signature matches? Function names? Addresses? TBD
        # md.append('No results found.')

        return '\n'.join(md)
