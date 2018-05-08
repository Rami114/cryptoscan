
class ScanReport:

    def __init__(self, raw_results):
        self.raw_results = raw_results
        self.title = 'CryptoScan report - found {count} matches'.format(count = len(raw_results))
        self.text_report, self.markdown_report = self._compile_report()

    def _compile_report(self):
        text = self._compile_text_report()
        markdown = self._compile_markdown_report()
        return text, markdown

    def _compile_text_report(self):
        text = list(['Constants'])
        text.append('---------')
        text.append('')
        statics = [result for result in self.raw_results if result.scan.type == 'static']
        if len(statics) != 0:
            for result in (result for result in self.raw_results if result.scan.type == 'static'):
                text.append('Name: {name}\nFamily: {family}\nFlags: {flags}\nAddress: {address}\n'.format(
                    name = result.scan.name,
                    family = result.scan.family,
                    flags = '-'.join(result.scan.flags),
                    address = hex(result.address).rstrip("L")))
        else:
            text.append('No results found.')
        text.append('')
        text.append('Signatures')
        text.append('----------')
        text.append('')
        # Todo: how do we report on signature matches? Function names? Addresses? TBD
        text.append('No results found.')

        return '\n'.join(text)

    def _compile_markdown_report(self):
        # We don't particularly care about alignment with the raw markdown
        md = list(['## Constants'])
        md.append('')
        statics = [result for result in self.raw_results if result.scan.type == 'static']
        if len(statics) != 0:
            md.append('| Name              |  \| | Family  |  \| | Flags |  \| | Address |')
            md.append('|:----------------- | --- |:-------:| --- |:-----:|     | -------:|')
            for result in (result for result in self.raw_results if result.scan.type == 'static'):
                md.append('| {name} |\|| {family} |\|| `{flags}` |\|| `{address}` |'.format(
                    name = result.scan.name,
                    family = result.scan.family,
                    flags = '-'.join(result.scan.flags),
                    address = hex(result.address).rstrip("L")))
        else:
            md.append('No results found.')
        md.append('')
        md.append('## Signatures')
        md.append('')
        # Todo: how do we report on signature matches? Function names? Addresses? TBD
        md.append('No results found.')

        return '\n'.join(md)
