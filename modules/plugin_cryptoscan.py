import binaryninja as bn
from cryptoscan.modules.CryptoScan import CryptoScan

def run_plugin(bv):
    # Just run everything until we have something tangible for IL signature detection
    ## For now this will reload configs on every run, might be desirable.
    ## static_scan = bn.ChoiceField('Scan for constants', ['Yes', 'No'])
    ## signature_scan = bn.ChoiceField('Scan IL signatures', ['Yes', 'No'])
    ## bn.get_form_input([None, static_scan, None, signature_scan], 'Scanning options')
    ## options = {'static' : static_scan.result == 0, 'signature' : signature_scan.result == 0}
    options = {'static' : True, 'signature' : False}
    if any(option for option in options.values()):
        cs = CryptoScan(bv, options)
        cs.start()

