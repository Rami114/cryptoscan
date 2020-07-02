from binaryninja import BinaryViewType
from cryptoscan.modules.CryptoScan import CryptoScan
import sys

import argparse
parser = argparse.ArgumentParser(description='Scan binaries for crypto related contents')
static_parser = parser.add_mutually_exclusive_group(required=False)
static_parser.add_argument('--static', dest='static', action='store_true')
static_parser.add_argument('--no-static', dest='static', action='store_false')
parser.set_defaults(static=True)

signature_parser = parser.add_mutually_exclusive_group(required=False)
signature_parser.add_argument('--signature', dest='signature', action='store_true')
signature_parser.add_argument('--no-signature', dest='signature', action='store_false')
parser.set_defaults(signature=True)

il_parser = parser.add_mutually_exclusive_group(required=False)
il_parser.add_argument('--il', dest='il', action='store_true')
il_parser.add_argument('--no-il', dest='il', action='store_false')
parser.set_defaults(il=True)

parser.add_argument('filenames', nargs='+')

args = parser.parse_args()

try:
    options = parser.parse_args()
except:
    parser.print_help()
    sys.exit(0)

options = {'static' : args.static, 'signature' : args.signature, 'il': args.il}

if any(option for option in options.values()):
    for filename in args.filenames:
        bv = BinaryViewType.get_view_of_file(filename)
        cs = CryptoScan(bv, options)
        cs.start()
