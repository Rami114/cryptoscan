"""
cryptoscan
Plugin to scan binaries for common crypto implementations and magic variables. 
"""
from binaryninja import *
from cryptoscan.modules import plugin_cryptoscan

# Register our plugin
PluginCommand.register("Scan for crypto", "Scan the binary file for known crypto constructs", plugin_cryptoscan.run_plugin)
