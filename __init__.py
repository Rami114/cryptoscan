"""
cryptoscan
Plugin to scan binaries for common crypto implementations and magic variables. 
"""
from binaryninja import PluginCommand
from .modules import plugin_cryptoscan

PluginCommand.register("Scan for crypto", "Scan the binary file for known crypto constructs", plugin_cryptoscan.run_plugin)
