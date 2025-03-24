import os
import sys
def get_base_dir():
    if getattr(sys, 'frozen', False):
        BASE_PATH = os.path.dirname(sys.executable)
    else:
        BASE_PATH = os.path.dirname(os.path.abspath(__file__))
    return BASE_PATH

BASE_DIR=get_base_dir()