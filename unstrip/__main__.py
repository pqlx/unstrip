import sys
import re

from unstrip.cli import start_cli

def main():
    
    if re.search('__main__.pyc?$', sys.argv[0]):
        sys.argv[0] = 'python -m unstrip'

    start_cli(sys.argv[1:])

if __name__ == "__main__":
    main()
