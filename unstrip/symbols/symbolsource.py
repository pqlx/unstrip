from typing import List
from unstrip.symbols import Symbol

class SymbolSource:
    """
    Abstract class that facilitates the acquisition of symbols from different sources
    """
    
    def __init__(self):
        pass

    def get_function_symbols() -> List[Symbol]:
        raise NotImplementedError();
