from typing import Union, List
import logging


from unstrip.symbols import Symbol, SymbolType, BindType, VisibilityType
from unstrip.symbols.symbolsource import SymbolSource

from unstrip.symbols.textlexer import create_lexer

logger = logging.getLogger(__name__)

class TextSymbolSource(SymbolSource):

    def __init__(self, text_path: Union[str, 'pathlib.Path']=None, raw_text: str=None):
        
        super().__init__()

        if text_path:
            with open(text_path, 'r') as h: 
                self._text = h.read()
        elif raw_text:
            self._text = raw_text
        else:
            raise Exception("Either supply text_path or raw_text")
  
    def get_function_symbols(self) -> List[Symbol]:
        """
        Here we parse our format.
        it 's not the cleanest code.... it does its job however
        """

        lexer = create_lexer()
        lexer.input(self._text)
        
        
        def syntax_error(tok, extra=None):
            msg = f"line {tok.lineno}: Encountered syntax error at token {tok.type} (value={repr(tok.value)})"

            if extra:
                msg += ": " + extra
            
            raise Exception(msg)
        
        def next_tok(lexer_, no_fail=True):
            
            tok = lexer_.token()
            if not tok and no_fail:
                raise Exception("Token stream stopped prematurely.")
            return tok
        
        def symbol_set_value(symbol, key, value):
            
            mappings = {
                'size': 'size',
                'visibility': 'visibility',
                'bind': 'bind'
            }

            if key not in mappings.keys():
                raise Exception(f"Invalid key '{key}'")
            
            if key == 'size' and not isinstance(value, int):
                raise Exception(f"Expected integer value for key 'size'")
            

            if isinstance(value, int):
                setattr(symbol, key, value)
                return

            def create_lookup(enumtype, prefix):
                result = {}
                for t in enumtype:
                    result[t.name.lower()] = t.value
                    result[t.value.lower()] = t.value
                
                return result;
            
            lookups = {
                'bind': create_lookup(BindType),
                'visibility': create_lookup(VisibilityType)
            }
            
            if value.lower() not in lookuks[key].keys():
                raise Exception(f"Invalid value for key {key}")

            setattr(symbol, key, lookups[key][value.lower()])
         

        symbols = []
         
        while True:
            
            tok = next_tok(lexer, no_fail=False)
            
            if not tok:
                break

            if tok.type != 'FUNCTION_IDENTIFIER':
               syntax_error(tok, 'Expected another symbol declaration')
            
            current_symbol = Symbol()
            
            current_symbol.type_ = SymbolType.FUNCTION

            tok = next_tok(lexer)
            
            if tok.type != 'VAR_NAME':
                syntax_error(tok, "Expected VAR_NAME token.")
            
            current_symbol.name = tok.value.encode()

            tok = next_tok(lexer)

            if tok.type != '@':
                syntax_error(tok, "Expected '@' token.")
            
            tok = next_tok(lexer)

            if tok.type != 'INT':
                syntax_error(tok, "Expected INT token.")
            
            current_symbol.value = tok.value
            initiated_more_values = False

            while True:

                tok = next_tok(lexer)
                
                if tok.type == ';':
                    symbols.append(current_symbol)
                    break
                
                if not initiated_more_values and tok.type == ',':
                    tok = next_tok(lexer)
                    initiated_more_values = True

                if tok.type != 'VAR_NAME':
                    syntax_error(tok, "Expected either ';' or VAR_NAME token.")
                
                key = tok.value

                tok = next_tok(lexer)
                
                if tok.type != '=':
                    syntax_error("Expected '=' token.")
                
                tok = next_tok(lexer)

                if tok.type not in ('STRING_LITERAL', 'INT', 'VAR_NAME'):
                    syntax_error("Expected either STRING_LITERAL, INT, or VAR_NAME token")
                value = tok.value
                
                symbol_set_value(current_symbol, key, value) 
                
        return symbols



