import logging

import ply.lex as lex

logger = logging.getLogger(__name__)


'''
function this_is_a_symbol @ 0x1000, size=100 
'''

tokens = (
    'INT',
    'FUNCTION_IDENTIFIER',
    'VAR_NAME',
    'STRING_LITERAL')

def t_INT(t):
    r'0x[0-9a-fA-F]+|0b[0-1]+|0o[0-7]+|\d+'
        
    bases = {
        '0x': 16,
        '0b': 2,
        '0o': 8
    }
    
    for k, v in bases.items():
        if t.value.startswith(k):
            t.value = int(t.value, v)
            return t
    
    t.value = int(t.value)
    return t

def t_STRING_LITERAL(t):
    r'\"([^\\\"]|\\.)*\"'
    
    t.value = t.value[1:-1]
    t.value = t.value.replace('\\"', '"')
    t.value = t.value.replace('\\\\', '\\')
    
    return t

def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)

# for priority
def t_FUNCTION_IDENTIFIER(t):
    r"function"
    return t

t_VAR_NAME = "[a-zA-Z_][a-zA-Z0-9]*"
t_ignore = ' \t'

literals = '@,=;'

def t_error(t):
    logger.warn(f"Illegal character encountered on line {t.lexer.lineno}: '{t.value[0]}'")
    t.lexer.skip(1)

def create_lexer():
    return lex.lex()

