from slugify import slugify
import random
import sys

with open('/usr/share/dict/usa', 'r') as w:
    words = list(map(lambda x: x[:-1], w.readlines()))


def gen_symbol_name(elems=3):
    return slugify(' '.join([random.choice(words) for _ in range(elems)])).replace('-', '_')


def gen_symbol(type_, *args):
    if type_ == "function":
        return f"FUNC_SYMBOL({args[0]})"
    elif type_ == "var":
        return f"VAR_SYMBOL({args[0]}, {args[1]})"



n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000

with open('generated_symbols.txt', 'w') as x:
    wline = lambda z: x.write(z + '\n')

    for _ in range(n):
        wline(gen_symbol('function', gen_symbol_name()))
        wline(gen_symbol('var', gen_symbol_name(), random.randint(1, 2**30)))
