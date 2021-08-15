# unstrip

`unstrip` is a small utility for adding back debug information to stripped ELF files.

Being able to add back debugging information can be useful for easing the task of debugging and reversing closed-source native applications. I've personally accumulated lots of wasted time simply copying over offsets from IDA to gdb and eventually got fed up with it.

There's a few scripts floating on github that attempt to achieve the same thing, but sadly they're old, not portable, and flawed in several ways. This is why I decided to write my own. 

`unstrip` supports importing symbols from the following media:
   - IDA (the interactive disassembler) databases. (.idb, .i64)
   - A custom human-redable file format
   - JSON

`unstrip` is platform-agnostic (mostly due to the awesome [pyelftools](https://github.com/eliben/pyelftools) project!). It works with 32 bit ELFs, 64 bit ELFs, on executables for any major operating system that uses ELF.

I'm planning to implement the following eventually:
  - Importing symbols other than function symbols (!!important)
  - Importing symbols from Ghidra databases
  - Adding back type info
  - Adding back DWARF debug information in general
    - Ideally, you would be able to import **full** debug information with only an IDA database available. It would allow for source-level debugging with only decompiled IDA pseudocode. 

## Installation instructions
Simply run
```
python -m pip install git+https://github.com/pqlx/unstrip
```

## Usage
The CLI tool can be invoked either by running `unstrip` or `python -m unstrip`. The usage is as follows:

```
usage: unstrip [-h] [--symidb SYMIDB] [--symtxt SYMTXT] [--outfile OUTFILE] infile

positional arguments:
  infile                Path to excutable that needs to be unstripped.

optional arguments:
  -h, --help            show this help message and exit
  --symidb SYMIDB       Path to IDB (IDA database) to fetch symbols from.
  --symtxt SYMTXT       Path to text file describing symbols
  --outfile OUTFILE, -o OUTFILE
                        Path to write resulting executable to (defaults to '_unstripped' suffix).

```

You can also use `unstrip` in your python programs. Simply `import unstrip`. (for now, the code serves as documentation)

The file format that's used to declare symbol is best explained with an example (`example.syms`):

```
function main @ 0x4e4a, size = 25;
function hello_world @ 0x4e63, size = 14 visibility=public;
function foo_bar_baz @ 0x4e71;
```

Each line contains one entry. Every entry has to close with a semicolon. The parts before the comma are mandatory. The available symbol data you can set are the fields `(visibility, bind, size)`. `visibility` and `bind` are set to GLOBAL and DEFAULT if omitted.

This file format is subject to change. Update at your own risk. 
