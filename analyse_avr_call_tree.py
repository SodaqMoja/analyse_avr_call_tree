#!/usr/bin/env python
#
# Copyright (c) 2014 Kees Bakker.  All rights reserved.
#
# This utility analyses the AVR .lss file and it displays
# a call tree with annotated with the stacksize.


import sys
import re
import argparse

all_funcs = {}
class Function(object):
    # First line: 00000978 <realloc>:
    first_line_pat = re.compile(r'(?P<addr>[0-9a-f]+)\s+<(?P<name>\w+)>:')
    # Instruction line
    # 9f6:	cd 01       	movw	r24, r26
    # 9f8:	20 df       	rcall	.-448    	; 0x83a <free>
    # a08:	e0 91 f9 04 	lds	r30, 0x04F9
    # a0c:	f0 91 fa 04 	lds	r31, 0x04FA
    instr_line_pat = re.compile(r'''(?P<addr>[0-9a-f]+): \s+
                       (?P<byts1>[0-9a-f]{2} \s [0-9a-f]{2}) \s+
                       ((?P<byts2>[0-9a-f]{2} \s [0-9a-f]{2}) \s+)?
                       (?P<opc>\w+) (\s+ (?P<rest>.*))?''', re.VERBOSE)
    # The operand and the optional comment is the "rest" part.
    rest_pat = re.compile(r'(?P<opnd>\S+) \s+ ; \s+ (?P<addr>[x0-9a-f]+) \s+ <(?P<name>\w+)>', re.VERBOSE)

    #
    # Patterns to discover the "stack frame" of a function. How many
    # bytes does a function need on the stack?

    # This is a typical sequence to create (14 bytes) stack space in a function
    #    574c:	cd b7       	in	r28, 0x3d	; 61
    #    574e:	de b7       	in	r29, 0x3e	; 62
    #    5750:	2e 97       	sbiw	r28, 0x0e	; 14
    #    5752:	0f b6       	in	r0, 0x3f	; 63
    #    5754:	f8 94       	cli
    #    5756:	de bf       	out	0x3e, r29	; 62
    #    5758:	0f be       	out	0x3f, r0	; 63
    #    575a:	cd bf       	out	0x3d, r28	; 61

    # Here is another sequence, 128 bytes stack space
    #    4970:	cd b7       	in	r28, 0x3d	; 61
    #    4972:	de b7       	in	r29, 0x3e	; 62
    #    4974:	c0 58       	subi	r28, 0x80	; 128
    #    4976:	d1 09       	sbc	r29, r1
    #    4978:	0f b6       	in	r0, 0x3f	; 63
    #    497a:	f8 94       	cli
    #    497c:	de bf       	out	0x3e, r29	; 62
    #    497e:	0f be       	out	0x3f, r0	; 63
    #    4980:	cd bf       	out	0x3d, r28	; 61

    def __init__(self, lines):
        m = self.first_line_pat.match(lines[0])
        if m:
            self._name = m.group('name')
            self._addr = int(m.group('addr'), 16)
            self._body = lines[1:]
        else:
            self._name = 'unknown'
            self._addr = 0
            self._body = lines

        # Make a list of callees
        self._callees = set()
        for b in self._body[:-1]:
            self.analyse_call(b)
        # Last line is special, it can be a tail call (i.e. jmp or rjmp)
        self.analyse_call(self._body[-1], True)

        # Compute stack frame
        self._stacksize = self.count_pushes()

    def analyse_call(self, line, is_last=False):
        'Find the name of the function call'
        m2 = self.instr_line_pat.match(line.strip())
        if m2:
            opc = m2.group('opc')
            rest = m2.group('rest')
            if opc in ('call', 'rcall') or is_last and opc in ('jmp', 'rjmp'):
                m3 = self.rest_pat.match(rest)
                if m3:
                    callee = m3.group('name')
                    self._callees.add(callee)
            elif opc in ('icall',):
                pass
            else:
                if opc.endswith('call'):
                    #print(">>>" + line)
                    pass

    # Count pushes, if present
    # Find stackpointer change, if present
    def count_pushes(self):
        count = 0
        done_pushes = False
        nr_in = 0
        for b in self.body:
            m = self.instr_line_pat.match(b.strip())
            if m:
                opc = m.group('opc')
                if not done_pushes and opc == 'push':
                    count = count + 1
                    continue
                else:
                    done_pushes = True
                if nr_in < 2 and opc == 'in':
                    nr_in = nr_in + 1
                    continue
                if nr_in == 2 and opc in ('sbiw', 'subi'):
                    # Expect something like this: r28, 0x0e	; 14
                    rest = m.group('rest')
                    v = rest.split()
                    if v[0] == 'r28,':
                        num = int(v[1], 16)
                        count = count + num
                        break
        return count

    @property
    def name(self):
        return self._name

    @property
    def addr(self):
        return self._addr

    @property
    def stacksize(self):
        return self._stacksize

    @property
    def body(self):
        return self._body

    @property
    def callees(self):
        return [c for c in self._callees]

    def __str__(self):
        name = self.name
        addr = self.addr
        return "<Function name=%(name)s addr=0x%(addr)04x>" % locals()

# This is a function to split the text into chunks for each function
symbol_pat = re.compile(r'\n\n(?=[0-9a-f]+ )', re.MULTILINE)
def get_funcs(args, blob):
    chunks = symbol_pat.split(blob)
    #funcs = [c for c in chunks if c.endswith('ret')]
    funcs = [f.splitlines() for f in chunks]
    return map(Function, funcs)

def process_lss(args, lssfname):
    blob = open(lssfname).read()
    funcs = get_funcs(args, blob)
    for f in funcs:
        all_funcs[f.name] = f
    return funcs

def dump_funcs(args, funcs):
    #print([str(f) for f in funcs])
    for f in funcs:
        print(str(f))
        callees = f.callees
        if len(callees) > 0:
            print('>>\t' + '\n>>\t'.join(callees))
        #print('\n'.join(f.body))

def print_call_tree(args, funcname, stacksize, level):
    if funcname in all_funcs:
        func = all_funcs[funcname]
    else:
        func = None
    indent = '  ' * level
    my_stacksize = 0
    if func is not None:
        my_stacksize = func.stacksize
    stacksize = stacksize + my_stacksize
    print("%(stacksize)3d %(my_stacksize)3d %(indent)s%(funcname)s" % vars())
    indent = '  ' * (level + 1)
    indent = ' ' * 8 + indent    # To account for the two %3d above
    if level > 20:
        print(indent + " !!!! Nested too deeply")
        return
    max_ss = stacksize
    if func is not None:
        for c in func.callees:
            if c == funcname:
                print(indent + funcname + " !!!! Recursive call")
            else:
                this_ss = print_call_tree(args, c, stacksize, level + 1)
                max_ss = max(this_ss, max_ss)
    return max_ss

def main():
    parser = argparse.ArgumentParser(description='Analyse AVR call tree from .lss file')
    parser.add_argument('lss',
                        help='the .lss file')    
    parser.add_argument('func',
                        help='the function to print the call tree for')    
    args = parser.parse_args()
    funcs = process_lss(args, args.lss)
    func = args.func
    if args.func not in all_funcs:
        sys.stderr.write('ERROR: Function "%(func)s" not found\n' % locals())
    ss = print_call_tree(args, func, 0, 0)
    print("Deepest stacksize: %(ss)d" % vars())

if __name__ == '__main__':
    import traceback
    try:
        main()
    except SystemExit:
        pass
    except:
        traceback.print_exc()
