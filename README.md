This is a small Python script to display the call tree of
an Atmel AVR program. It also shows the stack size for each
function in the tree.

It uses the .lss file as input and displays the tree at stdout.

The function names are "mangled" but you can feed it though c++filt
to get more useful function names. Here is an example of its
usage:

$ analyse_avr_call_tree.py my_sketch.lss
