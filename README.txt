for linux

1. download & build MIRACL
Download MIRACL repository for "https://github.com/miracl/MIRACL.git",
and build it acording miracl/readme.txt
example: 
in linux64, run "bash linux64" and get three files: miracl.a miracl.h mirdef.h.

2. install tcl8.5-dev
For ubuntu, use the command : "sudo apt-get install tcl8.5-dev"

3. build the extend commands
Copy miracl.a miracl.h mirdef.h generated in step 1 to c_extend/,
and run make command in a shell. Copy the libcrypto.so to cryptove/lib/.

4. test & use
./cryptove/test/main_test.tcl for test.
run tclsh, and "source cryptove.tcl" for using.

for windows
to be continue.
