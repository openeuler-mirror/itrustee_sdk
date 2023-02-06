You need to install the pycryptodome library of python and run the make command to compile the binary of ta.

qta is trusted application for remote attestion, when compile it, some libraries and tools are depended on.

1. cjson: download it, put it to "src" directory, rename it into cJSON
2. miracl core: when you enable DAA feture in makefile or cmakelist, download it and execute follow cmd:
    2.1 copy c directory in miracl into src, example copy miracl/c ./src/miracl-c
    2.2 cd ./src/miracl-c;
    2.3 export CC=gcc CFLAGS=-fPIC; python3 config64.py -o 33;unset CC CFLAGS
    2.4 cp core.a libcore.a
3. make for make cmd; or sh config.sh for cmake cmd
     
