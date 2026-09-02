nob.h - Next generation of the NoBuild
This library is the next generation of the NoBuild idea. "nob" stands for "nobuild", but it's shorter and more suitable as a prefix for a library.

NoBuild Idea
The idea is that you should not need anything but a C compiler to build a C project. No make, no cmake, no shell, no cmd, no PowerShell etc. Only C compiler. So with the C compiler you bootstrap your build system and then you use the build system to build everything else.
NoBuild is more like writing shell scripts but in C.

Advantages of NoBuild
Extremely portable builds across variety of systems including (but not limited to) Linux, MacOS, Windows, FreeBSD, etc. This is achieved by reducing the amount of dependencies to just a C compiler, which exists pretty much for any platform these days.
You end up using the same language for developing and building your project. Which may enable some interesting code reusage strategies. The build system can use the code of the project itself directly and the project can use the code of the build system also directly.
You get to use C more.
...
Disadvantages of NoBuild
You need to be comfortable with C and implementing things yourself. As mentioned above this is like writing shell scripts but in C.
You get to use C more.
...
Why is it called "nobuild" when it's clearly a build tool?
You know all these BS movements that supposedly remove the root cause of your problems? Things like NoSQL, No-code, Serverless, etc. This is the same logic. I had too many problems with the process of building C projects. So there is nobuild anymore.

How to use the library in your own project
The only file you need from here is nob.h. Just copy-paste it to your project and start using it. See how_to/ folder for examples.



# Two Stage Build

Quite often when your project grows big enough you end up wanting to configure the build of your application: different sets of enabled features, compilation flags, etc. The recommended approach to this in nob is to setup Two Stage Build™ system. That is [nob.c](./nob.c) does not do any actual work except generating initial `./build/config.h` and building `./src_build/nob_configed.c` (which `#include`-s the `./build/config.h` file) and then running it.

Exact details of the setup is up to your. Here we present just one way of doing it. In fact you have a freedom to do as many stages of your build as you want, analysing your environment in all sorts of different ways (you literally have a system programming language at your disposal). The whole point of nob is that you bootstrap it ONLY with `cc -o nob nob.c` (no additional flags or actions should be required form the user) and the rest is taken care of by your C code.

## Quick Start

```console
$ cc -o nob nob.c
$ ./nob
$ ./build/main
$ <edit ./build/config.h>
$ ./nob
$ ./build/main
```
