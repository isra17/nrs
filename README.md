# NRS
## NSIS Reversing Suite

NRS is a set of Python librairies used to unpack and analysis NSIS installer's data. It also feature an IDA plugin used to disassembly the NSIS Script of an installer.

![nrs screenshot](http://i.imgur.com/0EQE6gu.png)

### Installation

NRS is available through [Pypi](https://pypi.python.org/pypi/nrs) or this repositoy.
To use with IDA, the native module must be build in 32 bits since IDA use its own 32 bits Python runtime on x64_86 systems.

It is recommended to use [IDAPython-virtualenv](https://github.com/Kerrigan29a/idapython_virtualenv) to manage Python dependancies in IDA.

Change working directory to IDA root directory: `cd $IDA_DIR`

To setup virtualenv: `virtualenv -p python2 venv && source venv/bin/activate`.

Install nrs from Pypi and build in 32 bits: `CFLAGS=-m32 LDFLAGS=-m32 pip install nrs`.

It can also be installed from the git repository: `CFLAGS=-m32 LDFLAGS=-m32 pip install -e $PATH_TO_LOCAL_REPO`.

Create symbolic links from NRS modules to IDA folders: `python -c 'import nrs.ida;nrs.ida.install()`. The `venv` folder must be in the IDA folder or you must pass the ida folder path to the `nrs.ida.install` function.

Open IDA and load any NSIS installer!

If you have errors about `nrs` modules not found, ensure you run IDA from the Python venv.
A simple way is simply to run it from command line with your virtualenv activated:
```
$ source venv/bin/activate
$ ./idaq
```
