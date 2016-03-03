%module(package="nrs") bzip2

%{
#define SWIG_FILE_WITH_INIT
#include "bzlib.h"
%}

