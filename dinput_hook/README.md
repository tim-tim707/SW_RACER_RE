hooks using dinput.dll. Currently used for renderer replacement.

# Building
In the main directory (`SW_RACER_RE/`) run the following commands in a cmd:

```
mkdir build && cd build && ^
cmake -G "MinGW Makefiles" .. -DPYTHON_EXECUTABLE=<pathToYourPython.exe> -DGAME_DIR=<pathToYourGameDir> ^
make
```

You can omit the `-G MinGW Makefiles` if you already have nmake installed
