# mlibinjector
A handy script to inject Frida-Gadgets and enable debugging in Android applications.

Now with Python3 support.

Based on previous work from:
- Sahil Dhar (https://github.com/sahildhar/mlibinjector)


# Installation

Execute following commands from your terminal 

To install mlibinjector for current user only

```python3 setup.py install --user```

To install mlibinjector for all users of the system

```sudo python3 setup.py install```


```
Usage: mlibinjector [options] apkfile

[mlibinjector 2.0.1] -  A handy script to inject Frida-Gadgets and enable
debugging in Android applications - TheZero (@Th3Zer0) & Sahil Dhar (@0x401)

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -s                    Sign apk
  -d                    Decompile using apktool
  -b                    Build & Sign & Zipalign
  -e                    Enable debug mode for apk
  -n                    Inject a custon network_security_config.xml file
  -i                    Inject frida-gadget in *listen* mode (requires -p)
  -p LIBPATH            Absolute path to downloaded frida-gadgets (.so) files
  -c CONFPATH           Absolute path to the frida-gadgets config file
                        (.config.so)
  -f                    Force decompilation and overwrite previous one
  --network=NETCONFPATH
                        Absolute path to the network_security_config.xml file
  --port=PORT           Listen frida-gadget on port number in *listen mode*
  --host=HOST           Listen frida-gadget on specific network interface in
                        *listen mode*
  --script-file=SCRIPTFILE
                        Path to script file on the device
  --script-dir=SCRIPTDIR
                        Path to directory containing frida scripts on the
                        device
  --native-lib=NATIVELIB
                        Name of exisiting native lib. Example "libnative-
                        lib.so"
  --arch=ARCH           Add frida gadget for particular
                        arch.(arm64-v8a|armeabi-v7a|x86|x86_64)
  --random              Randomize frida-gadget name
  -V                    Verbose

```

### Following advanced options can be used to bypass anti-debugging features set by the application specifically for Frida
```
--arch ARCH           Use this option only when you are sure about the arch of the device which will run the modified application
--port PORT           Run frida-server on custom port
--script-file SCRIPTFILE
                      This will run frida in serverless/script mode which mean it will load the script from the device.
--script-dir SCRIPTDIR
                      This will run frida in serverless/script mode and load the scripts present in defined file system directory on the device.
--native-lib NATIVELIB
                      If your application uses native code, you can use this option to specify the lib used by the application. This will inject frida-gadget as a dependency to already existing native libs (this option does not require tampering smali code).

--random              This will randomize the name of frida-gadgets as well as associated config files.
```

## Examples:

### Build and Sign
```
mlibinjector box.apk -b -V
```

### Enable Debug mode
```
mlibinjector box.apk -e -V
```

### Inject a default network_security_config.xml file
```
mlibinjector box.apk -n -V
```

### Inject a network_security_config.xml file
```
mlibinjector box.apk -n -V --network .\net.xml
```

### Inject Frida gadgets for all supported architectures.
```
mlibinjector box.apk  -i -p "C:\Tools\Android\androidtools\mlibinjector\frida-gadgets" -V
```

### Inject Frida gadgets (For particular architecture)
> Use this option only when you are sure about the arch you are building the app for.
```
mlibinjector box.apk  -i -p "C:\Tools\Android\androidtools\mlibinjector\frida-gadgets" --arch x86 -V
```

### Randomize Frida gadget name for device arch:x86
```
mlibinjector box.apk  -i -p "C:\Tools\Android\androidtools\mlibinjector\frida-gadgets" --arch x86 -V --random
```

### Run frida gadget on custom port for device arch:x86
> Below command will run frida gadget on custom port 21212.
```
mlibinjector box.apk  -i -p "C:\Tools\Android\androidtools\mlibinjector\frida-gadgets" --arch x86 -V --random --port 21212
```

### Inject frida gadget in serverless mode for device arch:x86
> Below command will inject frida gadet in serverless mode which means scriptfile present on the device filesystem /data/local/tmp/frida-script.js will be executed by the agent as soon as the frida library is loaded by the box.apk application
```
mlibinjector box.apk  -i -p "C:\Tools\Android\androidtools\mlibinjector\frida-gadgets" --arch x86 -V --random --script-file "/data/local/tmp/frida-script.js"
```

### Inject frida gadget in serverless mode for device arch:x86
> Below command will inject frida gadet in serverless mode which means frida gagdet will load all the scripts present in the directory /data/local/tmp from the device filesystem as soon as the frida library is loaded by the box.apk application
```
mlibinjector box.apk  -i -p "C:\Tools\Android\androidtools\mlibinjector\frida-gadgets" --arch x86 -V --random --script-dir "/data/local/tmp/scripts"
```

### Inject frida gadget in serverless mode for device arch:x86 using existing native library
> This command will add frida gadet as a dependency to existing native library and thus will not tamper smali code/AndroidManifest.xml file.
```
mlibinjector box.apk  -i -p "C:\Tools\Android\androidtools\mlibinjector\frida-gadgets" --arch x86 -V --random --script-dir "/data/local/tmp" --native-lib "libnative-lib.so"
```

# TODO:
- Use a better signing script (apksigner)
- Inject smali revshell / drozer
- Add custom permissions
