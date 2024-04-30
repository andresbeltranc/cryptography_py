# cryptography_py

## Required software

1. Conan package manager 2.0 -> https://conan.io
2. OpenSSL lib
3. C++ Compiler
4. pybind11 as a lib or clone the git repository in the project root folder.

### Setting up Conan:

To compile the app, you need to have conan installed and configured on your system.
When you've run conan you should see a folder in the following path: C:/Users/[Your User]/.conan
https://docs.conan.io/2/tutorial.html
This folder contains any libraries you install as well as some configuration files of the default profile file doesn't exist you would have to run the folowing command:
`conan profile detect`
In the profiles folder you can setup different configurations for the conan package manager.

Please edit the following file: C:/Users/[Your User]/.conan2/profiles/default
Make sure it includes the following configuration:
```
[settings]
arch=x86_64               #arch of the current device 
build_type=Release/Debug  #build type
compiler=msvc             #compiler
compiler.cppstd=17        # C++ version
compiler.runtime=dynamic  # runtime
compiler.version=192      #compiler version
os=Windows                # current OS
```

After conan is installed and configured, you can install the necessary dependencies by running the following command in the root of the project

`conan install . -of ./conan_libs  -s build_type=Release --build=missing`

To Modify the cryptography_py dependencies you would have to modify the conanfile.py file.
