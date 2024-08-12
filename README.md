# KaiCenat

Shellcode loader that embeds XOR-encrypted shellcode into a DLL and clones exports to a valid Windows library for DLL hijacking.

![](https://assets.bwbx.io/images/users/iqjWHBFdfxIU/iMorSlUY7xpM/v5/-1x-1.png)

Requirements:
- Python3
- Visual Studio

```
cd KaiCenat
.\build.ps1 -shellcode shellcode.bin -target C:\Windows\System32\xmllite.dll
```

Credits:
- @monoxgas - [Stability Hooking](https://gist.github.com/monoxgas/5027de10caad036c864efb32533202ec)
- @monoxgas - [Koppeling](https://github.com/monoxgas/Koppeling)
- @9emin1 - [Charlotte](https://github.com/9emin1/charlotte)
