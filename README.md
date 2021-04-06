Patch it
----
Crack for **Learning** Purpose   

* [010Editor](#010Editor)

## Description
File *.1337 is generated by [x64dbg](https://github.com/x64dbg/x64dbg), telling that the byte from RVA should be changed to the other.    
It is human-readable and used to clearly show the patches for raw file.    

File format:
```
>010editor.exe              # raw file
00000000001E4188:0F->E9     # RVA:from_byte->to_byte
...
```
File *.patch is generated by [bsdiff](https://github.com/mendsley/bsdiff) and used by bspatch to patch raw file.

## Usage
For guys just want to get patched binary:   
Ensure that [bsdiff/bspatch](https://github.com/mendsley/bsdiff) is by your hand, otherwise get it via your package manager or something.
1. Download patch file you need in this repo.
2. Just patch it!
```zsh
#         raw file      patched file          patch
$ bspatch 010Editor.exe 010Editor_patched.exe 010Editor.patch
```

## 010Editor
* bypass license checking fully (local and online)
* label registration status with 'Cracked'   

#### Note that keygen isn't implemented, but it doesn't matter in fact.