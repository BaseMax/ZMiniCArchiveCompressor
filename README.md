# ZMini C Archive Compressor

C software to compress and archive files with CLI console. (miniz)

## Compile

```
gcc compressor.c -o compressor -O3
```

## Using

```
./compressor c input.txt output.x
./compressor d output.x input.txt
```

##### max@base:~/compress$ ./compressor d o.txt oi.txt

```
Mode: d, Level: 10
Input File: "o.txt"
Output File: "oi.txt"
Input file size: 2107
Total input bytes: 2107
Total output bytes: 4275
Done.
```

##### max@base:~/compress$ ./compressor c i.txt o.txt

```
Mode: c, Level: 10
Input File: "i.txt"
Output File: "o.txt"
Input file size: 4275
Total input bytes: 4275
Total output bytes: 2107
Done.
```

Tested on: Linux base 5.3.0-40-generic (Cross-platform/ miniz)

## Similar Projects

- https://github.com/BaseMax/MiniPHPArchiveCompressor
- https://github.com/BaseMax/MiniArchiveCompressor

### Credit

Thanks to Rich Geldreich, Rich Geldreich, Alex Evans, Paul Holden, Thorsten Scheuermann, Matt Pritchard, Sean Barrett, Bruce Dawson, and Janez Zemva. (miniz library)

---------

# Max Base

My nickname is Max, Programming language developer, Full-stack programmer. I love computer scientists, researchers, and compilers. ([Max Base](https://maxbase.org/))

## Asrez Team

A team includes some programmer, developer, designer, researcher(s) especially Max Base.

[Asrez Team](https://www.asrez.com/)
