# rule-id-lookup

Exploit for [this patch](https://github.com/torvalds/linux/commit/36d5b2913219ac853908b0f1c664345e04313856). For Ubuntu `jammy`, kernel version `5.15.0-41-generic`.

Compile:

```
g++ -fdiagnostics-color=always -no-pie -g -Wall -O0 -std=c++17 exploit.cpp -o nf_obj -lmnl -lnftnl
```
