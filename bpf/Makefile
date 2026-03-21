CC = clang-14
CFLAGS = -O2 -g -Wall

all: chameleon.out

# --- Chameleon 规则 ---
chameleon.bpf.o: chameleon.bpf.c
	$(CC) -target bpf -D__TARGET_ARCH_x86 -c $(CFLAGS) -mcpu=v3 \
		-idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include \
		-idirafter /usr/local/include \
		-idirafter /usr/include/x86_64-linux-gnu \
		-idirafter /usr/include \
		$< -o $@

chameleon.skel.h: chameleon.bpf.o
	sudo /usr/local/sbin/bpftool gen skeleton $< > $@

chameleon.out: chameleon.c chameleon.skel.h
	$(CC) $(CFLAGS) $< -o $@ -L/usr/local/lib64 -lbpf

clean:
	rm -f *.o *.skel.h *.out