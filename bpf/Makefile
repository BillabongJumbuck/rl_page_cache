CC = clang-14
CFLAGS = -O2 -g -Wall

all: chameleon.out
mru: cache_ext_mru.out

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

cache_ext_mru.bpf.o: cache_ext_mru.bpf.c
	$(CC) -target bpf -D__TARGET_ARCH_x86 -c $(CFLAGS) -mcpu=v3 \
		-idirafter /usr/lib/llvm-14/lib/clang/14.0.0/include \
		-idirafter /usr/local/include \
		-idirafter /usr/include/x86_64-linux-gnu \
		-idirafter /usr/include \
		$< -o $@

cache_ext_mru.skel.h: cache_ext_mru.bpf.o
	sudo /usr/local/sbin/bpftool gen skeleton $< > $@

cache_ext_mru.out: cache_ext_mru.c cache_ext_mru.skel.h
	$(CC) $(CFLAGS) $< -o $@ -L/usr/local/lib64 -lbpf


clean:
	rm -f *.o *.skel.h *.out