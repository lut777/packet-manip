all: build-ebpf build run

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm \
		ebpf/main.c \
		-g \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o
	/root/go/bin/go-bindata -pkg main -prefix "ebpf/bin" -o "probe.go" "ebpf/bin/probe.o"

build:
	go build -o bin/main .

run:
	sudo bin/main

clean:
	rm ./bin/main
	rm ./probe.go
	rm ./ebpf/bin/probe.o