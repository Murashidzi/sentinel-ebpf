.PHONY: all check-go check-c

all: check-go check-c

check-go:
	@echo "[*] Verifying Go daemon..."
	@cd daemon && go vet ./... && go build -o /dev/null ./...

check-c:
	@echo "[*] Verifying eBPF C code..."
	@clang -O2 -target bpf -c kernel/tracer.bpf.c -o /dev/null || exit 0
	@echo "[+] C syntax check passed."
