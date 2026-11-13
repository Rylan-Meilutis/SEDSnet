#!/bin/bash
# Per-call Cortex-M4 instruction counts of the time sync hot paths, built with
# the firmware profile (opt-level "z", fat LTO) and run under QEMU mps2-an386
# with one instruction per translation block. Exits non-zero when a path
# exceeds its budget (5.0.0 before/after: network_time_ms 10840 -> ~1800,
# read_unix_ms 708 -> ~240, from_unix_ns 2425 -> ~280).
# Needs: rustup target thumbv7em-none-eabihf, qemu-system-arm, arm-none-eabi-nm.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
# Build from outside the repo: its .cargo/config.toml adds firmware link
# arguments for this target that a bare test binary does not want.
(cd / && CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS="-C link-arg=-Tlink.x" \
  cargo build --release --offline -q --manifest-path "$HERE/Cargo.toml" \
  --target thumbv7em-none-eabihf --target-dir "$HERE/target")
cd "$HERE"
ELF=target/thumbv7em-none-eabihf/release/mcu-icount
M=$(arm-none-eabi-nm "$ELF" | awk '$3=="marker"{print $1}')
M=$(printf '%x' $((16#$M & ~1)))
LOG=$(mktemp)
qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel "$ELF" \
  -accel tcg,one-insn-per-tb=on -d exec,nochain -D "$LOG" >/dev/null 2>&1 || true
python3 - "$LOG" "$M" <<'PY'
import sys,re
log,marker=sys.argv[1],int(sys.argv[2],16)
n=0; marks=[]
for line in open(log):
    m=re.search(r'Trace .*?\[[0-9a-f/]+?([0-9a-f]{8})/',line)
    if not m: continue
    pc=int(m.group(1),16)
    n+=1
    if pc==marker: marks.append(n)
N=64
d=[marks[i+1]-marks[i] for i in range(len(marks)-1)]
base=d[0]
names=['read_unix_ms (slewing)','read_unix_ms (slew done)','NetworkTime::from_unix_ns']
counts={name:(v-base)/N for name,v in zip(names,d[1:4])}
# d[4] is router setup; d[5] the router reads; d[6] the same loop without them.
counts['Router::network_time_ms']=(d[5]-d[6])/N
budget={'read_unix_ms (slewing)':500,'read_unix_ms (slew done)':320,
        'NetworkTime::from_unix_ns':360,'Router::network_time_ms':2400}
over=False
for name,v in counts.items():
    flag='' if v<=budget[name] else f'  OVER BUDGET {budget[name]}'
    over|=bool(flag)
    print(f'{name}: {v:.0f} instructions/call{flag}')
sys.exit(1 if over else 0)
PY
rm -f "$LOG"
