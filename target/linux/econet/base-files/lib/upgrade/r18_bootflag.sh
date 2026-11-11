# SPDX-License-Identifier: GPL-2.0
#
# D-Link R18 boot flags in the "benv" partition (bootloader CSID store).
# Format and semantics reverse engineered from the stock bootloader:
#   0x80cc0000 sw_curboot_id   slot booted this time (written by the bootloader)
#   0x80cc0001 sw_commit       last known-good slot (0 = tclinux/A, 1 = tclinux_slave/B)
#   0x80cc0002 sw_active       slot to boot; reset to sw_commit if a try was not committed
#   0x80cc0003 sw_tryactive    one-shot: boot slot (value-1) once
# Block 0 layout: 16-byte stag header (sum over bytes 0..13 at 14), 16-byte csxf
# header ('CS', sum at 18 over csxf header with sum=0 + body, odd tail padded 0xff),
# body = {u32 id, u16 len, value}... u32 0. Sums are ~(16-bit one's complement sum).
#
# Only existing 4-byte records are modified; the section length never changes.
# Every write is verified by parsing the new block and comparing the read-back.

R18_BENV_BS=131072

r18_benv_mtd() {
	local mtd
	mtd=$(grep '"benv"' /proc/mtd | cut -d: -f1)
	[ -n "$mtd" ] && echo "$mtd"
}

# _r18_benv_awk <file> <mode> [name=value...]
# mode "show": print records; mode "patch": print "offset value" for changed bytes.
# Exit status 1 on any format/checksum error.
_r18_benv_awk() {
	local file="$1" mode="$2"
	shift 2
	hexdump -v -n 4096 -e '1/1 "%u\n"' "$file" | awk -v mode="$mode" -v sets="$*" '
	function u16(i) { return b[i] + 256 * b[i + 1] }
	function u32(i) { return u16(i) + 65536 * u16(i + 2) }
	function osum(s, e,   i, sum, w) {
		sum = 0
		for (i = s; i < e; i += 2) {
			w = b[i] + 256 * ((i + 1 < e) ? b[i + 1] : 255)
			sum += w; sum = (sum % 65536) + int(sum / 65536)
		}
		return sum
	}
	function inv(x) { return 65535 - x }
	function csxf_sum(   s0, s1, r) {
		s0 = b[18]; s1 = b[19]; b[18] = 0; b[19] = 0
		r = inv(osum(16, 32 + blen) ); b[18] = s0; b[19] = s1
		return r
	}
	{ b[NR - 1] = $1 + 0 }
	END {
		if (NR < 64) { print "benv: short read" > "/dev/stderr"; exit 1 }
		if (b[2] != 36 || b[3] != 43) { print "benv: bad stag magic" > "/dev/stderr"; exit 1 }
		if (u16(14) != inv(osum(0, 14))) { print "benv: stag checksum mismatch" > "/dev/stderr"; exit 1 }
		if (u16(16) != 21315) { print "benv: bad csxf magic" > "/dev/stderr"; exit 1 }
		blen = u32(20)
		if (blen < 4 || 32 + blen > NR) { print "benv: bad body length" > "/dev/stderr"; exit 1 }
		if (u16(18) != csxf_sum()) { print "benv: csxf checksum mismatch" > "/dev/stderr"; exit 1 }
		split("sw_curboot_id sw_commit sw_active sw_tryactive", nm, " ")
		o = 32; n = 0
		while (o + 4 <= 32 + blen) {
			id = u32(o); if (id == 0) break
			len = u16(o + 4)
			n++; rid[n] = id; roff[n] = o + 6; rlen[n] = len
			o += 6 + len
		}
		if (mode == "show") {
			for (i = 1; i <= n; i++) {
				name = "?"
				if (id_ok(rid[i])) name = nm[rid[i] - 2160852992 + 1]
				val = (rlen[i] == 4) ? u32(roff[i]) : "len" rlen[i]
				printf "%s=%s\n", name, val
			}
			exit 0
		}
		cnt = split(sets, kv, " ")
		for (k = 1; k <= cnt; k++) {
			split(kv[k], p, "=")
			want = -1
			for (j = 1; j <= 4; j++) if (nm[j] == p[1]) want = 2160852992 + j - 1
			if (want < 0 || p[2] !~ /^[0-9]+$/) { print "benv: bad setting " kv[k] > "/dev/stderr"; exit 1 }
			found = 0
			for (i = 1; i <= n; i++) if (rid[i] == want && rlen[i] == 4) {
				v = p[2] + 0; found = 1
				for (x = 0; x < 4; x++) { nb = v % 256; v = int(v / 256)
					if (b[roff[i] + x] != nb) { b[roff[i] + x] = nb; ch[roff[i] + x] = 1 } }
			}
			if (!found) { print "benv: record not present: " p[1] > "/dev/stderr"; exit 1 }
		}
		s = csxf_sum()
		if (b[18] != s % 256) { b[18] = s % 256; ch[18] = 1 }
		if (b[19] != int(s / 256)) { b[19] = int(s / 256); ch[19] = 1 }
		for (x in ch) print x, b[x]
	}
	function id_ok(id) { return id >= 2160852992 && id <= 2160852995 }
	'
}

# r18_bootflag_show: print name=value lines (validates the block)
r18_bootflag_show() {
	local mtd tmp
	mtd=$(r18_benv_mtd) || { echo "benv: partition not found" >&2; return 1; }
	tmp=/tmp/benv.show.$$
	dd if=/dev/${mtd}ro of=$tmp bs=$R18_BENV_BS count=1 2>/dev/null
	_r18_benv_awk $tmp show
	local rc=$?
	rm -f $tmp
	return $rc
}

# r18_bootflag_get <name>
r18_bootflag_get() {
	r18_bootflag_show | grep "^$1=" | cut -d= -f2
}

# r18_bootflag_set name=value... : patch, verify, write, read back
r18_bootflag_set() {
	local mtd cur new patch off val sum_new sum_rb
	mtd=$(r18_benv_mtd) || { echo "benv: partition not found" >&2; return 1; }
	cur=/tmp/benv.cur.$$; new=/tmp/benv.new.$$; patch=/tmp/benv.patch.$$
	dd if=/dev/${mtd}ro of=$cur bs=$R18_BENV_BS count=1 2>/dev/null
	_r18_benv_awk $cur patch "$@" > $patch || { rm -f $cur $patch; return 1; }
	cp $cur $new
	while read off val; do
		printf "\\$(printf %o $val)" | dd of=$new bs=1 seek=$off conv=notrunc 2>/dev/null
	done < $patch
	rm -f $patch
	# the new block must parse and carry the requested values
	_r18_benv_awk $new show > /dev/null || { echo "benv: new block invalid, not written" >&2; rm -f $cur $new; return 1; }
	if cmp -s $cur $new 2>/dev/null || [ "$(md5sum < $cur)" = "$(md5sum < $new)" ]; then
		rm -f $cur $new; return 0
	fi
	flash_erase /dev/$mtd 0 1 >/dev/null 2>&1 &&
		nandwrite -p /dev/$mtd $new >/dev/null 2>&1
	sync
	sum_new=$(md5sum < $new)
	sum_rb=$(dd if=/dev/${mtd}ro bs=$R18_BENV_BS count=1 2>/dev/null | md5sum)
	rm -f $cur $new
	[ "$sum_new" = "$sum_rb" ] || { echo "benv: read-back mismatch!" >&2; return 1; }
	return 0
}
