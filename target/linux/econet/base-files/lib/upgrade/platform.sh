platform_check_image() {
	local board=$(board_name)

	case "$board" in
	chinamobile,gs3101|\
	dasan,h660gm-a-airtel|\
	dasan,h660gm-a-generic|\
	dlink,r18|\
	jiofiber,jcow407|\
	jiofiber,jcow414)
		return 0
		;;
	esac

	return 1
}

platform_do_upgrade() {
	local board=$(board_name)

	case "$board" in
	chinamobile,gs3101|\
	dasan,h660gm-a-airtel|\
	dasan,h660gm-a-generic|\
	jiofiber,jcow407|\
	jiofiber,jcow414)
		CI_KERNPART="tclinux_kernel"
		nand_do_upgrade "$1"
		;;
	dlink,r18)
		# try the new slot A once; unless /etc/init.d/r18-bootconfirm commits it,
		# the next boot falls back to the recovery image in slot B
		. /lib/upgrade/r18_bootflag.sh
		r18_bootflag_set sw_commit=1 sw_tryactive=1 ||
			echo "r18: WARNING: could not arm boot fallback"
		CI_KERNPART="tclinux_kernel"
		nand_do_upgrade "$1"
		;;
	esac
}
