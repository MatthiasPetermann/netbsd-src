run_apply_command() {
	run_reconcile_command "$@"
}

dispatch_command() {
	cmd=${1:-}
	rc=0
	case "${cmd}" in
	help|-h|--help)
		usage
		rc=0
		;;
	ipc)
		shift
		run_ipc_resource_command "$@" || rc=$?
		;;
	cell)
		shift
		run_cell_resource_command "$@" || rc=$?
		;;
	volume)
		shift
		run_volume_resource_command "$@" || rc=$?
		;;
	system)
		shift
		run_system_resource_command "$@" || rc=$?
		;;
	apply)
		shift
		run_apply_command "$@" || rc=$?
		;;
	*)
		usage
		rc=1
		;;
	esac
	return "${rc}"
}
