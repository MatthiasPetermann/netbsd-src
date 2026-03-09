run_system_reset() {
	scope=both
	include_cells=NO
	include_volumes=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--scope)
			[ $# -ge 2 ] || {
				echo "system reset: --scope requires desired|runtime|both" >&2
				return 1
			}
			scope=$2
			shift 2
			;;
		--cells)
			include_cells=YES
			shift
			;;
		--volumes)
			include_volumes=YES
			shift
			;;
		--yes)
			CELLMGR_ASSUME_YES=YES
			shift
			;;
		-*)
			echo "system reset: unknown option $1" >&2
			return 1
			;;
		*)
			echo "system reset: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	case "${scope}" in
	desired|runtime|both)
		;;
	*)
		echo "system reset: invalid scope '${scope}' (expected desired|runtime|both)" >&2
		return 1
		;;
	esac

	if [ "${include_cells}" = "NO" ] && [ "${include_volumes}" = "NO" ]; then
		include_cells=YES
		include_volumes=YES
	fi

	if [ "${include_cells}" = "YES" ]; then
		if [ "${CELLMGR_ASSUME_YES}" = "YES" ]; then
			run_cell_resource_command remove --all --scope "${scope}" --yes || return $?
		else
			run_cell_resource_command remove --all --scope "${scope}" || return $?
		fi
	fi

	if [ "${include_volumes}" = "YES" ]; then
		if [ "${CELLMGR_ASSUME_YES}" = "YES" ]; then
			run_volume_resource_command remove --all --scope "${scope}" --yes || return $?
		else
			run_volume_resource_command remove --all --scope "${scope}" || return $?
		fi
	fi

	return 0
}

run_system_resource_command() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	sub=$1
	shift
	case "${sub}" in
	bootstrap)
		run_bootstrap_command "$@"
		;;
	reset)
		run_system_reset "$@"
		;;
	*)
		echo "unknown system command: ${sub}" >&2
		usage
		return 1
		;;
	esac
}
