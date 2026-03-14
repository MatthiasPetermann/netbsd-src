run_bootstrap_command() {
	include_xbase=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		-x|--xbase)
			include_xbase=YES
			shift
			;;
		--)
			shift
			break
			;;
		-*)
			usage
			exit 1
			;;
		*)
			usage
			exit 1
			;;
		esac
	done

	if [ $# -ne 0 ]; then
		usage
		exit 1
	fi

	ensure_rc_conf_entry
	ensure_secmodel_cell
	write_default_conf
	fetch_sets "${include_xbase}"
	build_base "${include_xbase}"
}

validate_cell_profile() {
	case "${1:-}" in
	""|low|medium|high)
		return 0
		;;
	*)
		echo "invalid profile '${1}' (expected low|medium|high)" >&2
		return 1
		;;
	esac
}

validate_cell_rlimit() {
	rlimit_field=$1
	rlimit_value=${2:-}
	case "${rlimit_value}" in
	""|unlimited)
		return 0
		;;
	*[!0-9]*)
		echo "invalid rlimit ${rlimit_field} '${rlimit_value}' (expected integer or unlimited)" >&2
		return 1
		;;
	esac
	return 0
}

set_cell_autostart_if_manifest() {
	autostart_cell_name=$1
	autostart_value=$2
	if ! manifest_cell_exists "${autostart_cell_name}"; then
		return 0
	fi
	load_manifest_cell_conf "${autostart_cell_name}"
	set_manifest_cell "${autostart_cell_name}" "${autostart_value}" "${CELL_SUPERVISE_CMD:-}" \
	    "${CELL_CREATE_PROFILE:-}" "${CELL_CREATE_RESERVED_PORTS:-}" \
	    "${CELL_CREATE_RLIMIT_NOFILE:-}" "${CELL_CREATE_RLIMIT_AS:-}" \
	    "${CELL_CREATE_RLIMIT_CORE:-}" \
	    "${CELL_SUPERVISE_FACILITY:-}" "${CELL_SUPERVISE_STDOUT_LEVEL:-}" \
	    "${CELL_SUPERVISE_STDERR_LEVEL:-}" "${CELL_SUPERVISE_TAG:-}" \
	    "${CELL_DEPENDS_ON:-}" "${CELL_HEALTHCHECK_CMD:-}" "${CELL_VOLUME_MOUNTS:-}"
}
