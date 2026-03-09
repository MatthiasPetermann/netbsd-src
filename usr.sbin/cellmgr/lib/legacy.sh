run_cell_create_command() {
	autostart=NO
	supervise_cmd="/bin/true"
	create_profile=
	create_reserved_ports=
	create_rlimit_nofile=
	create_rlimit_as=
	create_rlimit_core=
	supervise_facility=
	supervise_stdout_level=
	supervise_stderr_level=
	supervise_tag=
	depends_on=
	healthcheck_cmd=
	volume_mounts=

	while [ $# -gt 0 ]; do
		case "$1" in
		-a)
			autostart=YES
			shift
			;;
		-x)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			supervise_cmd=$2
			shift 2
			;;
		-l)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			create_profile=$2
			shift 2
			;;
		-r)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			create_reserved_ports=$2
			shift 2
			;;
		-f)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			supervise_facility=$2
			shift 2
			;;
		-o)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			supervise_stdout_level=$2
			shift 2
			;;
		-e)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			supervise_stderr_level=$2
			shift 2
			;;
		-t)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			supervise_tag=$2
			shift 2
			;;
		-d)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			depends_on=$2
			shift 2
			;;
		-H)
			[ $# -ge 2 ] || {
				usage
				exit 1
			}
			healthcheck_cmd=$2
			shift 2
			;;
		-*)
			usage
			exit 1
			;;
		*)
			break
			;;
		esac
	done

	if [ $# -ne 1 ]; then
		usage
		exit 1
	fi

	name=$1
	create_manifest_cell "${name}" "${autostart}" "${supervise_cmd}" \
	    "${create_profile}" "${create_reserved_ports}" \
	    "${create_rlimit_nofile}" "${create_rlimit_as}" "${create_rlimit_core}" \
	    "${supervise_facility}" "${supervise_stdout_level}" \
	    "${supervise_stderr_level}" "${supervise_tag}" \
	    "${depends_on}" "${healthcheck_cmd}" "${volume_mounts}"
}

run_cell_remove_command() {
	all=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--all)
			all=YES
			shift
			;;
		-*)
			usage
			exit 1
			;;
		*)
			break
			;;
		esac
	done

	if [ "${all}" = "YES" ]; then
		if [ $# -ne 0 ]; then
			usage
			exit 1
		fi
		remove_manifest_all
		return
	fi
	if [ $# -ne 1 ]; then
		usage
		exit 1
	fi
	remove_manifest_cell "$1"
}

run_cell_command() {
	[ $# -ge 1 ] || {
		usage
		exit 1
	}
	sub=$1
	shift

	case "${sub}" in
	create)
		run_cell_create_command "$@"
		;;
	list)
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		list_manifest_cells
		;;
	show)
		[ $# -eq 1 ] || {
			usage
			exit 1
		}
		show_manifest_cell "$1"
		;;
	edit)
		[ $# -eq 1 ] || {
			usage
			exit 1
		}
		edit_cell_config "$1"
		;;
	remove)
		run_cell_remove_command "$@"
		;;
	*)
		usage
		exit 1
		;;
	esac
}

run_volume_command() {
	[ $# -ge 1 ] || {
		usage
		exit 1
	}
	sub=$1
	shift

	case "${sub}" in
	create)
		volume_mode=
		while [ $# -gt 0 ]; do
			case "$1" in
			-m)
				[ $# -ge 2 ] || {
					usage
					exit 1
				}
				volume_mode=$2
				shift 2
				;;
			-*)
				usage
				exit 1
				;;
			*)
				break
				;;
			esac
		done
		[ $# -eq 1 ] || {
			usage
			exit 1
		}
		create_manifest_volume "$1" "${volume_mode}"
		;;
	remove)
		[ $# -eq 1 ] || {
			usage
			exit 1
		}
		remove_manifest_volume "$1"
		;;
	list)
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		list_volumes
		;;
	show)
		[ $# -eq 1 ] || {
			usage
			exit 1
		}
		show_volume "$1"
		;;
	*)
		usage
		exit 1
		;;
	esac
}

run_runtime_lifecycle_command() {
	action=$1
	shift

	if [ $# -ne 1 ]; then
		usage
		exit 1
	fi

	target=$1
	if [ "${target}" = "--all" ]; then
		case "${action}" in
		start)
			start_all
			;;
		stop)
			stop_all
			;;
		restart)
			restart_all
			;;
		esac
		return
	fi

	assert_valid_cell_name "${target}"
	case "${action}" in
	start)
		start_cell "${target}"
		;;
	stop)
		stop_cell "${target}"
		;;
	restart)
		restart_cell "${target}"
		;;
	esac
}

run_runtime_remove_command() {
	all=NO
	orphans=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--all)
			all=YES
			shift
			;;
		--orphans)
			orphans=YES
			shift
			;;
		-*)
			usage
			exit 1
			;;
		*)
			break
			;;
		esac
	done

	if [ "${all}" = "YES" ] && [ "${orphans}" = "YES" ]; then
		echo "cell remove: --all and --orphans are mutually exclusive" >&2
		exit 1
	fi

	if [ "${all}" = "YES" ]; then
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		prune_runtime_all all
		return
	fi

	if [ "${orphans}" = "YES" ]; then
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		prune_runtime_all orphans
		return
	fi
	[ $# -eq 1 ] || {
		usage
		exit 1
	}
	prune_runtime_cell "$1"
}

run_runtime_volume_remove_command() {
	all=NO
	orphans=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--all)
			all=YES
			shift
			;;
		--orphans)
			orphans=YES
			shift
			;;
		-*)
			usage
			exit 1
			;;
		*)
			break
			;;
		esac
	done

	if [ "${all}" = "YES" ] && [ "${orphans}" = "YES" ]; then
		echo "volume remove: --all and --orphans are mutually exclusive" >&2
		exit 1
	fi

	if [ "${all}" = "YES" ]; then
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		prune_runtime_volumes all
		return
	fi

	if [ "${orphans}" = "YES" ]; then
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		prune_runtime_volumes orphans
		return
	fi

	[ $# -eq 1 ] || {
		usage
		exit 1
	}
	prune_runtime_volume "$1"
}

run_runtime_cell_command() {
	[ $# -ge 1 ] || {
		usage
		exit 1
	}
	sub=$1
	shift

	case "${sub}" in
	list)
		runtime_list "$@"
		;;
	show)
		[ $# -ge 1 ] || {
			usage
			exit 1
		}
		name=$1
		shift
		runtime_show "${name}" "$@"
		;;
	fields)
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		runtime_fields
		;;
	start)
		run_runtime_lifecycle_command start "$@"
		;;
	stop)
		run_runtime_lifecycle_command stop "$@"
		;;
	restart)
		run_runtime_lifecycle_command restart "$@"
		;;
	apply)
		apply_cell_script "$@"
		;;
	shell)
		[ $# -eq 1 ] || {
			usage
			exit 1
		}
		runtime_shell "$1"
		;;
	remove)
		run_runtime_remove_command "$@"
		;;
	*)
		usage
		exit 1
		;;
	esac
}

run_runtime_volume_command() {
	[ $# -ge 1 ] || {
		usage
		exit 1
	}
	sub=$1
	shift

	case "${sub}" in
	list)
		[ $# -eq 0 ] || {
			usage
			exit 1
		}
		list_volumes
		;;
	show)
		[ $# -eq 1 ] || {
			usage
			exit 1
		}
		show_volume "$1"
		;;
	remove)
		run_runtime_volume_remove_command "$@"
		;;
	*)
		usage
		exit 1
		;;
	esac
}

run_runtime_command() {
	[ $# -ge 1 ] || {
		usage
		exit 1
	}

	noun=$1
	shift

	case "${noun}" in
	cell)
		run_runtime_cell_command "$@"
		;;
	volume)
		run_runtime_volume_command "$@"
		;;
	*)
		usage
		exit 1
		;;
	esac
}

list_pretty_cells() {
	snapshot_tmp=$(mktemp /tmp/cellmgr-runtime-snapshot.XXXXXX)
	if ! runtime_collect_snapshot "${snapshot_tmp}"; then
		rm -f "${snapshot_tmp}"
		exit 1
	fi

	awk -F '\t' '
		function truncw(s, w) {
			if (length(s) <= w)
				return s
			if (w <= 1)
				return substr(s, 1, w)
			return substr(s, 1, w - 1) "~"
		}
		BEGIN {
			printf "%-26s %-7s %-8s %-8s %-5s %-5s %-5s %-4s\n", \
			    "NAME", "STATE", "MANIFEST", "RENDERED", \
			    "CID", "PROCS", "REFS", "AUTO"
		}
		{
			name = $1
			if ($3 != "1")
				name = "!" name
			state = ($2 == "1") ? "RUN" : "STOP"
			manifest = ($3 == "1") ? "YES" : "NO"
			rendered = ($15 == "1") ? "YES" : "NO"
			cid = ($4 == "") ? "-" : $4
			procs = ($6 == "") ? "0" : $6
			refs = ($5 == "") ? "-" : $5
			auto = ($8 == "") ? "NO" : $8

			printf "%-26s %-7s %-8s %-8s %-5s %-5s %-5s %-4s\n", \
			    truncw(name, 26), truncw(state, 7), truncw(manifest, 8), \
			    truncw(rendered, 8), truncw(cid, 5), truncw(procs, 5), \
			    truncw(refs, 5), truncw(auto, 4)
		}
	' "${snapshot_tmp}"

	rm -f "${snapshot_tmp}"
}

run_list_command() {
	if [ $# -eq 0 ]; then
		list_pretty_cells
		return
	fi

	run_runtime_command cell list "$@"
}

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

run_manifest_command() {
	[ $# -ge 1 ] || {
		usage
		exit 1
	}
	noun=$1
	shift

	case "${noun}" in
	cell)
		run_cell_command "$@"
		;;
	volume)
		run_volume_command "$@"
		;;
	*)
		usage
		exit 1
		;;
	esac
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
	name=$1
	value=${2:-}
	case "${value}" in
	""|unlimited)
		return 0
		;;
	*[!0-9]*)
		echo "invalid rlimit ${name} '${value}' (expected integer or unlimited)" >&2
		return 1
		;;
	esac
	return 0
}

set_cell_autostart_if_manifest() {
	name=$1
	autostart=$2
	if ! manifest_cell_exists "${name}"; then
		return 0
	fi
	load_manifest_cell_conf "${name}"
	set_manifest_cell "${name}" "${autostart}" "${CELL_SUPERVISE_CMD:-}" \
	    "${CELL_CREATE_PROFILE:-}" "${CELL_CREATE_RESERVED_PORTS:-}" \
	    "${CELL_CREATE_RLIMIT_NOFILE:-}" "${CELL_CREATE_RLIMIT_AS:-}" \
	    "${CELL_CREATE_RLIMIT_CORE:-}" \
	    "${CELL_SUPERVISE_FACILITY:-}" "${CELL_SUPERVISE_STDOUT_LEVEL:-}" \
	    "${CELL_SUPERVISE_STDERR_LEVEL:-}" "${CELL_SUPERVISE_TAG:-}" \
	    "${CELL_DEPENDS_ON:-}" "${CELL_HEALTHCHECK_CMD:-}" "${CELL_VOLUME_MOUNTS:-}"
}

