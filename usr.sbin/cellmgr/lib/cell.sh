run_cell_create() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	cell_name=$1
	shift
	assert_valid_cell_name "${cell_name}"

	autostart=NO
	supervise_cmd=
	create_profile=high
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
	scope=desired

	while [ $# -gt 0 ]; do
		case "$1" in
		--autostart)
			[ $# -ge 2 ] || {
				echo "cell create: --autostart requires YES or NO" >&2
				return 1
			}
			autostart=$(normalize_yesno "$2")
			shift 2
			;;
		--cmd)
			[ $# -ge 2 ] || {
				echo "cell create: --cmd requires a command" >&2
				return 1
			}
			supervise_cmd=$2
			shift 2
			;;
		--profile)
			[ $# -ge 2 ] || {
				echo "cell create: --profile requires a value" >&2
				return 1
			}
			create_profile=$2
			shift 2
			;;
		--reserved-ports)
			[ $# -ge 2 ] || {
				echo "cell create: --reserved-ports requires a value" >&2
				return 1
			}
			create_reserved_ports=$2
			shift 2
			;;
		--rlimit-nofile)
			[ $# -ge 2 ] || {
				echo "cell create: --rlimit-nofile requires a value" >&2
				return 1
			}
			create_rlimit_nofile=$2
			shift 2
			;;
		--rlimit-as)
			[ $# -ge 2 ] || {
				echo "cell create: --rlimit-as requires a value" >&2
				return 1
			}
			create_rlimit_as=$2
			shift 2
			;;
		--rlimit-core)
			[ $# -ge 2 ] || {
				echo "cell create: --rlimit-core requires a value" >&2
				return 1
			}
			create_rlimit_core=$2
			shift 2
			;;
		--depends-on)
			[ $# -ge 2 ] || {
				echo "cell create: --depends-on requires a value" >&2
				return 1
			}
			depends_on=$2
			shift 2
			;;
		--healthcheck)
			[ $# -ge 2 ] || {
				echo "cell create: --healthcheck requires a command" >&2
				return 1
			}
			healthcheck_cmd=$2
			shift 2
			;;
		--mount)
			[ $# -ge 2 ] || {
				echo "cell create: --mount requires a spec" >&2
				return 1
			}
			if [ -n "${volume_mounts}" ]; then
				volume_mounts="${volume_mounts},"
			fi
			volume_mounts="${volume_mounts}$2"
			shift 2
			;;
		--log-facility)
			[ $# -ge 2 ] || return 1
			supervise_facility=$2
			shift 2
			;;
		--stdout-level)
			[ $# -ge 2 ] || return 1
			supervise_stdout_level=$2
			shift 2
			;;
		--stderr-level)
			[ $# -ge 2 ] || return 1
			supervise_stderr_level=$2
			shift 2
			;;
		--log-tag)
			[ $# -ge 2 ] || return 1
			supervise_tag=$2
			shift 2
			;;
		--scope)
			[ $# -ge 2 ] || {
				echo "cell create: --scope requires desired or both" >&2
				return 1
			}
			scope=$2
			shift 2
			;;
		-*)
			echo "cell create: unknown option $1" >&2
			return 1
			;;
		*)
			echo "cell create: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	case "${scope}" in
	desired|both)
		;;
	*)
		echo "cell create: invalid scope '${scope}' (expected desired|both)" >&2
		return 1
		;;
	esac
	if [ -z "${supervise_cmd}" ]; then
		echo "cell create: --cmd is required" >&2
		return 1
	fi
	validate_cell_profile "${create_profile}" || return 1
	validate_cell_rlimit "nofile" "${create_rlimit_nofile}" || return 1
	validate_cell_rlimit "as" "${create_rlimit_as}" || return 1
	validate_cell_rlimit "core" "${create_rlimit_core}" || return 1

	create_manifest_cell "${cell_name}" "${autostart}" "${supervise_cmd}" \
	    "${create_profile}" "${create_reserved_ports}" \
	    "${create_rlimit_nofile}" "${create_rlimit_as}" "${create_rlimit_core}" \
	    "${supervise_facility}" "${supervise_stdout_level}" \
	    "${supervise_stderr_level}" "${supervise_tag}" \
	    "${depends_on}" "${healthcheck_cmd}" "${volume_mounts}"

	if [ "${scope}" = "both" ]; then
		run_reconcile_command "${cell_name}"
	fi
}

run_cell_set() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	cell_name=$1
	shift
	assert_valid_cell_name "${cell_name}"
	load_manifest_cell_conf "${cell_name}"

	autostart=${CELL_AUTOSTART:-NO}
	supervise_cmd=${CELL_SUPERVISE_CMD:-}
	create_profile=${CELL_CREATE_PROFILE:-}
	create_reserved_ports=${CELL_CREATE_RESERVED_PORTS:-}
	create_rlimit_nofile=${CELL_CREATE_RLIMIT_NOFILE:-}
	create_rlimit_as=${CELL_CREATE_RLIMIT_AS:-}
	create_rlimit_core=${CELL_CREATE_RLIMIT_CORE:-}
	supervise_facility=${CELL_SUPERVISE_FACILITY:-}
	supervise_stdout_level=${CELL_SUPERVISE_STDOUT_LEVEL:-}
	supervise_stderr_level=${CELL_SUPERVISE_STDERR_LEVEL:-}
	supervise_tag=${CELL_SUPERVISE_TAG:-}
	depends_on=${CELL_DEPENDS_ON:-}
	healthcheck_cmd=${CELL_HEALTHCHECK_CMD:-}
	volume_mounts=${CELL_VOLUME_MOUNTS:-}
	mounts_replaced=NO
	scope=desired

	while [ $# -gt 0 ]; do
		case "$1" in
		--autostart)
			[ $# -ge 2 ] || return 1
			autostart=$(normalize_yesno "$2")
			shift 2
			;;
		--cmd)
			[ $# -ge 2 ] || return 1
			supervise_cmd=$2
			shift 2
			;;
		--profile)
			[ $# -ge 2 ] || return 1
			create_profile=$2
			shift 2
			;;
		--reserved-ports)
			[ $# -ge 2 ] || return 1
			create_reserved_ports=$2
			shift 2
			;;
		--rlimit-nofile)
			[ $# -ge 2 ] || return 1
			create_rlimit_nofile=$2
			shift 2
			;;
		--rlimit-as)
			[ $# -ge 2 ] || return 1
			create_rlimit_as=$2
			shift 2
			;;
		--rlimit-core)
			[ $# -ge 2 ] || return 1
			create_rlimit_core=$2
			shift 2
			;;
		--depends-on)
			[ $# -ge 2 ] || return 1
			depends_on=$2
			shift 2
			;;
		--healthcheck)
			[ $# -ge 2 ] || return 1
			healthcheck_cmd=$2
			shift 2
			;;
		--mount)
			[ $# -ge 2 ] || return 1
			if [ "${mounts_replaced}" = "NO" ]; then
				volume_mounts=
				mounts_replaced=YES
			fi
			if [ -n "${volume_mounts}" ]; then
				volume_mounts="${volume_mounts},"
			fi
			volume_mounts="${volume_mounts}$2"
			shift 2
			;;
		--log-facility)
			[ $# -ge 2 ] || return 1
			supervise_facility=$2
			shift 2
			;;
		--stdout-level)
			[ $# -ge 2 ] || return 1
			supervise_stdout_level=$2
			shift 2
			;;
		--stderr-level)
			[ $# -ge 2 ] || return 1
			supervise_stderr_level=$2
			shift 2
			;;
		--log-tag)
			[ $# -ge 2 ] || return 1
			supervise_tag=$2
			shift 2
			;;
		--clear-reserved-ports)
			create_reserved_ports=
			shift
			;;
		--clear-rlimit-nofile)
			create_rlimit_nofile=
			shift
			;;
		--clear-rlimit-as)
			create_rlimit_as=
			shift
			;;
		--clear-rlimit-core)
			create_rlimit_core=
			shift
			;;
		--clear-depends-on)
			depends_on=
			shift
			;;
		--clear-healthcheck)
			healthcheck_cmd=
			shift
			;;
		--clear-mounts)
			volume_mounts=
			mounts_replaced=YES
			shift
			;;
		--clear-log)
			supervise_facility=
			supervise_stdout_level=
			supervise_stderr_level=
			supervise_tag=
			shift
			;;
		--scope)
			[ $# -ge 2 ] || return 1
			scope=$2
			shift 2
			;;
		-*)
			echo "cell set: unknown option $1" >&2
			return 1
			;;
		*)
			echo "cell set: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	case "${scope}" in
	desired|both)
		;;
	*)
		echo "cell set: invalid scope '${scope}' (expected desired|both)" >&2
		return 1
		;;
	esac
	validate_cell_profile "${create_profile}" || return 1
	validate_cell_rlimit "nofile" "${create_rlimit_nofile}" || return 1
	validate_cell_rlimit "as" "${create_rlimit_as}" || return 1
	validate_cell_rlimit "core" "${create_rlimit_core}" || return 1

	set_manifest_cell "${cell_name}" "${autostart}" "${supervise_cmd}" \
	    "${create_profile}" "${create_reserved_ports}" \
	    "${create_rlimit_nofile}" "${create_rlimit_as}" "${create_rlimit_core}" \
	    "${supervise_facility}" "${supervise_stdout_level}" \
	    "${supervise_stderr_level}" "${supervise_tag}" \
	    "${depends_on}" "${healthcheck_cmd}" "${volume_mounts}"

	if [ "${scope}" = "both" ]; then
		run_reconcile_command "${cell_name}"
	fi
}

run_cell_remove() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	target=$1
	shift
	scope=desired
	force=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--scope)
			[ $# -ge 2 ] || return 1
			scope=$2
			shift 2
			;;
		--yes)
			CELLMGR_ASSUME_YES=YES
			shift
			;;
		--force)
			force=YES
			shift
			;;
		-*)
			echo "cell remove: unknown option $1" >&2
			return 1
			;;
		*)
			echo "cell remove: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	case "${scope}" in
	desired|runtime|both)
		;;
	*)
		echo "cell remove: invalid scope '${scope}' (expected desired|runtime|both)" >&2
		return 1
		;;
	esac

	case "${target}" in
	--all)
		if [ "${scope}" = "desired" ] || [ "${scope}" = "both" ]; then
			remove_manifest_all
		fi
		if [ "${scope}" = "runtime" ] || [ "${scope}" = "both" ]; then
			prune_runtime_all all
		fi
		return 0
		;;
	--orphans)
		if [ "${scope}" = "desired" ]; then
			echo "cell remove: --orphans requires scope runtime or both" >&2
			return 1
		fi
		prune_runtime_all orphans
		return 0
		;;
	esac

	assert_valid_cell_name "${target}"
	manifest_present=NO
	runtime_present=NO
	if manifest_cell_exists "${target}"; then
		manifest_present=YES
	fi
	cell_paths "${target}"
	if [ -d "${CELL_DIR}" ]; then
		runtime_present=YES
	fi

	if [ "${manifest_present}" = "NO" ] && [ "${runtime_present}" = "NO" ] && [ "${force}" != "YES" ]; then
		echo "cell remove: not found: ${target}" >&2
		return 1
	fi

	if [ "${scope}" = "runtime" ] || [ "${scope}" = "both" ]; then
		if [ "${runtime_present}" = "YES" ]; then
			prune_runtime_cell "${target}"
		elif [ "${scope}" = "runtime" ] && [ "${force}" != "YES" ]; then
			echo "cell remove: runtime state not found: ${target}" >&2
			return 1
		fi
	fi
	if [ "${scope}" = "desired" ] || [ "${scope}" = "both" ]; then
		if [ "${manifest_present}" = "YES" ]; then
			remove_manifest_cell "${target}"
		elif [ "${scope}" = "desired" ] && [ "${force}" != "YES" ]; then
			echo "cell remove: desired state not found: ${target}" >&2
			return 1
		fi
	fi
}

run_cell_lifecycle() {
	action=$1
	shift
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	target=$1
	shift
	scope=runtime

	while [ $# -gt 0 ]; do
		case "$1" in
		--scope)
			[ $# -ge 2 ] || return 1
			scope=$2
			shift 2
			;;
		-*)
			echo "cell ${action}: unknown option $1" >&2
			return 1
			;;
		*)
			echo "cell ${action}: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	case "${scope}" in
	runtime|both)
		;;
	*)
		echo "cell ${action}: invalid scope '${scope}' (expected runtime|both)" >&2
		return 1
		;;
	esac

	if [ "${target}" = "--all" ]; then
		case "${action}" in
		start)
			start_all
			if [ "${scope}" = "both" ]; then
				for cell_conf in "${MANIFEST_DIR}"/*.cell; do
					[ -f "${cell_conf}" ] || continue
					manifest_cell_name=${cell_conf##*/}
					manifest_cell_name=${manifest_cell_name%.cell}
					set_cell_autostart_if_manifest "${manifest_cell_name}" "YES"
				done
			fi
			;;
		stop)
			stop_all
			if [ "${scope}" = "both" ]; then
				for cell_conf in "${MANIFEST_DIR}"/*.cell; do
					[ -f "${cell_conf}" ] || continue
					manifest_cell_name=${cell_conf##*/}
					manifest_cell_name=${manifest_cell_name%.cell}
					set_cell_autostart_if_manifest "${manifest_cell_name}" "NO"
				done
			fi
			;;
		restart)
			restart_all
			;;
		esac
		return 0
	fi

	assert_valid_cell_name "${target}"
	case "${action}" in
	start)
		start_cell "${target}"
		if [ "${scope}" = "both" ]; then
			set_cell_autostart_if_manifest "${target}" "YES"
		fi
		;;
	stop)
		stop_cell "${target}"
		if [ "${scope}" = "both" ]; then
			set_cell_autostart_if_manifest "${target}" "NO"
		fi
		;;
	restart)
		restart_cell "${target}"
		;;
	esac
}

run_cell_plan_command() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	plan_sub=$1
	shift
	case "${plan_sub}" in
	run)
		;;
	*)
		echo "cell plan: expected subcommand 'run'" >&2
		return 1
		;;
	esac

	ephemeral=NO
	plan_file=
	while [ $# -gt 0 ]; do
		case "$1" in
		--ephemeral)
			ephemeral=YES
			shift
			;;
		--file)
			[ $# -ge 2 ] || return 1
			plan_file=$2
			shift 2
			;;
		-*)
			echo "cell plan run: unknown option $1" >&2
			return 1
			;;
		*)
			break
			;;
		esac
	done

	[ $# -eq 1 ] || {
		echo "cell plan run: expected exactly one cell name" >&2
		return 1
	}
	cell_name=$1
	assert_valid_cell_name "${cell_name}"

	set --
	if [ "${ephemeral}" = "YES" ]; then
		set -- "$@" --ephemeral
	fi
	set -- "$@" "${cell_name}"
	if [ -n "${plan_file}" ]; then
		set -- "$@" "${plan_file}"
	fi
	apply_cell_script "$@"
}

run_cell_edit() {
	[ $# -ge 1 ] || {
		echo "cell edit: expected one cell name" >&2
		return 1
	}
	cell_name=$1
	shift
	target=cell

	while [ $# -gt 0 ]; do
		case "$1" in
		--target)
			[ $# -ge 2 ] || {
				echo "cell edit: --target requires cell|apply" >&2
				return 1
			}
			target=$2
			shift 2
			;;
		--cell)
			target=cell
			shift
			;;
		--apply)
			target=apply
			shift
			;;
		-*)
			echo "cell edit: unknown option $1" >&2
			return 1
			;;
		*)
			echo "cell edit: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	case "${target}" in
	cell|apply)
		;;
	*)
		echo "cell edit: invalid target '${target}' (expected cell|apply)" >&2
		return 1
		;;
	esac

	edit_cell_config "${cell_name}" "${target}"
}

run_cell_backup_create() {
	[ $# -eq 1 ] || {
		echo "cell backup create: expected one cell name" >&2
		return 1
	}
	backup_overlay "$1"
}

run_cell_backup_list() {
	[ $# -ge 1 ] || {
		echo "cell backup list: expected cell name" >&2
		return 1
	}
	cell_name=$1
	shift
	tsv=NO
	header=YES

	while [ $# -gt 0 ]; do
		case "$1" in
		-T)
			tsv=YES
			shift
			;;
		-H)
			header=NO
			shift
			;;
		-*)
			echo "cell backup list: unknown option $1" >&2
			return 1
			;;
		*)
			echo "cell backup list: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	if [ "${header}" = "NO" ] && [ "${tsv}" != "YES" ]; then
		echo "cell backup list: -H requires -T" >&2
		return 1
	fi

	list_overlay_backups "${cell_name}" "${tsv}" "${header}"
}

run_cell_backup_restore() {
	[ $# -ge 1 ] || {
		echo "cell backup restore: expected cell name" >&2
		return 1
	}
	cell_name=$1
	shift
	archive=
	latest=NO
	restore_manifest=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--from)
			[ $# -ge 2 ] || {
				echo "cell backup restore: --from requires an archive path" >&2
				return 1
			}
			archive=$2
			shift 2
			;;
		--latest)
			latest=YES
			shift
			;;
		--manifest)
			restore_manifest=YES
			shift
			;;
		--yes)
			CELLMGR_ASSUME_YES=YES
			shift
			;;
		-*)
			echo "cell backup restore: unknown option $1" >&2
			return 1
			;;
		*)
			if [ -n "${archive}" ]; then
				echo "cell backup restore: unexpected argument $1" >&2
				return 1
			fi
			archive=$1
			shift
			;;
		esac
	done

	restore_overlay "${cell_name}" "${archive}" "${latest}" "${restore_manifest}"
}

run_cell_backup_delete() {
	[ $# -ge 1 ] || {
		echo "cell backup delete: expected cell name" >&2
		return 1
	}
	cell_name=$1
	shift
	archive=
	latest=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--from)
			[ $# -ge 2 ] || {
				echo "cell backup delete: --from requires an archive path" >&2
				return 1
			}
			archive=$2
			shift 2
			;;
		--latest)
			latest=YES
			shift
			;;
		--yes)
			CELLMGR_ASSUME_YES=YES
			shift
			;;
		-*)
			echo "cell backup delete: unknown option $1" >&2
			return 1
			;;
		*)
			if [ -n "${archive}" ]; then
				echo "cell backup delete: unexpected argument $1" >&2
				return 1
			fi
			archive=$1
			shift
			;;
		esac
	done

	delete_overlay_backup "${cell_name}" "${archive}" "${latest}"
}

run_cell_backup_resource_command() {
	[ $# -ge 1 ] || {
		echo "cell backup: expected subcommand create|list|restore|delete" >&2
		return 1
	}
	backup_sub=$1
	shift
	case "${backup_sub}" in
	create)
		run_cell_backup_create "$@"
		;;
	list)
		run_cell_backup_list "$@"
		;;
	restore)
		run_cell_backup_restore "$@"
		;;
	delete)
		run_cell_backup_delete "$@"
		;;
	*)
		echo "unknown cell backup command: ${backup_sub}" >&2
		usage
		return 1
		;;
	esac
}

run_cell_resource_command() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	cell_sub=$1
	shift
	case "${cell_sub}" in
	list)
		runtime_list "$@"
		;;
	show)
		runtime_show "$@"
		;;
	fields)
		runtime_fields "$@"
		;;
	create)
		run_cell_create "$@"
		;;
	set)
		run_cell_set "$@"
		;;
	remove)
		run_cell_remove "$@"
		;;
	start)
		run_cell_lifecycle start "$@"
		;;
	stop)
		run_cell_lifecycle stop "$@"
		;;
	restart)
		run_cell_lifecycle restart "$@"
		;;
	shell)
		[ $# -eq 1 ] || {
			echo "cell shell: expected one cell name" >&2
			return 1
		}
		runtime_shell "$1"
		;;
	plan)
		run_cell_plan_command "$@"
		;;
	backup)
		run_cell_backup_resource_command "$@"
		;;
	edit)
		run_cell_edit "$@"
		;;
	*)
		echo "unknown cell command: ${cell_sub}" >&2
		usage
		return 1
		;;
	esac
}
