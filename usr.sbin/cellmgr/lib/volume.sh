run_volume_create() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	volume_name=$1
	shift
	volume_mode=
	scope=desired
	while [ $# -gt 0 ]; do
		case "$1" in
		-m|--mode)
			[ $# -ge 2 ] || return 1
			volume_mode=$2
			shift 2
			;;
		--scope)
			[ $# -ge 2 ] || return 1
			scope=$2
			shift 2
			;;
		-*)
			echo "volume create: unknown option $1" >&2
			return 1
			;;
		*)
			echo "volume create: unexpected argument $1" >&2
			return 1
			;;
		esac
	done
	case "${scope}" in
	desired|both)
		;;
	*)
		echo "volume create: invalid scope '${scope}' (expected desired|both)" >&2
		return 1
		;;
	esac
	create_manifest_volume "${volume_name}" "${volume_mode}"
	if [ "${scope}" = "both" ]; then
		ensure_volume_runtime_from_manifest "${volume_name}"
	fi
}

run_volume_set() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	volume_name=$1
	shift
	volume_mode=
	scope=desired
	while [ $# -gt 0 ]; do
		case "$1" in
		-m|--mode)
			[ $# -ge 2 ] || return 1
			volume_mode=$2
			shift 2
			;;
		--scope)
			[ $# -ge 2 ] || return 1
			scope=$2
			shift 2
			;;
		-*)
			echo "volume set: unknown option $1" >&2
			return 1
			;;
		*)
			echo "volume set: unexpected argument $1" >&2
			return 1
			;;
		esac
	done
	case "${scope}" in
	desired|both)
		;;
	*)
		echo "volume set: invalid scope '${scope}' (expected desired|both)" >&2
		return 1
		;;
	esac
	set_manifest_volume "${volume_name}" "${volume_mode}"
	if [ "${scope}" = "both" ]; then
		ensure_volume_runtime_from_manifest "${volume_name}"
	fi
}

run_volume_edit() {
	[ $# -eq 1 ] || {
		echo "volume edit: expected one volume name" >&2
		return 1
	}
	edit_volume_config "$1"
}

run_volume_backup_create() {
	[ $# -eq 1 ] || {
		echo "volume backup create: expected one volume name" >&2
		return 1
	}
	backup_volume "$1"
}

run_volume_backup_list() {
	[ $# -ge 1 ] || {
		echo "volume backup list: expected volume name" >&2
		return 1
	}
	volume_name=$1
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
			echo "volume backup list: unknown option $1" >&2
			return 1
			;;
		*)
			echo "volume backup list: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	if [ "${header}" = "NO" ] && [ "${tsv}" != "YES" ]; then
		echo "volume backup list: -H requires -T" >&2
		return 1
	fi

	list_volume_backups "${volume_name}" "${tsv}" "${header}"
}

run_volume_backup_restore() {
	[ $# -ge 1 ] || {
		echo "volume backup restore: expected volume name" >&2
		return 1
	}
	volume_name=$1
	shift
	archive=
	latest=NO
	restore_manifest=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--from)
			[ $# -ge 2 ] || {
				echo "volume backup restore: --from requires an archive path" >&2
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
			echo "volume backup restore: unknown option $1" >&2
			return 1
			;;
		*)
			if [ -n "${archive}" ]; then
				echo "volume backup restore: unexpected argument $1" >&2
				return 1
			fi
			archive=$1
			shift
			;;
		esac
	done

	restore_volume "${volume_name}" "${archive}" "${latest}" "${restore_manifest}"
}

run_volume_backup_delete() {
	[ $# -ge 1 ] || {
		echo "volume backup delete: expected volume name" >&2
		return 1
	}
	volume_name=$1
	shift
	archive=
	latest=NO

	while [ $# -gt 0 ]; do
		case "$1" in
		--from)
			[ $# -ge 2 ] || {
				echo "volume backup delete: --from requires an archive path" >&2
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
			echo "volume backup delete: unknown option $1" >&2
			return 1
			;;
		*)
			if [ -n "${archive}" ]; then
				echo "volume backup delete: unexpected argument $1" >&2
				return 1
			fi
			archive=$1
			shift
			;;
		esac
	done

	delete_volume_backup "${volume_name}" "${archive}" "${latest}"
}

run_volume_backup_resource_command() {
	[ $# -ge 1 ] || {
		echo "volume backup: expected subcommand create|list|restore|delete" >&2
		return 1
	}
	backup_sub=$1
	shift
	case "${backup_sub}" in
	create)
		run_volume_backup_create "$@"
		;;
	list)
		run_volume_backup_list "$@"
		;;
	restore)
		run_volume_backup_restore "$@"
		;;
	delete)
		run_volume_backup_delete "$@"
		;;
	*)
		echo "unknown volume backup command: ${backup_sub}" >&2
		usage
		return 1
		;;
	esac
}

run_volume_remove() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	volume_target=$1
	shift
	scope=desired
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
		-*)
			echo "volume remove: unknown option $1" >&2
			return 1
			;;
		*)
			echo "volume remove: unexpected argument $1" >&2
			return 1
			;;
		esac
	done
	case "${scope}" in
	desired|runtime|both)
		;;
	*)
		echo "volume remove: invalid scope '${scope}' (expected desired|runtime|both)" >&2
		return 1
		;;
	esac

	case "${volume_target}" in
	--all)
		if [ "${scope}" = "desired" ] || [ "${scope}" = "both" ]; then
			remove_manifest_volumes_all
		fi
		if [ "${scope}" = "runtime" ] || [ "${scope}" = "both" ]; then
			prune_runtime_volumes all
		fi
		return 0
		;;
	--orphans)
		if [ "${scope}" = "desired" ]; then
			echo "volume remove: --orphans requires scope runtime or both" >&2
			return 1
		fi
		prune_runtime_volumes orphans
		return 0
		;;
	esac

	assert_valid_volume_name "${volume_target}"
	volume_manifest_paths "${volume_target}"
	manifest_present=NO
	runtime_present=NO
	if [ -f "${VOLUME_CONF}" ]; then
		manifest_present=YES
	fi
	if [ -d "${VOLUME_PATH}" ]; then
		runtime_present=YES
	fi
	if [ "${manifest_present}" = "NO" ] && [ "${runtime_present}" = "NO" ]; then
		echo "volume remove: not found: ${volume_target}" >&2
		return 1
	fi

	if [ "${scope}" = "runtime" ] || [ "${scope}" = "both" ]; then
		if [ "${runtime_present}" = "YES" ]; then
			prune_runtime_volume "${volume_target}"
		elif [ "${scope}" = "runtime" ]; then
			echo "volume remove: runtime state not found: ${volume_target}" >&2
			return 1
		fi
	fi
	if [ "${scope}" = "desired" ] || [ "${scope}" = "both" ]; then
		if [ "${manifest_present}" = "YES" ]; then
			remove_manifest_volume "${volume_target}"
		elif [ "${scope}" = "desired" ]; then
			echo "volume remove: desired state not found: ${volume_target}" >&2
			return 1
		fi
	fi
}

run_volume_resource_command() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	volume_sub=$1
	shift
	case "${volume_sub}" in
	list)
		volume_list_view "$@"
		;;
	show)
		volume_show_view "$@"
		;;
	fields)
		volume_fields_view "$@"
		;;
	create)
		run_volume_create "$@"
		;;
	set)
		run_volume_set "$@"
		;;
	edit)
		run_volume_edit "$@"
		;;
	backup)
		run_volume_backup_resource_command "$@"
		;;
	remove)
		run_volume_remove "$@"
		;;
	*)
		echo "unknown volume command: ${volume_sub}" >&2
		usage
		return 1
		;;
	esac
}
