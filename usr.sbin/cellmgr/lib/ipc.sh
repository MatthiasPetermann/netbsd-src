is_uint() {
	case "${1:-}" in
	''|*[!0-9]*)
		return 1
		;;
	*)
		return 0
		;;
	esac
}

ipc_send_frame_file() {
	ipc_frame_type=$1
	ipc_frame_id=$2
	ipc_frame_p1=$3
	ipc_frame_p2=$4
	ipc_frame_p3=$5
	ipc_frame_payload_file=$6
	ipc_frame_payload_len=$7

	printf 'M 1 %s %s %s %s %s %s\n' \
	    "${ipc_frame_type}" "${ipc_frame_id}" "${ipc_frame_p1}" \
	    "${ipc_frame_p2}" "${ipc_frame_p3}" "${ipc_frame_payload_len}"
	if [ "${ipc_frame_payload_len}" -gt 0 ]; then
		cat "${ipc_frame_payload_file}"
	fi
}

ipc_send_error() {
	ipc_id=$1
	ipc_code=$2
	shift 2
	ipc_msg=$*
	ipc_tmp=$(mktemp /tmp/cellmgr-ipc-err.XXXXXX)
	printf '%s' "${ipc_msg}" > "${ipc_tmp}"
	ipc_len=$(wc -c < "${ipc_tmp}" | tr -d '[:space:]')
	ipc_send_frame_file ERR "${ipc_id}" "${ipc_code}" 0 0 "${ipc_tmp}" "${ipc_len}"
	rm -f "${ipc_tmp}"
}

ipc_read_payload() {
	ipc_len=$1
	ipc_payload_file=$2

	: > "${ipc_payload_file}"
	if [ "${ipc_len}" -eq 0 ]; then
		return 0
	fi
	if ! dd bs=1 count="${ipc_len}" of="${ipc_payload_file}" 2>/dev/null; then
		return 1
	fi
	ipc_got=$(wc -c < "${ipc_payload_file}" | tr -d '[:space:]')
	if [ "${ipc_got}" != "${ipc_len}" ]; then
		return 1
	fi
	return 0
}

ipc_execute_call() {
	ipc_id=$1
	ipc_mode=$2
	ipc_argc=$3
	ipc_env_enabled=$4
	ipc_payload_file=$5

	set --
	ipc_seen=0
	ipc_env_key=
	ipc_env_val=
	ipc_env_lines_needed=0

	case "${ipc_env_enabled}" in
	0)
		;;
	1)
		ipc_env_lines_needed=2
		;;
	*)
		ipc_send_error "${ipc_id}" 64 "invalid CALL flags: ${ipc_env_enabled}"
		return 0
		;;
	esac

	while IFS= read -r ipc_arg || [ -n "${ipc_arg}" ]; do
		if [ "${ipc_env_lines_needed}" -gt 0 ]; then
			if [ "${ipc_env_lines_needed}" -eq 2 ]; then
				ipc_env_key=${ipc_arg}
			else
				ipc_env_val=${ipc_arg}
			fi
			ipc_env_lines_needed=$((ipc_env_lines_needed - 1))
			continue
		fi
		set -- "$@" "${ipc_arg}"
		ipc_seen=$((ipc_seen + 1))
	done < "${ipc_payload_file}"

	if [ "${ipc_env_enabled}" -eq 1 ] && [ "${ipc_env_lines_needed}" -ne 0 ]; then
		ipc_send_error "${ipc_id}" 64 "invalid CALL payload: missing env data"
		return 0
	fi

	if [ "${ipc_env_enabled}" -eq 1 ]; then
		case "${ipc_env_key}" in
		[A-Za-z_][A-Za-z0-9_]*)
			;;
		*)
			ipc_send_error "${ipc_id}" 64 "invalid environment variable name"
			return 0
			;;
		esac
	fi

	if [ "${ipc_seen}" -ne "${ipc_argc}" ]; then
		ipc_send_error "${ipc_id}" 64 "invalid CALL payload: argc mismatch"
		return 0
	fi

	ipc_out_tmp=$(mktemp /tmp/cellmgr-ipc-out.XXXXXX)
	ipc_err_tmp=$(mktemp /tmp/cellmgr-ipc-err.XXXXXX)

	case "${ipc_mode}" in
	0)
		if [ "${ipc_env_enabled}" -eq 1 ]; then
			if (export "${ipc_env_key}=${ipc_env_val}" CELLMGR_CALL_CONTEXT=ipc; dispatch_command "$@") \
			    > "${ipc_out_tmp}" 2> "${ipc_err_tmp}"; then
				ipc_rc=0
			else
				ipc_rc=$?
			fi
		elif (export CELLMGR_CALL_CONTEXT=ipc; dispatch_command "$@") > "${ipc_out_tmp}" 2> "${ipc_err_tmp}"; then
			ipc_rc=0
		else
			ipc_rc=$?
		fi
		;;
	1)
		: > "${ipc_out_tmp}"
		: > "${ipc_err_tmp}"
		if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
			printf '%s\n' "interactive mode requires controlling tty" > "${ipc_err_tmp}"
			ipc_rc=1
		else
			if [ "${ipc_env_enabled}" -eq 1 ]; then
				if (export "${ipc_env_key}=${ipc_env_val}" CELLMGR_CALL_CONTEXT=ipc; dispatch_command "$@") \
				    < /dev/tty > /dev/tty 2> /dev/tty; then
					ipc_rc=0
				else
					ipc_rc=$?
				fi
			elif (export CELLMGR_CALL_CONTEXT=ipc; dispatch_command "$@") < /dev/tty > /dev/tty 2> /dev/tty; then
				ipc_rc=0
			else
				ipc_rc=$?
			fi
		fi
		;;
	*)
		rm -f "${ipc_out_tmp}" "${ipc_err_tmp}"
		ipc_send_error "${ipc_id}" 64 "invalid CALL mode: ${ipc_mode}"
		return 0
		;;
	esac

	ipc_out_len=$(wc -c < "${ipc_out_tmp}" | tr -d '[:space:]')
	ipc_err_len=$(wc -c < "${ipc_err_tmp}" | tr -d '[:space:]')
	ipc_total_len=$((ipc_out_len + ipc_err_len))
	printf 'M 1 RET %s %s %s %s %s\n' \
	    "${ipc_id}" "${ipc_rc}" "${ipc_out_len}" "${ipc_err_len}" "${ipc_total_len}"
	if [ "${ipc_total_len}" -gt 0 ]; then
		cat "${ipc_out_tmp}" "${ipc_err_tmp}"
	fi

	rm -f "${ipc_out_tmp}" "${ipc_err_tmp}"
	return 0
}

ipc_serve_stdio() {
	while IFS= read -r ipc_header; do
		[ -n "${ipc_header}" ] || continue
		set -- ${ipc_header}
		if [ $# -ne 8 ] || [ "$1" != "M" ]; then
			break
		fi

		ipc_ver=$2
		ipc_type=$3
		ipc_id=$4
		ipc_p1=$5
		ipc_p2=$6
		ipc_p3=$7
		ipc_len=$8

		if [ "${ipc_ver}" != "1" ] || \
		   ! is_uint "${ipc_id}" || ! is_uint "${ipc_p1}" || \
		   ! is_uint "${ipc_p2}" || ! is_uint "${ipc_p3}" || \
		   ! is_uint "${ipc_len}"; then
			break
		fi

		if [ "${ipc_len}" -gt 67108864 ]; then
			ipc_send_error "${ipc_id}" 68 "payload too large"
			break
		fi

		ipc_req_payload_file=$(mktemp /tmp/cellmgr-ipc-payload.XXXXXX)
		if ! ipc_read_payload "${ipc_len}" "${ipc_req_payload_file}"; then
			rm -f "${ipc_req_payload_file}"
			break
		fi

		case "${ipc_type}" in
		HELLO)
			ipc_send_frame_file HELLO "${ipc_id}" 0 0 0 /dev/null 0
			;;
		PING)
			ipc_send_frame_file PONG "${ipc_id}" 0 0 0 /dev/null 0
			;;
		BYE)
			ipc_send_frame_file BYE "${ipc_id}" 0 0 0 /dev/null 0
			rm -f "${ipc_req_payload_file}"
			return 0
			;;
		CALL)
			ipc_execute_call "${ipc_id}" "${ipc_p1}" "${ipc_p2}" \
			    "${ipc_p3}" "${ipc_req_payload_file}"
			;;
		*)
			ipc_send_error "${ipc_id}" 66 "unknown message type: ${ipc_type}"
			;;
		esac

		rm -f "${ipc_req_payload_file}"
	done

	return 0
}

run_ipc_serve_command() {
	transport=stdio

	while [ $# -gt 0 ]; do
		case "$1" in
		--stdio)
			transport=stdio
			shift
			;;
		-*)
			echo "ipc serve: unknown option $1" >&2
			return 1
			;;
		*)
			echo "ipc serve: unexpected argument $1" >&2
			return 1
			;;
		esac
	done

	case "${transport}" in
	stdio)
		ipc_serve_stdio
		;;
	*)
		echo "ipc serve: unsupported transport '${transport}'" >&2
		return 1
		;;
	esac
}

run_ipc_resource_command() {
	[ $# -ge 1 ] || {
		usage
		return 1
	}
	sub=$1
	shift
	case "${sub}" in
	serve)
		run_ipc_serve_command "$@"
		;;
	*)
		echo "unknown ipc command: ${sub}" >&2
		usage
		return 1
		;;
	esac
}
