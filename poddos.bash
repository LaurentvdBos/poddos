# bash completion for poddos
# usage: source /etc/bash_completion.d/poddos

_poddos_runtime_dir() {
    if [ -n "$XDG_RUNTIME_DIR" ]; then
        printf '%s/poddos' "$XDG_RUNTIME_DIR"
    else
        printf '/tmp/poddos'
    fi
}

_poddos_layer_path() {
    if [ -n "$LAYERPATH" ]; then
        printf '%s' "$LAYERPATH"
        return
    fi
    if [ -n "$XDG_DATA_HOME" ]; then
        printf '%s/poddos' "$XDG_DATA_HOME"
        return
    fi
    if [ -n "$HOME" ]; then
        printf '%s/.local/share/poddos' "$HOME"
        return
    fi
    printf '/usr/local/share/poddos'
}

_poddos_names_configured() {
    local dir; dir=$(_poddos_layer_path)
    if [ -d "$dir" ]; then
        find "$dir" -maxdepth 1 -type f ! -name '*.2' -printf '%f\n' 2>/dev/null
    fi
}

_poddos_overlays() {
    local dir; dir=$(_poddos_layer_path)
    if [ -d "$dir" ]; then
        find "$dir" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null
    fi
}

_poddos_names_running() {
    local dir; dir=$(_poddos_runtime_dir)
    if [ -d "$dir" ]; then
        find "$dir" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null
    fi
}

_poddos_names_start() {
    local config run name
    mapfile -t config < <(_poddos_names_configured)
    mapfile -t run < <(_poddos_names_running)
    for name in "${config[@]}"; do
        local ok=1
        for r in "${run[@]}"; do
            [ "$name" = "$r" ] && ok=0 && break
        done
        [ "$ok" -eq 1 ] && printf '%s\n' "$name"
    done
}

_poddos_option_candidates() {
    local subcmd="$1"
    case "$subcmd" in
        pull)
            printf '%s ' --url --help --usage
            ;;
        start)
            printf '%s ' --overlay --env --ephemeral --no-ephemeral --net --mac --dns --bind --directory --help --usage
            ;;
        exec)
            printf '%s ' --env --help --usage
            ;;
        prune)
            printf '%s ' --all --force --help --usage
            printf '%s ' $(_poddos_overlays)
            ;;
        *)
            printf '%s ' pull start exec prune --layer --name --help --usage
            ;;
    esac
}

_poddos() {
    local cur prev words cword
    _get_comp_words_by_ref -n : cur prev words cword

    local subcmd=""
    for ((i = 1; i < cword; i++)); do
        case "${words[i]}" in
            pull|start|exec|prune)
                subcmd="${words[i]}"
                break
                ;;
        esac
    done

    if [[ "$prev" == "--net" ]]; then
        local ifs
        ifs=$(ls /sys/class/net 2>/dev/null)
        COMPREPLY=( $(compgen -W "$ifs" -- "$cur") )
        return 0
    fi

    if [[ "$prev" == "--env" || "$prev" == "--dns" || "$prev" == "--bind" || "$prev" == "--mac" || "$prev" == "--directory" || "$prev" == "--url" ]]; then
        # These options expect a value, so do not complete flags here.
        return 0
    fi

    if [[ "$prev" == "--overlay" || "$prev" == "-o" ]]; then
        local layer_root
        layer_root=$(_poddos_layer_path)
        local candidates=""

        # absolute paths from filesystem
        if [ -z "$cur" ] || [[ "$cur" == /* ]]; then
            candidates=$(compgen -f -- "$cur")
        fi

        # overlays from layer directory
        candidates="$candidates $(printf '%s ' $(_poddos_overlays))"

        COMPREPLY=( $(compgen -W "$candidates" -- "$cur") )
        return 0
    fi

    if [[ "$prev" == "--name" || "$prev" == "-n" ]]; then
        case "$subcmd" in
            exec)
                COMPREPLY=( $(compgen -W "$(printf '%s ' $(_poddos_names_running))" -- "$cur") )
                return 0
                ;;
            start)
                COMPREPLY=( $(compgen -W "$(printf '%s ' $(_poddos_names_start))" -- "$cur") )
                return 0
                ;;
            *)
                COMPREPLY=( $(compgen -W "$(printf '%s ' $(_poddos_names_configured))" -- "$cur") )
                return 0
                ;;
        esac
    fi

    if (( cword > 1 )); then
        local prevprev
        prevprev=${words[cword-2]}

        if [[ "$subcmd" != "" ]]; then
            COMPREPLY=( $(compgen -W "$(_poddos_option_candidates "$subcmd")" -- "$cur") )
            return 0
        fi

        case "$prevprev" in
            --layer|--name|-n|--overlay|-o|--net|--mac|--dns|--bind|--directory|--env)
                COMPREPLY=( $(compgen -W "$(_poddos_option_candidates "")" -- "$cur") )
                return 0
                ;;
        esac
    fi

    if [ $cword -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$(_poddos_option_candidates "")" -- "$cur") )
        return 0
    fi

    if [ $cword -eq 2 ]; then
        if [[ "$subcmd" == "" ]]; then
            if [[ "$cur" != -* ]]; then
                COMPREPLY=( $(compgen -W "pull start exec prune" -- "$cur") )
            fi
            return 0
        fi

        COMPREPLY=( $(compgen -W "$(_poddos_option_candidates "$subcmd")" -- "$cur") )
        return 0
    fi

    # For other options prefer default completion
    return 0
}

complete -F _poddos poddos
