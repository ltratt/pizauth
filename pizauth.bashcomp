#!/bin/bash
_server() {
    local cur prev

    prev=${COMP_WORDS[COMP_CWORD - 1]}
    cur=${COMP_WORDS[COMP_CWORD]}
    case "$prev" in
        -c) _filedir;;
        *) mapfile -t COMPREPLY < \
            <(compgen -W '-c -d -v -vv -vvv -vvvv' -- "$cur");;
    esac
}
_accounts(){
    local config

    config="$(pizauth info | awk -F' *: *' '$1 ~ /config file/ { print $2 }')"
    sed -n '/^account/{s/^account \(.*\) {/\1/;p}' "$config"
}
_pizauth()
{
    local cur prev sub
    local cmds=(dump info refresh restore reload server show shutdown status)

    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD - 1]}
    sub=${COMP_WORDS[1]}

    if [ "$sub" == server ] && [ "$COMP_CWORD" -gt 1 ]; then _server; return; fi

    case ${COMP_CWORD} in
        1)  mapfile -t COMPREPLY < <(compgen -W "${cmds[*]}" -- "$cur");;
        2)
            case $sub in
                dump|restore|reload|shutdown|status) COMPREPLY=();;
                info) mapfile -t COMPREPLY < <(compgen -W '-j' -- "$cur") ;;
                refresh|show)
                    local accounts
                    mapfile -t accounts < <(_accounts)
                    accounts+=(-u)
                    mapfile -t COMPREPLY < \
                        <(compgen -W "${accounts[*]}" -- "$cur")
                    ;;
            esac
            ;;
        3)
            case $sub in
                refresh|show)
                    case $prev in
                        -u)
                            local accounts
                            mapfile -t accounts < <(_accounts)
                            mapfile -t COMPREPLY < \
                                <(compgen -W "${accounts[*]}" -- "$cur")
                            ;;
                        *) COMPREPLY=()
                    esac
                    ;;
            esac
            ;;
        *)
            COMPREPLY=()
            ;;
    esac
}

complete -F _pizauth pizauth
