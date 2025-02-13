#!/usr/bin/fish

function __fish_pizauth_accounts --description "Helper function to parse accounts from config"
    set -l config (pizauth info | awk -F' *: *' '$1 ~ /config file/ { print $2 }')
    sed -n '/^account/{s/^account \(.*\) {/\1/;p}' $config | string unescape
end

function __fish_pizauth_is_main_command --description "Returns true if we're not in a subcommand"
    not __fish_seen_subcommand_from dump restore reload shutdown status info server refresh revoke show
end

# Don't autocomplete files
complete -c pizauth -f

# pizauth top-level commands
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Writes current pizauth state to stdout" -a "dump"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Writes output about pizauth to stdout" -a "info"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Request a refresh of the access token for account" -a "refresh"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Reloads the server's configuration" -a "reload"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Reads previously dumped pizauth state from stdin" -a "restore"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Removes token and cancels authorization for account" -a "revoke"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Start the server" -a "server"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Print access token of account to stdout" -a "show"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Shut the server down" -a "shutdown"
complete -c pizauth -n "__fish_pizauth_is_main_command" -d "Writes output about current accounts to stdout" -a "status"

# pizauth info [-j]
complete -c pizauth -n "__fish_seen_subcommand_from info" -s j -d "JSON output"

# pizauth refresh/show [-u] account
complete -c pizauth -n "__fish_seen_subcommand_from refresh show" -s u -d "Exclude authorization URL"
complete -c pizauth -n "__fish_seen_subcommand_from refresh show" -a "(__fish_pizauth_accounts)"

# pizauth revoke account
complete -c pizauth -n "__fish_seen_subcommand_from revoke" -a "(__fish_pizauth_accounts)"

# pizauth server [-c config-file] [-dv]
complete -c pizauth -n "__fish_seen_subcommand_from server" -l config -s c -r -F -d "Config file"
complete -c pizauth -n "__fish_seen_subcommand_from server" -s d -d "Do not daemonise"
complete -c pizauth -n "__fish_seen_subcommand_from server" -o v -d "Verbose"
complete -c pizauth -n "__fish_seen_subcommand_from server" -o vv -d "Verboser"
complete -c pizauth -n "__fish_seen_subcommand_from server" -o vvv -d "Verboserer"
complete -c pizauth -n "__fish_seen_subcommand_from server" -o vvvv -d "Verbosest"
