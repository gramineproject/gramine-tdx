#!/bin/sh

set -e

if [ "$#" -ne 2 ]; then
    echo "usage: $0 BASE_JSON OUTPUT_JSON" >&2
    exit 1
fi

base_json=$1
output_json=$2

# For TDX CI, move `name_to_handle_at` from the CAP_SYS_ADMIN allow-list to
# the CAP_DAC_READ_SEARCH allow-list used by virtiofsd.
jq '
    .syscalls |= map(
        if .action == "SCMP_ACT_ALLOW"
           and ((.includes?.caps? // []) | any(. == "CAP_DAC_READ_SEARCH"))
           and (.names | any(. == "open_by_handle_at"))
        then
            .names |= (. + ["name_to_handle_at"] | unique)
        elif .action == "SCMP_ACT_ALLOW"
             and ((.includes?.caps? // []) | any(. == "CAP_SYS_ADMIN"))
             and (.names | any(. == "name_to_handle_at"))
        then
            .names |= map(select(. != "name_to_handle_at"))
        else
            .
        end
    )
' "$base_json" > "$output_json"
