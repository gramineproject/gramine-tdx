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
           and .includes.caps == ["CAP_DAC_READ_SEARCH"]
           and (.names | index("open_by_handle_at")) != null
        then
            .names |= if index("name_to_handle_at") == null
                      then . + ["name_to_handle_at"]
                      else .
                      end
        elif .action == "SCMP_ACT_ALLOW"
             and .includes.caps == ["CAP_SYS_ADMIN"]
             and (.names | index("name_to_handle_at")) != null
        then
            .names |= map(select(. != "name_to_handle_at"))
        else
            .
        end
    )
' "$base_json" > "$output_json"
