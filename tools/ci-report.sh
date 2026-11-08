#!/bin/bash
# Bazarish project (c) 2026
# What the failed step said, as annotations: a run's log is readable only with
# rights on the repository, while an annotation is readable by anyone who can
# read the repository itself.
set -u

# GitHub keeps ten error annotations of a step and drops the rest, so all of it
# goes out as one annotation, its lines joined by the escape a workflow command
# reads as a line break.
readonly kLines=120
readonly kTailLines=40
# GitHub cuts an annotation at 4096 characters, so what it shows is fitted to that,
# less room for the line that names the log.
readonly kShownChars=4000

# Each step writes its own log, so the newest one is the step that just failed.
log=$(ls -t ci-*.log 2>/dev/null | head -n 1)
if [ -z "$log" ]; then
    echo "::error::the step left no log behind"
    exit 0
fi
if [ ! -s "$log" ]; then
    echo "::error::$log is empty: the step printed nothing before it failed"
    exit 0
fi

# The lines around the first mark, which is where the failure is named: for a
# compile error the lines above it are the include chain that says which file
# asked for it, and for a test the lines above it are what the test itself
# printed before it stopped.
window() {
    local pattern=$1 before=$2 after=$3 text=$4
    local at
    at=$(printf '%s\n' "$text" | grep -naE "$pattern" | head -n 1 | cut -d: -f1)
    if [ -n "$at" ]; then
        printf '%s\n' "$text" | sed -n "$((at > before ? at - before : 1)),$((at + after))p"
    fi
}

# Ninja's own "FAILED:" line is not a mark: it comes first and would push the
# error that follows it out of frame.
whole=$(cat "$log")
failures=$(sed -n '/The following tests FAILED/,$p' "$log")
if [ -n "$failures" ]; then
    # A test that hung is read by how its output ends, so each failed test gives
    # its result line and the last lines it printed.
    told=$(sed '/The following tests FAILED/,$d' "$log" | grep -avE '^[[:space:]]*Start +[0-9]+:' \
        | awk -v keep="$kTailLines" '
            function flush() { if (head != "") { print head; for (i = n - keep + 1; i <= n; ++i) if (i > 0) print lines[i] } head = ""; n = 0 }
            / Test +#[0-9]+: / { flush(); if ($0 ~ /\*\*\*(Timeout|Failed|Exception)/) head = $0; next }
            head != "" { lines[++n] = $0 }
            END { flush() }')
    body=$(printf '%s\n%s' "$told" "$failures" | grep -v '^[[:space:]]*$' | head -n "$kLines")
    body=${body:0:kShownChars}
else
    # The first mark is where a compile went wrong; a tool that warns on its way
    # stops at its last, so the lines the step ended with follow it.
    marked=$(window 'CHECK failed|error:|ERROR:|error [A-Z]+[0-9]+|CMake Error' 6 3 "$whole" \
        | grep -v '^[[:space:]]*$' | head -n "$kLines")
    marked=${marked:0:kShownChars/2}
    ending=$(tail -n "$kLines" "$log" | grep -v '^[[:space:]]*$')
    room=$((kShownChars - ${#marked}))
    if [ "${#ending}" -gt "$room" ]; then
        ending=${ending: -room}
    fi
    body=$(printf '%s\n...\n%s' "$marked" "$ending")
fi
body=${body//%/%25}
body=${body//$'\r'/%0D}
body=${body//$'\n'/%0A}
printf '::error::%s said:%%0A%s\n' "$log" "$body"
