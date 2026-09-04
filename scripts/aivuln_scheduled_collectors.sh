#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000}"

STATE_DIR="/var/lib/ai-vulnerability-management/scheduler_state"

OPERATIONAL_CHANGELOG="/var/lib/ai-vulnerability-management/changelog/events.jsonl"

AUDIT_CHANGELOG="/var/lib/ai-vulnerability-management/evidence/changelog.jsonl"

EVIDENCE_ROOT="/var/lib/ai-vulnerability-management/evidence"

DB_SOURCES_FILE="${DB_SOURCES_FILE:-/opt/ai-vulnerability-management/iam-db-collector/config/sources.json}"

collectors='[
  "iam_users",
  "os_inventory",
  "disk_usage",
  "docker_inventory",
  "listening_ports",
  "package_inventory"
]'

mkdir -p \
  "$STATE_DIR" \
  "$(dirname "$OPERATIONAL_CHANGELOG")" \
  "$(dirname "$AUDIT_CHANGELOG")"

exec 9>"${STATE_DIR}/scheduler.lock"

if ! flock -n 9
then
  exit 0
fi

ts() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

operational_event() {
  local asset_id="$1"
  local collector="$2"
  local event_type="$3"
  local message="$4"

  jq -nc \
    --arg timestamp "$(ts)" \
    --arg asset_id "$asset_id" \
    --arg collector "$collector" \
    --arg event_type "$event_type" \
    --arg message "$message" \
    '{
      timestamp: $timestamp,
      asset_id: $asset_id,
      collector: $collector,
      event_type: $event_type,
      message: $message
    }' \
    >> "$OPERATIONAL_CHANGELOG"
}

audit_event() {
  local asset_id="$1"
  local event_type="$2"
  local summary="$3"
  local details="${4-}"

  if [ -z "$details" ]
  then
    details='{}'
  fi

  if ! jq -e . >/dev/null 2>&1 <<<"$details"
  then
    details='{}'
  fi

  jq -nc \
    --arg timestamp "$(ts)" \
    --arg asset_id "$asset_id" \
    --arg event_type "$event_type" \
    --arg summary "$summary" \
    --argjson details "$details" \
    '{
      timestamp: $timestamp,
      event_type: $event_type,
      asset_id: $asset_id,
      summary: $summary,
      details: $details
    }' \
    >> "$AUDIT_CHANGELOG"
}

normalize_evidence() {
  local file="$1"

  jq -c '
    if (.stdout? | type) == "string"
    then
      (
        .stdout
        | fromjson? // .
      )
    else
      .
    end
    | del(.collected_at)
  ' "$file" 2>/dev/null || cat "$file"
}

process_server_user_changes() {
  local asset="$1"
  local previous="$2"
  local current="$3"

  local old_users
  local new_users

  old_users="$(
    jq -r \
      '.users[]?.username // empty' \
      "$previous" 2>/dev/null |
      sort -u
  )"

  new_users="$(
    jq -r \
      '.users[]?.username // empty' \
      "$current" 2>/dev/null |
      sort -u
  )"

  while IFS= read -r username
  do
    [ -n "$username" ] || continue

    audit_event \
      "$asset" \
      "server_user_added" \
      "Server user ${username} added to ${asset}." \
      "$(
        jq -nc \
          --arg username "$username" \
          --arg asset_id "$asset" \
          '{
            username: $username,
            asset_id: $asset_id,
            source: "iam_users"
          }'
      )"
  done < <(
    comm -13 \
      <(printf '%s\n' "$old_users") \
      <(printf '%s\n' "$new_users")
  )

  while IFS= read -r username
  do
    [ -n "$username" ] || continue

    audit_event \
      "$asset" \
      "server_user_removed" \
      "Server user ${username} removed from ${asset}." \
      "$(
        jq -nc \
          --arg username "$username" \
          --arg asset_id "$asset" \
          '{
            username: $username,
            asset_id: $asset_id,
            source: "iam_users"
          }'
      )"
  done < <(
    comm -23 \
      <(printf '%s\n' "$old_users") \
      <(printf '%s\n' "$new_users")
  )
}

process_server_group_changes() {
  local asset="$1"
  local previous="$2"
  local current="$3"

  # If the previous evidence predates group inventory,
  # establish a baseline without reporting every group.
  if ! jq -e \
    '.groups | type == "array"' \
    "$previous" >/dev/null 2>&1
  then
    return 0
  fi

  if ! jq -e \
    '.groups | type == "array"' \
    "$current" >/dev/null 2>&1
  then
    return 0
  fi

  local old_groups
  local new_groups

  old_groups="$(
    jq -r \
      '.groups[]?.group_name // empty' \
      "$previous" |
      sort -u
  )"

  new_groups="$(
    jq -r \
      '.groups[]?.group_name // empty' \
      "$current" |
      sort -u
  )"

  while IFS= read -r group_name
  do
    [ -n "$group_name" ] || continue

    audit_event \
      "$asset" \
      "server_group_added" \
      "Server group ${group_name} added to ${asset}." \
      "$(
        jq -nc \
          --arg group_name "$group_name" \
          --arg asset_id "$asset" \
          '{
            group_name: $group_name,
            asset_id: $asset_id,
            source: "iam_users"
          }'
      )"
  done < <(
    comm -13 \
      <(printf '%s\n' "$old_groups") \
      <(printf '%s\n' "$new_groups")
  )

  while IFS= read -r group_name
  do
    [ -n "$group_name" ] || continue

    audit_event \
      "$asset" \
      "server_group_removed" \
      "Server group ${group_name} removed from ${asset}." \
      "$(
        jq -nc \
          --arg group_name "$group_name" \
          --arg asset_id "$asset" \
          '{
            group_name: $group_name,
            asset_id: $asset_id,
            source: "iam_users"
          }'
      )"
  done < <(
    comm -23 \
      <(printf '%s\n' "$old_groups") \
      <(printf '%s\n' "$new_groups")
  )
}

process_server_group_membership_changes() {
  local asset="$1"
  local previous="$2"
  local current="$3"

  local old_memberships
  local new_memberships

  old_memberships="$(
    jq -r '
      .users[]? as $user
      | $user.groups[]?
      | [
          $user.username,
          .
        ]
      | @tsv
    ' "$previous" 2>/dev/null |
      sort -u
  )"

  new_memberships="$(
    jq -r '
      .users[]? as $user
      | $user.groups[]?
      | [
          $user.username,
          .
        ]
      | @tsv
    ' "$current" 2>/dev/null |
      sort -u
  )"

  while IFS=$'\t' read -r \
    username \
    group_name
  do
    [ -n "$username" ] || continue
    [ -n "$group_name" ] || continue

    audit_event \
      "$asset" \
      "server_group_membership_added" \
      "Server user ${username} added to group ${group_name} on ${asset}." \
      "$(
        jq -nc \
          --arg username "$username" \
          --arg group_name "$group_name" \
          --arg asset_id "$asset" \
          '{
            username: $username,
            group_name: $group_name,
            asset_id: $asset_id,
            source: "iam_users"
          }'
      )"
  done < <(
    comm -13 \
      <(printf '%s\n' "$old_memberships") \
      <(printf '%s\n' "$new_memberships")
  )

  while IFS=$'\t' read -r \
    username \
    group_name
  do
    [ -n "$username" ] || continue
    [ -n "$group_name" ] || continue

    audit_event \
      "$asset" \
      "server_group_membership_removed" \
      "Server user ${username} removed from group ${group_name} on ${asset}." \
      "$(
        jq -nc \
          --arg username "$username" \
          --arg group_name "$group_name" \
          --arg asset_id "$asset" \
          '{
            username: $username,
            group_name: $group_name,
            asset_id: $asset_id,
            source: "iam_users"
          }'
      )"
  done < <(
    comm -23 \
      <(printf '%s\n' "$old_memberships") \
      <(printf '%s\n' "$new_memberships")
  )
}

process_change() {
  local asset="$1"
  local collector="$2"
  local evidence_id="$3"

  local file="${EVIDENCE_ROOT}/${asset}/${collector}/${evidence_id}.json"

  [ -f "$file" ] || return 0

  local safe
  safe="$(
    printf '%s_%s' "$asset" "$collector" |
      tr -c 'A-Za-z0-9_.-' '_'
  )"

  local current="${STATE_DIR}/${safe}.current.json"
  local previous="${STATE_DIR}/${safe}.previous.json"
  local new="${STATE_DIR}/${safe}.new.json"

  normalize_evidence "$file" > "$new"

  if [ ! -f "$current" ]
  then
    cp "$new" "$current"

    operational_event \
      "$asset" \
      "$collector" \
      "collector_initial_state" \
      "Initial evidence state recorded."

    return 0
  fi

  if cmp -s "$current" "$new"
  then
    rm -f "$new"
    return 0
  fi

  cp "$current" "$previous"
  cp "$new" "$current"
  rm -f "$new"

  operational_event \
    "$asset" \
    "$collector" \
    "collector_state_changed" \
    "Evidence state changed."

  if [ "$collector" = "iam_users" ]
  then
    process_server_user_changes \
      "$asset" \
      "$previous" \
      "$current"

    process_server_group_changes \
      "$asset" \
      "$previous" \
      "$current"

    process_server_group_membership_changes \
      "$asset" \
      "$previous" \
      "$current"
  fi
}

normalize_db_sources() {
  local source_file="$1"
  local output_file="$2"

  jq -c '
    if type != "array"
    then
      error(
        "Database source configuration must be an array"
      )
    else
      map(
        select(
          (.id // "" | tostring | length) > 0
        )
        | {
            id: (.id | tostring),
            name: (
              .name
              // .id
              | tostring
            ),
            type: (
              .type
              // "postgres"
              | tostring
            ),
            host: (
              .host
              // null
            ),
            port: (
              .port
              // null
            ),
            database: (
              .database
              // null
            ),
            enabled: (
              .enabled
              // true
            )
          }
      )
      | sort_by(.id)
    end
  ' "$source_file" > "$output_file"
}

process_db_collector_changes() {
  local current="${STATE_DIR}/db_collectors.current.json"
  local previous="${STATE_DIR}/db_collectors.previous.json"
  local new="${STATE_DIR}/db_collectors.new.json"

  if [ ! -r "$DB_SOURCES_FILE" ]
  then
    operational_event \
      "iam-db-collector" \
      "database_sources" \
      "db_collector_config_unavailable" \
      "Database collector source configuration is unavailable."

    return 0
  fi

  if ! normalize_db_sources \
    "$DB_SOURCES_FILE" \
    "$new"
  then
    rm -f "$new"

    operational_event \
      "iam-db-collector" \
      "database_sources" \
      "db_collector_config_invalid" \
      "Database collector source configuration is invalid."

    return 0
  fi

  if [ ! -f "$current" ]
  then
    cp "$new" "$current"
    rm -f "$new"

    operational_event \
      "iam-db-collector" \
      "database_sources" \
      "db_collector_initial_state" \
      "Initial database collector configuration recorded."

    return 0
  fi

  if cmp -s "$current" "$new"
  then
    rm -f "$new"
    return 0
  fi

  cp "$current" "$previous"

  while IFS=$'\t' read -r \
    source_id \
    source_name \
    source_type \
    source_host \
    source_port \
    source_database \
    source_enabled
  do
    [ -n "$source_id" ] || continue

    audit_event \
      "$source_id" \
      "db_collector_added" \
      "Database collector ${source_name} added." \
      "$(
        jq -nc \
          --arg source_id "$source_id" \
          --arg source_name "$source_name" \
          --arg source_type "$source_type" \
          --arg source_host "$source_host" \
          --arg source_port "$source_port" \
          --arg source_database "$source_database" \
          --argjson enabled "$source_enabled" \
          '{
            source_id: $source_id,
            source_name: $source_name,
            source_type: $source_type,
            host: $source_host,
            port: $source_port,
            database: $source_database,
            enabled: $enabled
          }'
      )"
  done < <(
    jq -r \
      --slurpfile previous "$previous" '
        . as $current
        | ($previous[0] // []) as $old
        | $current[]
        | select(
            .id as $id
            | (
                $old
                | map(.id)
                | index($id)
              ) == null
          )
        | [
            .id,
            .name,
            .type,
            (.host // ""),
            (
              .port
              // ""
              | tostring
            ),
            (.database // ""),
            (
              .enabled
              | tostring
            )
          ]
        | @tsv
      ' "$new"
  )

  while IFS=$'\t' read -r \
    source_id \
    source_name \
    source_type \
    source_host \
    source_port \
    source_database \
    source_enabled
  do
    [ -n "$source_id" ] || continue

    audit_event \
      "$source_id" \
      "db_collector_removed" \
      "Database collector ${source_name} removed." \
      "$(
        jq -nc \
          --arg source_id "$source_id" \
          --arg source_name "$source_name" \
          --arg source_type "$source_type" \
          --arg source_host "$source_host" \
          --arg source_port "$source_port" \
          --arg source_database "$source_database" \
          --argjson enabled "$source_enabled" \
          '{
            source_id: $source_id,
            source_name: $source_name,
            source_type: $source_type,
            host: $source_host,
            port: $source_port,
            database: $source_database,
            enabled: $enabled
          }'
      )"
  done < <(
    jq -r \
      --slurpfile current_state "$new" '
        . as $previous
        | ($current_state[0] // []) as $current
        | $previous[]
        | select(
            .id as $id
            | (
                $current
                | map(.id)
                | index($id)
              ) == null
          )
        | [
            .id,
            .name,
            .type,
            (.host // ""),
            (
              .port
              // ""
              | tostring
            ),
            (.database // ""),
            (
              .enabled
              | tostring
            )
          ]
        | @tsv
      ' "$previous"
  )

  cp "$new" "$current"
  rm -f "$new"

  operational_event \
    "iam-db-collector" \
    "database_sources" \
    "db_collector_state_changed" \
    "Database collector configuration changed."
}

process_db_collector_changes

curl -fsS "${API_URL}/api/assets/" |
  jq -c '
    .[]
    | select(
        (.agent_status // "")
        | test(
            "deployed"
        )
      )
  ' |
  while IFS= read -r asset
  do
    asset_id="$(
      jq -r \
        '.asset_id' \
        <<<"$asset"
    )"

    echo "[$(ts)] Running baseline collectors for ${asset_id}"

    if ! response="$(
      curl -fsS \
        -X POST \
        "${API_URL}/api/collectors/run" \
        -H "Content-Type: application/json" \
        -d "$(
          jq -nc \
            --arg asset_id "$asset_id" \
            --argjson collectors "$collectors" \
            '{
              asset_id: $asset_id,
              collectors: $collectors
            }'
        )"
    )"
    then
      operational_event \
        "$asset_id" \
        "all" \
        "collector_run_failed" \
        "Collector API request failed."

      continue
    fi

    if ! jq -e . >/dev/null 2>&1 <<<"$response"
    then
      operational_event \
        "$asset_id" \
        "all" \
        "collector_run_failed" \
        "Collector API returned a non-JSON response."

      continue
    fi

    while IFS= read -r result
    do
      collector="$(
        jq -r \
          '.collector' \
          <<<"$result"
      )"

      status="$(
        jq -r \
          '.status' \
          <<<"$result"
      )"

      evidence_id="$(
        jq -r \
          '.evidence_id // empty' \
          <<<"$result"
      )"

      operational_event \
        "$asset_id" \
        "$collector" \
        "collector_run_${status}" \
        "${collector} status ${status}."

      if [ "$status" = "completed" ] &&
         [ -n "$evidence_id" ]
      then
        process_change \
          "$asset_id" \
          "$collector" \
          "$evidence_id"
      fi
    done < <(
      jq -c \
        '.results[]?' \
        <<<"$response"
    )
  done
