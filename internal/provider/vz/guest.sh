#!/bin/sh
# bivouac guest bootstrap. Copied into each clone at boot through the bivouac
# guest agent, which runs inside the logged-in desktop session, so the runner
# it starts can open windows and take focus. The JIT config arrives on stdin.
set -u
dir=/tmp/bivouac
runner=${2:-$HOME/actions-runner}
case "${1:-}" in
start)
  umask 077
  mkdir -p "$dir" || exit 1
  jit=$(cat)
  if [ -z "$jit" ]; then echo "empty JIT config on stdin" >&2; exit 2; fi
  if [ ! -x "$runner/bin/Runner.Listener" ]; then echo "no runner at $runner" >&2; exit 3; fi
  cat > "$dir/job-started.sh" <<'HOOK'
#!/bin/sh
umask 077
# Only job identity is copied. Never dump the environment or event payload.
(printf 'run_id=%s\nrepository=%s\njob=%s\n' "$GITHUB_RUN_ID" "$GITHUB_REPOSITORY" "$GITHUB_JOB" > /tmp/bivouac/job.tmp && mv /tmp/bivouac/job.tmp /tmp/bivouac/job) || true
if [ -x /tmp/bivouac-helper ]; then
  /tmp/bivouac-helper guest macos hook "$BIVOUAC_RUNNER_DIRECTORY" || true
fi
HOOK
  chmod 700 "$dir/job-started.sh" || exit 3
  cat > "$dir/job-completed.sh" <<'HOOK'
#!/bin/sh
if [ -x /tmp/bivouac-helper ]; then
  /tmp/bivouac-helper guest macos hook-completed "$BIVOUAC_RUNNER_DIRECTORY" || true
fi
exit 0
HOOK
  # Completion telemetry must never prevent normal runner startup.
  chmod 700 "$dir/job-completed.sh" 2>/dev/null || true
  if [ -f /tmp/bivouac/cache-config.json ]; then
    export BIVOUAC_CACHE_CONFIG=/tmp/bivouac/cache-config.json
    export NODE_OPTIONS="${NODE_OPTIONS:-} --require=/tmp/bivouac-cache-preload.cjs"
    if [ -f /tmp/bivouac-cache-env ]; then
      { read -r proxy_endpoint; read -r cache_bypass; } < /tmp/bivouac-cache-env
      export http_proxy="$proxy_endpoint" https_proxy="$proxy_endpoint"
      export HTTP_PROXY="$proxy_endpoint" HTTPS_PROXY="$proxy_endpoint"
      export no_proxy="127.0.0.1,localhost,$cache_bypass${no_proxy:+,$no_proxy}"
      export NO_PROXY="$no_proxy${NO_PROXY:+,$NO_PROXY}"
      export SSL_CERT_FILE=/tmp/bivouac-cache-roots.pem
      export CURL_CA_BUNDLE=/tmp/bivouac-cache-roots.pem
      export GIT_SSL_CAINFO=/tmp/bivouac-cache-roots.pem
      export NODE_EXTRA_CA_CERTS=/tmp/bivouac-cache-ca.pem
    fi
  fi
  cd "$runner" || exit 3
  runner=$PWD
  export BIVOUAC_RUNNER_DIRECTORY="$runner"
  if [ -S /tmp/bivouac-container/api.sock ]; then
    export DOCKER_HOST=unix:///tmp/bivouac-container/api.sock
    export CONTAINER_HOST=unix:///tmp/bivouac-container/api.sock
    export DOCKER_CONFIG=/tmp/bivouac-container/docker-config
    unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH CONTAINER_CONNECTION
  fi
  # The whole subshell must drop the agent's stdin/stdout/stderr, or the
  # agent command stays open until the runner exits.
  (
    export ACTIONS_RUNNER_HOOK_JOB_STARTED="$dir/job-started.sh"
    if [ -x "$dir/job-completed.sh" ]; then
      export ACTIONS_RUNNER_HOOK_JOB_COMPLETED="$dir/job-completed.sh"
    fi
    export ACTIONS_RUNNER_INPUT_JITCONFIG="$jit"
    if [ -x /tmp/bivouac-helper ]; then
      /tmp/bivouac-helper guest macos run "$runner"
    else
      ./bin/Runner.Listener run &
      listener=$!
      echo "$listener" > "$dir/listener.pid"
      wait "$listener"
    fi
    echo $? > "$dir/runner.exit"
  ) > "$dir/runner.log" 2>&1 < /dev/null &
  echo $! > "$dir/runner.pid"
  unset jit
  echo started
  ;;
cache-setup)
  umask 077
  # All trust changes are in this disposable clone, never its baseline or host.
  sudo -n /usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/bivouac-cache-ca.pem || exit 3
  /usr/bin/security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > /tmp/bivouac-cache-roots.pem || exit 3
  /usr/bin/security find-certificate -a -p /Library/Keychains/System.keychain >> /tmp/bivouac-cache-roots.pem || exit 3
  /tmp/bivouac-helper cache proxy /tmp/bivouac/cache-config.json /tmp/bivouac-cache-env > /tmp/bivouac-cache-proxy.log 2>&1 < /dev/null &
  proxy_pid=$!
  attempt=0
  while [ ! -f /tmp/bivouac-cache-env ]; do
    kill -0 "$proxy_pid" 2>/dev/null || exit 3
    attempt=$((attempt + 1))
    [ "$attempt" -lt 150 ] || exit 3
    sleep 0.2
  done
  echo configured
  ;;
stop)
  if [ -f "$dir/runner.exit" ] || [ ! -f "$dir/listener.pid" ]; then exit 0; fi
  listener=$(cat "$dir/listener.pid")
  case "$listener" in ''|*[!0-9]*) echo "invalid listener pid" >&2; exit 4;; esac
  command=$(ps -p "$listener" -o comm=)
  case "$command" in */Runner.Listener) kill -TERM "$listener" || exit 0;; *) exit 0;; esac
  while kill -0 "$listener" 2>/dev/null; do sleep 0.2; done
  ;;
status)
  if [ -f "$dir/runner.exit" ]; then
    echo "exited $(cat "$dir/runner.exit")"
  elif [ -f "$dir/runner.pid" ] && kill -0 "$(cat "$dir/runner.pid")" 2>/dev/null; then
    if grep -q "Running job:" "$dir/runner.log" 2>/dev/null; then echo running
    elif grep -q "Listening for Jobs" "$dir/runner.log" 2>/dev/null; then echo listening
    else echo starting
    fi
  else
    echo absent
  fi
  if [ -f "$dir/job" ]; then cat "$dir/job"; fi
  ;;
diag)
  cd "$dir" 2>/dev/null || exit 0
  # The host validates/re-encodes optional numeric telemetry before retaining it.
  if [ -f performance.json ]; then tar czf - runner.log performance.json 2>/dev/null
  else tar czf - runner.log 2>/dev/null
  fi
  ;;
diag-runner)
  cd "$runner" 2>/dev/null || exit 0
  if [ -d _diag ]; then tar czf - _diag; fi
  ;;
session)
  launchctl managername
  ;;
*)
  echo "usage: bivouac-guest start|stop|status|diag|diag-runner|session [runner-dir]" >&2
  exit 64
  ;;
esac
