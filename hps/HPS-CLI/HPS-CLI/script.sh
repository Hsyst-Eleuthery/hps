#!/usr/bin/env bash
set -euo pipefail

CONTROLLER="$HOME/.hps_cli/controller_hpscli"

echo "Digite o comando para enviar ao controller:"
read -r USER_CMD

if [[ -z "$USER_CMD" ]]; then
  echo "Comando vazio. Saindo."
  exit 1
fi

echo
echo "▶ Enviando comando para o controller..."
echo "$USER_CMD" > "$CONTROLLER"

sleep 1

LOGFILE=$(cat "$CONTROLLER")

if [[ ! -f "$LOGFILE" ]]; then
  echo "❌ Log não encontrado: $LOGFILE"
  exit 1
fi

echo
echo "// Diretório do log:"
echo "$LOGFILE"
echo
echo "▶ Monitorando log em tempo real (pressione 'n' para sair)"
echo "----------------------------------------"

# Terminal em modo raw
stty -echo -icanon time 0 min 0

TAIL_PID=""

cleanup() {
  stty sane
  [[ -n "$TAIL_PID" ]] && kill "$TAIL_PID" 2>/dev/null || true
  [[ -f "$LOGFILE" ]] && rm -f "$LOGFILE"
  echo
  echo "🧹 Log removido. Saindo."
  clear
  ./script.sh
}
trap cleanup EXIT

# Mostra conteúdo inicial
cat "$LOGFILE"

# Tail em tempo real (background)
tail -n 0 -f "$LOGFILE" &
TAIL_PID=$!

# Loop só para escutar teclado
while true; do
  read -r -n 1 KEY
  if [[ "$KEY" == "n" ]]; then
    break
  fi
  sleep 0.1
done
