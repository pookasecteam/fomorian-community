#!/bin/bash
# fomorian/scripts/inject-logs.sh
#
# Injects Fomorian attack logs through Wazuh for detection testing
# Logs are in standard Wazuh alert format - compatible with any Wazuh setup
#
# Usage: ./inject-logs.sh <log-file-or-directory> [-m mode] [-t target] [-d delay]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default configuration
MODE="${MODE:-wazuh}"
TARGET="${TARGET:-your-wazuh-host}"
DELAY="${DELAY:-100}"
MAX_PARALLEL="${MAX_PARALLEL:-5}"
VERBOSE="${VERBOSE:-false}"
DRY_RUN="${DRY_RUN:-false}"
BATCH_SIZE="${BATCH_SIZE:-50}"
SSH_OPTIONS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

usage() {
    echo "Fomorian Attack Log Injector"
    echo ""
    echo "Injects attack simulation logs through Wazuh for detection testing."
    echo "Logs are in standard Wazuh alert format - works with ANY Wazuh setup."
    echo ""
    echo "Usage: $0 [options] <path>"
    echo ""
    echo "Options:"
    echo "  -m, --mode <mode>     Injection mode (default: wazuh)"
    echo "                        - wazuh: Append to Wazuh alerts.json (recommended)"
    echo "                        - logtest: Test through wazuh-logtest"
    echo "                        - print: Print logs to stdout (for piping)"
    echo "                        - batch: Batch mode - faster bulk injection"
    echo "  -t, --target <host>  SSH target for Wazuh manager (default: your-wazuh-host)"
    echo "  -d, --delay <ms>     Delay between logs in milliseconds (default: 100)"
    echo "  -b, --batch <n>      Batch size for batch mode (default: 50)"
    echo "  -p, --parallel <n>    Max parallel SSH connections (default: 5)"
    echo "  -v, --verbose        Verbose output"
    echo "  -n, --dry-run        Parse and validate only, don't inject"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 attacks/credential-access/T1003.001-lsass-memory/logs/001-procdump-lsass.json"
    echo "  $0 attacks/execution/T1059.001-powershell/"
    echo "  $0 -m logtest attacks/defense-evasion/T1027.004-compile-after-delivery/"
    echo "  $0 -m print attacks/scenarios/ransomware-attack/ > /tmp/attack-logs.json"
    echo "  $0 -m batch -b 100 attacks/    # Fast bulk injection"
    echo ""
    echo "Note: Direct injection to downstream SIEMs (Graylog, Splunk, ELK) is NOT supported."
    echo "      Logs should flow through Wazuh to maintain proper field mappings."
    echo ""
}

MODE="wazuh"
TARGET="your-wazuh-host"
DELAY=100
BATCH_SIZE=50
MAX_PARALLEL=5
VERBOSE=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -b|--batch)
            BATCH_SIZE="$2"
            shift 2
            ;;
        -p|--parallel)
            MAX_PARALLEL="$2"
            shift 2
            ;;
                -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            INPUT_PATH="$1"
            shift
            ;;
    esac
done

if [ -z "$INPUT_PATH" ]; then
    usage
    exit 1
fi

# Resolve path relative to project dir if needed
if [[ ! "$INPUT_PATH" = /* ]]; then
    if [[ -e "$PROJECT_DIR/$INPUT_PATH" ]]; then
        INPUT_PATH="$PROJECT_DIR/$INPUT_PATH"
    fi
fi

# Find all JSON log files
if [ -d "$INPUT_PATH" ]; then
    LOG_FILES=$(find "$INPUT_PATH" -name "*.json" -type f | sort)
else
    LOG_FILES="$INPUT_PATH"
fi

if [ -z "$LOG_FILES" ]; then
    echo -e "${RED}No JSON files found in: $INPUT_PATH${NC}"
    exit 1
fi

echo -e "${BLUE}=== Fomorian Attack Log Injector ===${NC}"
echo -e "Mode: ${YELLOW}$MODE${NC}"
echo -e "Target: ${YELLOW}$INPUT_PATH${NC}"
if [ "$MODE" = "wazuh" ] || [ "$MODE" = "logtest" ]; then
    echo -e "Wazuh Host: ${YELLOW}$TARGET${NC}"
fi
echo ""

# Count total logs
TOTAL_FILES=$(echo "$LOG_FILES" | wc -l | tr -d ' ')
TOTAL_LOGS=0
INJECTED=0
FAILED=0

for FILE in $LOG_FILES; do
    echo -e "${BLUE}Processing: ${NC}$(basename $FILE)"

    # Read metadata
    ATTACK_ID=$(jq -r '._metadata.attack_id // "unknown"' "$FILE" 2>/dev/null)
    VARIATION=$(jq -r '._metadata.variation // "unknown"' "$FILE" 2>/dev/null)
    NAME=$(jq -r '._metadata.name // "unknown"' "$FILE" 2>/dev/null)
    EXPECTED=$(jq -r '._metadata.expected_detection // "unknown"' "$FILE" 2>/dev/null)

    if [ "$VERBOSE" = true ]; then
        echo -e "  Attack: ${YELLOW}$ATTACK_ID${NC} - $NAME"
        echo -e "  Expected: ${YELLOW}$EXPECTED${NC}"
    fi

    # Count logs in file
    LOG_COUNT=$(jq '.logs | length' "$FILE" 2>/dev/null || echo "0")

    if [ "$LOG_COUNT" = "0" ]; then
        echo -e "  ${YELLOW}Warning: No logs found in file${NC}"
        continue
    fi

    TOTAL_LOGS=$((TOTAL_LOGS + LOG_COUNT))

    # Process each log entry
    for i in $(seq 0 $((LOG_COUNT - 1))); do
        LOG=$(jq -c ".logs[$i].log" "$FILE" 2>/dev/null)
        SEQUENCE=$(jq -r ".logs[$i].sequence" "$FILE" 2>/dev/null)
        COMMENT=$(jq -r ".logs[$i]._comment // \"\"" "$FILE" 2>/dev/null)

        if [ "$VERBOSE" = true ]; then
            echo -e "  [$SEQUENCE] $COMMENT"
        fi

        if [ "$DRY_RUN" = true ]; then
            echo -e "  ${GREEN}[DRY-RUN]${NC} Would inject log $SEQUENCE"
            INJECTED=$((INJECTED + 1))
            continue
        fi

        # Inject based on mode
        case $MODE in
            wazuh)
                # Append to Wazuh alerts.json for Filebeat to pick up
                # This is the standard Wazuh alert format
                RESULT=$(ssh "$TARGET" "echo '$LOG' | sudo tee -a /var/ossec/logs/alerts/alerts.json > /dev/null" 2>&1)
                if [ $? -eq 0 ]; then
                    echo -e "  ${GREEN}[OK]${NC} Appended to alerts.json"
                    INJECTED=$((INJECTED + 1))
                else
                    echo -e "  ${RED}[FAIL]${NC} Failed to append: $RESULT"
                    FAILED=$((FAILED + 1))
                fi
                ;;
            logtest)
                # Wazuh logtest for rule validation (doesn't persist)
                RESULT=$(ssh "$TARGET" "echo '$LOG' | docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest" 2>&1)
                if echo "$RESULT" | grep -q "rule"; then
                    echo -e "  ${GREEN}[OK]${NC} Processed via logtest"
                    INJECTED=$((INJECTED + 1))
                else
                    echo -e "  ${RED}[FAIL]${NC} Logtest failed"
                    FAILED=$((FAILED + 1))
                fi
                ;;
            print)
                # Print to stdout - useful for piping or manual review
                echo "$LOG"
                INJECTED=$((INJECTED + 1))
                ;;
            *)
                echo -e "${RED}Unknown mode: $MODE${NC}"
                exit 1
                ;;
        esac

        # Delay between logs
        if [ "$DELAY" -gt 0 ] && [ "$MODE" != "print" ]; then
            sleep $(echo "scale=3; $DELAY/1000" | bc)
        fi
    done

    echo ""
done

echo -e "${BLUE}=== Summary ===${NC}"
echo -e "Files processed: ${YELLOW}$TOTAL_FILES${NC}"
echo -e "Total logs: ${YELLOW}$TOTAL_LOGS${NC}"
echo -e "Injected: ${GREEN}$INJECTED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"

if [ "$DRY_RUN" = true ]; then
    echo -e "\n${YELLOW}This was a dry run. No logs were actually injected.${NC}"
fi
