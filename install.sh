#!/usr/bin/env bash
# Fomorian One-Liner Installer
# Usage: curl -sSL https://raw.githubusercontent.com/pookasec/fomorian/main/install.sh | bash
#    or: bash <(curl -sSL https://raw.githubusercontent.com/pookasec/fomorian/main/install.sh)
#
# This script:
# 1. Checks Python version (3.9+)
# 2. Creates a virtual environment (optional)
# 3. Installs fomorian via pip
# 4. Verifies the installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "  ______                          _             "
    echo " |  ____|                        (_)            "
    echo " | |__ ___  _ __ ___   ___  _ __  _  __ _ _ __  "
    echo " |  __/ _ \| '_ \` _ \ / _ \| '__|| |/ _\` | '_ \ "
    echo " | | | (_) | | | | | | (_) | |   | | (_| | | | |"
    echo " |_|  \___/|_| |_| |_|\___/|_|   |_|\__,_|_| |_|"
    echo ""
    echo " Attack Scenario Generator for Wazuh SIEM Testing"
    echo -e "${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python() {
    echo -e "${BLUE}Checking Python version...${NC}"

    # Try python3 first, then python
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        echo -e "${RED}Error: Python is not installed.${NC}"
        echo "Please install Python 3.9 or higher."
        exit 1
    fi

    # Check version
    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.minor)')

    if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 9 ]]; then
        echo -e "${RED}Error: Python 3.9+ is required. Found Python $PYTHON_VERSION${NC}"
        exit 1
    fi

    echo -e "${GREEN}Found Python $PYTHON_VERSION${NC}"
}

# Check pip
check_pip() {
    echo -e "${BLUE}Checking pip...${NC}"

    if ! $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        echo -e "${YELLOW}pip not found. Attempting to install...${NC}"
        $PYTHON_CMD -m ensurepip --upgrade || {
            echo -e "${RED}Error: Could not install pip. Please install pip manually.${NC}"
            exit 1
        }
    fi

    echo -e "${GREEN}pip is available${NC}"
}

# Ask about virtual environment
setup_venv() {
    echo ""
    echo -e "${YELLOW}Would you like to install Fomorian in a virtual environment?${NC}"
    echo "This is recommended to avoid conflicts with other Python packages."
    echo ""
    read -p "Create virtual environment? [Y/n]: " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        VENV_DIR="${HOME}/.fomorian/venv"

        echo -e "${BLUE}Creating virtual environment at $VENV_DIR...${NC}"
        mkdir -p "$(dirname "$VENV_DIR")"
        $PYTHON_CMD -m venv "$VENV_DIR"

        # Activate venv
        source "$VENV_DIR/bin/activate"
        PYTHON_CMD="python"

        echo -e "${GREEN}Virtual environment created and activated${NC}"

        # Note about activation
        echo ""
        echo -e "${YELLOW}Note: To use Fomorian in future sessions, activate the venv first:${NC}"
        echo "  source $VENV_DIR/bin/activate"
        echo ""
    fi
}

# Install Fomorian
install_fomorian() {
    echo -e "${BLUE}Installing Fomorian...${NC}"

    # Upgrade pip first
    $PYTHON_CMD -m pip install --upgrade pip

    # Install fomorian
    $PYTHON_CMD -m pip install fomorian

    echo -e "${GREEN}Fomorian installed successfully!${NC}"
}

# Install from source (development)
install_from_source() {
    echo -e "${BLUE}Installing Fomorian from source...${NC}"

    # Clone repo if not already in it
    if [[ ! -f "pyproject.toml" ]]; then
        INSTALL_DIR="${HOME}/.fomorian/src"
        mkdir -p "$INSTALL_DIR"
        cd "$INSTALL_DIR"

        if [[ -d "fomorian" ]]; then
            echo "Updating existing source..."
            cd fomorian
            git pull
        else
            echo "Cloning repository..."
            git clone https://github.com/pookasecteam/fomorian-community.git
            cd fomorian
        fi
    fi

    # Install in editable mode
    $PYTHON_CMD -m pip install -e .

    echo -e "${GREEN}Fomorian installed from source!${NC}"
}

# Verify installation
verify_installation() {
    echo ""
    echo -e "${BLUE}Verifying installation...${NC}"

    if command_exists fomorian; then
        FOMORIAN_VERSION=$(fomorian --version 2>/dev/null | head -1)
        echo -e "${GREEN}Installation verified: $FOMORIAN_VERSION${NC}"
        return 0
    else
        echo -e "${RED}Error: fomorian command not found in PATH${NC}"
        echo "You may need to:"
        echo "  1. Activate the virtual environment: source ~/.fomorian/venv/bin/activate"
        echo "  2. Or add the install location to your PATH"
        return 1
    fi
}

# Print next steps
print_next_steps() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}  Fomorian Installation Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Run the setup wizard:"
    echo -e "     ${BLUE}fomorian wizard${NC}"
    echo ""
    echo "  2. Or quick setup with defaults:"
    echo -e "     ${BLUE}fomorian wizard quick${NC}"
    echo ""
    echo "  3. Or generate a random scenario:"
    echo -e "     ${BLUE}fomorian wizard random --complexity medium${NC}"
    echo ""
    echo "Documentation: https://github.com/pookasecteam/fomorian-community"
    echo ""
}

# Main installation flow
main() {
    print_banner

    # Parse arguments
    FROM_SOURCE=false
    for arg in "$@"; do
        case $arg in
            --from-source)
                FROM_SOURCE=true
                shift
                ;;
            --help|-h)
                echo "Usage: install.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --from-source    Install from source (for development)"
                echo "  --help, -h       Show this help message"
                exit 0
                ;;
        esac
    done

    check_python
    check_pip
    setup_venv

    if [[ "$FROM_SOURCE" == true ]]; then
        install_from_source
    else
        install_fomorian
    fi

    verify_installation
    print_next_steps
}

# Run main
main "$@"
