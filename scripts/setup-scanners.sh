#!/usr/bin/env bash
set -euo pipefail

echo "Installing DefenseClaw scanner dependencies..."
echo ""

# Check for uv (recommended) or fall back to pip
if command -v uv &> /dev/null; then
    INSTALLER="uv pip install"
    echo "Using uv as package manager."
else
    INSTALLER="pip install"
    echo "Using pip as package manager. Consider installing uv: https://docs.astral.sh/uv/"
    pip install --upgrade pip
fi

echo ""
echo "Installing skill-scanner (cisco-ai-skill-scanner)..."
$INSTALLER cisco-ai-skill-scanner

echo ""
echo "Installing mcp-scanner (cisco-ai-mcp-scanner)..."
$INSTALLER cisco-ai-mcp-scanner

echo ""
echo "Installing aibom (cisco-aibom)..."
$INSTALLER cisco-aibom

echo ""
echo "Scanner dependencies installed."
echo ""
echo "Verify installation:"
echo "  skill-scanner --help"
echo "  mcp-scanner --help"
echo "  cisco-aibom --help"
echo ""
echo "Note: AI BOM requires a DuckDB catalog. See README.md for setup instructions."
echo "Note: Project CodeGuard rules are installed separately. See README.md."
