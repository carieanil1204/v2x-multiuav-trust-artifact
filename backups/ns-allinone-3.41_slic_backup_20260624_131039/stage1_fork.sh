#!/bin/bash
#
# stage1_fork.sh
#
# Mechanically forks NS-3's standard AODV into src/slic-aodv2/
# with namespace/class rename. After running this:
#   - The new module compiles
#   - It behaves identically to standard AODV
#   - Protocol typeid is "ns3::slic_aodv2::SlicAodvRoutingProtocol"
#   - Existing src/slic-aodv/ is UNTOUCHED
#
# Run from NS-3 root directory.
#
set -e

NS3_ROOT="$(pwd)"
SRC_AODV="$NS3_ROOT/src/aodv"
DST="$NS3_ROOT/src/slic-aodv2"

if [ ! -d "$SRC_AODV" ]; then
  echo "ERROR: $SRC_AODV not found. Run from NS-3 root." >&2
  exit 1
fi

if [ -d "$DST" ]; then
  echo "ERROR: $DST already exists. Remove it first:" >&2
  echo "  rm -rf $DST" >&2
  exit 1
fi

echo "=== Stage 1: Creating src/slic-aodv2/ as a clean fork of src/aodv/ ==="

# Create directory structure
mkdir -p "$DST/model" "$DST/helper" "$DST/test" "$DST/examples"

# ─── Copy files with rename ──────────────────────────────────────
# We copy EVERY source file unchanged, then do a global rename pass.

echo "[1/4] Copying model files..."
for f in aodv-routing-protocol aodv-packet aodv-rtable aodv-rqueue \
         aodv-neighbor aodv-id-cache aodv-dpd; do
  cp "$SRC_AODV/model/$f.h"  "$DST/model/slic-$f.h"  || true
  cp "$SRC_AODV/model/$f.cc" "$DST/model/slic-$f.cc" || true
done

echo "[2/4] Copying helper files..."
cp "$SRC_AODV/helper/aodv-helper.h"  "$DST/helper/slic-aodv-helper.h"
cp "$SRC_AODV/helper/aodv-helper.cc" "$DST/helper/slic-aodv-helper.cc"

# ─── Global rename inside those files ────────────────────────────
# 1) namespace aodv      → namespace slic_aodv2
# 2) TypeId strings      : ns3::aodv::     → ns3::slic_aodv2::
# 3) Include-guard names : AODV_*          → SLIC_AODV2_* (header files)
# 4) Header includes     : "aodv-*.h"      → "slic-aodv-*.h"
# 5) ns3 headers         : "ns3/aodv-*.h"  → "ns3/slic-aodv-*.h"
# 6) Class rename        : RoutingProtocol → SlicAodvRoutingProtocol
#                          AodvHelper      → SlicAodvHelper
# 7) Log component       : "AodvRouting..." → "SlicAodvRouting..."

echo "[3/4] Renaming namespaces and class names..."
cd "$DST"

# Find all our copied source files
FILES=$(find . -type f \( -name "*.cc" -o -name "*.h" \))

for f in $FILES; do
  # (6) Class rename — do this FIRST before namespace rename, because
  # the class is 'RoutingProtocol' (generic name), and renaming after
  # namespace change would catch unintended matches.
  # We only rename it when it's inside the aodv namespace — easy way:
  # use the fully-qualified form 'aodv::RoutingProtocol' first.
  sed -i 's/aodv::RoutingProtocol/aodv::SlicAodvRoutingProtocolTmp/g' "$f"
  # Now the unqualified RoutingProtocol inside the aodv namespace
  # must also be renamed.  We'll do it via the namespace open context.
  # The class is defined only in aodv-routing-protocol.h/cc, so scope
  # rename to those files.
  case "$f" in
    *slic-aodv-routing-protocol.h|*slic-aodv-routing-protocol.cc)
      # Rename the bare 'RoutingProtocol' identifier (class name and
      # method scope) only in these two files.
      sed -i 's/\bRoutingProtocol\b/SlicAodvRoutingProtocolTmp/g' "$f"
      ;;
  esac

  # (1) Namespace rename: 'namespace aodv' → 'namespace slic_aodv2'
  sed -i 's/\bnamespace aodv\b/namespace slic_aodv2/g' "$f"
  sed -i 's/\baodv::/slic_aodv2::/g' "$f"

  # (Finalize the temp class name)
  sed -i 's/SlicAodvRoutingProtocolTmp/SlicAodvRoutingProtocol/g' "$f"

  # (6) Helper class rename
  sed -i 's/\bAodvHelper\b/SlicAodvHelper/g' "$f"

  # (2) TypeId strings
  sed -i 's|ns3::aodv::|ns3::slic_aodv2::|g' "$f"
  sed -i 's|"Aodv"|"SlicAodv2"|g' "$f"     # GroupName

  # (7) Log components
  sed -i 's/\bAodvRoutingProtocol\b/SlicAodvRoutingProtocol/g' "$f"

  # (4)(5) Includes
  sed -i 's|#include "aodv-|#include "slic-aodv-|g' "$f"
  sed -i 's|#include "ns3/aodv-|#include "ns3/slic-aodv-|g' "$f"

  # (3) Include guards
  sed -i 's/\bAODV_ROUTING_PROTOCOL_H\b/SLIC_AODV2_ROUTING_PROTOCOL_H/g' "$f"
  sed -i 's/\bAODVROUTINGPROTOCOL_H\b/SLIC_AODV2_ROUTING_PROTOCOL_H/g' "$f"
  sed -i 's/\bAODV_PACKET_H\b/SLIC_AODV2_PACKET_H/g' "$f"
  sed -i 's/\bAODV_RTABLE_H\b/SLIC_AODV2_RTABLE_H/g' "$f"
  sed -i 's/\bAODV_RQUEUE_H\b/SLIC_AODV2_RQUEUE_H/g' "$f"
  sed -i 's/\bAODV_NEIGHBOR_H\b/SLIC_AODV2_NEIGHBOR_H/g' "$f"
  sed -i 's/\bAODV_ID_CACHE_H\b/SLIC_AODV2_ID_CACHE_H/g' "$f"
  sed -i 's/\bAODV_DPD_H\b/SLIC_AODV2_DPD_H/g' "$f"
  sed -i 's/\bAODV_HELPER_H\b/SLIC_AODV2_HELPER_H/g' "$f"
done

# ─── CMakeLists.txt ──────────────────────────────────────────────
echo "[4/4] Writing CMakeLists.txt..."

cat > "$DST/CMakeLists.txt" <<'CMAKE'
build_lib(
    LIBNAME slic-aodv2
    SOURCE_FILES
        model/slic-aodv-dpd.cc
        model/slic-aodv-id-cache.cc
        model/slic-aodv-neighbor.cc
        model/slic-aodv-packet.cc
        model/slic-aodv-routing-protocol.cc
        model/slic-aodv-rqueue.cc
        model/slic-aodv-rtable.cc
        helper/slic-aodv-helper.cc
    HEADER_FILES
        model/slic-aodv-dpd.h
        model/slic-aodv-id-cache.h
        model/slic-aodv-neighbor.h
        model/slic-aodv-packet.h
        model/slic-aodv-routing-protocol.h
        model/slic-aodv-rqueue.h
        model/slic-aodv-rtable.h
        helper/slic-aodv-helper.h
    LIBRARIES_TO_LINK
        ${libinternet}
        ${libwifi}
)
CMAKE

cd "$NS3_ROOT"
echo ""
echo "=== Stage 1 complete. ==="
echo ""
echo "Next steps:"
echo "  1) ./ns3 configure --enable-tests --enable-examples"
echo "  2) ./ns3 build 2>&1 | tail -50"
echo ""
echo "If it builds clean, run Stage 1 verification:"
echo "  cd $DST"
echo "  grep -r 'namespace slic_aodv2' --include='*.h' | wc -l  # should be ~8"
echo "  grep -r 'class SlicAodvRoutingProtocol' --include='*.h'"
echo ""
echo "If build errors appear, paste the output and we iterate before Stage 2."
