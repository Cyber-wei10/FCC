#!/bin/bash

VERSION=$(make kernelversion | cut -d '.' -f1)
SUBVER=$(make kernelversion | cut -d '.' -f2)

echo "[Checking] Current kernel major version: $VERSION"
echo "[Checking] Minor version: $SUBVER"

if [ "$VERSION" = "4" ] || ([ "$VERSION" = "5" ] && [ "$SUBVER" -le 5 ]); then
    echo "[Fixing] (Version 4.x or 5.0~5.5) continue fixing..."
else
    echo "[Fixing] Failed (Not met conditions) exit..."
    exit 0
fi

cd arch/x86/boot/compressed || exit 1

if [ -f "pagetable.c" ] && [ -f "pgtable_64.c" ]; then
    echo "[Matching] pagetable.c + pgtable_64.c"
    sed -i 's/^unsigned long __force_order;/extern unsigned long __force_order;/' pgtable_64.c
    echo "[Fixing] Modified pgtable_64.c"

elif [ -f "kaslr.c" ] && [ -f "kaslr_64.c" ]; then
    echo "[]kaslr.c + kaslr_64.c"
    sed -i 's/^unsigned long __force_order;/extern unsigned long __force_order;/' kaslr_64.c
    echo "[Fixing] Modified kaslr_64.c"


else
    echo "[Fixing] Failed (No file to fix)"
fi

echo -e "\n Fixed successfully!"
