#!/usr/bin/env bash

# Create the file test
../mfdsafe.py dummy.mfd -o test.mfd -v
../mfdsafe.py dummy.mfd -t transport -o transport-test.mfd -v
../mfdsafe.py dummy.mfd -t default -o default-test.mfd -v

# Check files with correct safe output files
cmp --silent safe-test.mfd test.mfd || echo "Safe test file check failed..."
cmp --silent safe-transport-test.mfd transport-test.mfd || echo "Safe test file check failed..."
cmp --silent safe-default-test.mfd default-test.mfd || echo "Safe test file check failed..."
