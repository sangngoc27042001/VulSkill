#!/usr/bin/env bash
# Deploy the project (sample: G5 pattern, placeholder command only).
ENVIRONMENT=$1
echo "Deploying to $ENVIRONMENT"
# Vulnerable pattern: unquoted expansion of an argument inside a command.
make deploy TARGET=$ENVIRONMENT
