#!/bin/bash

set -eu

Package="$1"

echo Pushing package "$Package"
dotnet nuget push -k "$NuGetApiKey" -s "$NuGetPushServer" "$Package"
