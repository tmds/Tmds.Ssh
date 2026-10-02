# Documentation

https://tmds.github.io/Tmds.Ssh

## CI Feed

You can obtain packages from the CI NuGet feed: https://www.myget.org/F/tmds/api/v3/index.json.

## Contributing

### Public API tracking

The public API surface is tracked using `Microsoft.CodeAnalysis.PublicApiAnalyzers`. When you add or change public API, the build will emit `RS0016` warnings for undeclared members.

To update the API tracking file, run:

```sh
dotnet format analyzers src/Tmds.Ssh/Tmds.Ssh.csproj --diagnostics RS0016
```

This adds the new API entries to `src/Tmds.Ssh/PublicAPI.Unshipped.txt`. Commit the updated file alongside your code changes.

Note: all API entries are tracked in `PublicAPI.Unshipped.txt`. `PublicAPI.Shipped.txt` is kept empty.
