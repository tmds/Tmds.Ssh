# Documentation

This directory contains the DocFX configuration for generating API documentation.

## Building Locally

1. Install DocFX:
   ```bash
   dotnet tool install -g docfx
   ```

2. Generate and build documentation:
   ```bash
   cd src/docfx
   docfx metadata  # Generate API metadata
   docfx build     # Build the site
   ```

3. Serve locally:
   ```bash
   docfx serve ../../_site
   ```

Then open http://localhost:8080 in your browser.
