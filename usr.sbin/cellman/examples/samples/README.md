# Generic sample set

This directory intentionally stays small and practical. It demonstrates common
DSL patterns with short names and one clear role per file:

- `01-volumes.lua`: all sample volumes
- `02-cells.lua`: all sample cells
- `03-apply-web.lua`: basic web content + script + symlink + template
- `04-apply-script.lua`: script action with args/env and token rendering
- `05-apply-template.lua`: template-focused owner/group and token usage

Suggested sequence:

```sh
cellman apply --dry-run --all
doas cellman apply --all
cellman cell list --view merged
```
