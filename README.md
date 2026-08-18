# KUARA Dynamic Engine

Stable engine id: `com.candestan.kuara`

KUARA is an independent, offline, first-party rule engine for static detection and evidence collection.
It is not a wrapper around YARA and has no YARA runtime dependency.

## Scope

- JSON rule/signature loading
- Rule validation and compilation
- Deterministic matching
- Evidence-first output
- Explain mode (`why matched / why not`)

## Rule compatibility

KUARA accepts BinarySectorInspector-style JSON signatures (`schema_version: 1`) as first-class inputs.
This allows teams to migrate without rewriting all existing signatures.

## Build

Requirements:

- Windows x64
- Visual Studio 2022
- MSBuild v143
- C++17

Before building, initialize third-party dependencies:

```powershell
git submodule update --init --recursive
```

Build:

```powershell
MSBuild.exe KUARA-Dynamic.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## CLI

```text
kuara validate <rules.json>
kuara scan <rules.json> <facts.json>
kuara explain <rules.json> <facts.json> <rule_id>
```

See `examples/`.

## Architecture

- Parser: `src/rule_parser.cpp`
- Validator/Compiler: `src/rule_validator.cpp`
- Matcher: `src/matcher.cpp`
- Engine API: `include/kuara/kuara.h`, `src/engine.cpp`

## Status

Initial standalone baseline focused on BSI JSON compatibility and deterministic evidence output.

