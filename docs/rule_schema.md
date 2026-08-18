# KUARA Rule Schema (v1)

KUARA v1 accepts BinarySectorInspector signature JSON schema (`schema_version: 1`) for migration safety.

## Required

- `schema_version` = `1`
- `id`
- `name`
- `category`
- `conditions`

## Supported category values

- `packer`
- `protector`
- `compiler`
- `toolchain`
- `dotnet_obfuscator`

## Condition model

Logical groups:

- `{ "all": [ ... ] }`
- `{ "any": [ ... ] }`
- `{ "not": { ... } }`

Supported leaf keys in baseline:

- `section_name`
- `section_count`
- `section_chars`
- `section_entropy`
- `section_raw_size`
- `imported_dll`
- `imported_function`
- `exported_function`
- `resource_type`
- `resource_name`
- `string_contains`
- `has_com`
- `clr_stream`
- `assembly_ref`
- `type_name`
- `namespace`
- `linker_major`
- `linker_minor`
- `import_dll_count`
- `writable_executable_section`
- `overlay`
- `tls`
- `tls_callbacks`
- `virtual_only_before_entry`
- `entry_section_chars`
- `entry_section_raw_size`
- `entry_section_entropy`

