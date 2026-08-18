#pragma once

#include <stdint.h>
#include <string>
#include <vector>

namespace kuara
{
enum class Category : uint8_t
{
    Packer = 0,
    Protector,
    Compiler,
    Toolchain,
    DotNetObfuscator
};

enum class MatchMode : uint8_t
{
    Exact = 0,
    Contains,
    Prefix
};

struct SectionFact
{
    std::string name;
    uint32_t chars = 0;
    uint32_t vsize = 0;
    uint32_t vaddr = 0;
    uint32_t rawsize = 0;
    uint32_t rawptr = 0;
    double entropy = 0.0;
};

struct ScanFacts
{
    bool is_pe = true;
    bool pe32plus = false;
    bool has_com = false;
    bool overlay = false;
    bool tls = false;
    bool tls_callbacks = false;
    uint16_t linker_major = 0;
    uint16_t linker_minor = 0;
    uint16_t machine = 0;
    uint16_t chars = 0;
    uint16_t dllchars = 0;
    uint32_t entry_rva = 0;
    uint64_t entry_off = 0;
    uint64_t overlay_off = 0;
    uint64_t overlay_size = 0;
    int import_dll_n = 0;

    std::vector<SectionFact> sections;
    std::vector<uint16_t> rich_prod;
    std::vector<uint16_t> rich_build;
    std::vector<std::string> import_dlls;
    std::vector<std::string> import_fns;
    std::vector<std::string> exports;
    std::vector<std::string> resource_types;
    std::vector<std::string> resource_names;
    std::vector<std::string> version_kv;
    std::vector<std::string> strings;
    std::vector<std::string> clr_streams;
    std::vector<std::string> clr_asm_refs;
    std::vector<std::string> clr_types;
    std::vector<std::string> clr_namespaces;
    const uint8_t* bytes = nullptr;
    size_t byte_n = 0;
};

struct Evidence
{
    std::string condition;
    std::string detail;
    int weight = 0;
};

struct Match
{
    std::string rule_id;
    std::string product_key;
    std::string product;
    std::string vendor;
    std::string version;
    std::string description;
    std::string reference;
    Category category = Category::Packer;
    int score = 0;
    int confidence = 0;
    bool heuristic = false;
    std::vector<Evidence> evidence;
};

struct Diagnostic
{
    std::string source;
    std::string message;
    bool error = true;
};

struct RuleSet;
struct CompiledRuleSet;

bool LoadRuleSetFromFile(const std::string& path, RuleSet* out_rules, std::vector<Diagnostic>* out_diags);
bool ValidateRuleSet(const RuleSet& rules, std::vector<Diagnostic>* out_diags);
bool CompileRuleSet(const RuleSet& rules, CompiledRuleSet* out_compiled, std::vector<Diagnostic>* out_diags);
bool Scan(const CompiledRuleSet& compiled, const ScanFacts& facts, std::vector<Match>* out_matches);
bool Explain(const CompiledRuleSet& compiled, const ScanFacts& facts, const std::string& rule_id, std::vector<Diagnostic>* out_trace);
const char* EngineId();
const char* EngineVersion();
const char* EngineAuthor();
const char* BrandImageUrl();
} // namespace kuara

