#pragma once

#include "kuara/kuara.h"

#include <nlohmann/json.hpp>

namespace kuara
{
enum class NodeKind : uint8_t
{
    All = 0,
    Any,
    Not,
    Leaf
};

enum class LeafKind : uint8_t
{
    Unknown = 0,
    SectionName,
    SectionCount,
    SectionChars,
    SectionEntropy,
    SectionRawSize,
    ImportedDll,
    ImportedFn,
    Exported,
    VersionString,
    ResourceType,
    ResourceName,
    StringContains,
    HasCom,
    ClrStream,
    AsmRef,
    TypeName,
    Namespace,
    LinkerMajor,
    LinkerMinor,
    ImportDllCount,
    WxSection,
    Overlay,
    BytePattern,
    Tls,
    TlsCallbacks,
    VirtualOnlyBeforeEntry,
    EntrySectionChars,
    EntrySectionRawSize,
    EntrySectionEntropy
};

struct Leaf
{
    LeafKind kind = LeafKind::Unknown;
    MatchMode mode = MatchMode::Exact;
    std::string a;
    std::string b;
    int i0 = 0;
    int i1 = 0;
    double f0 = 0.0;
    int weight = 0;
    std::vector<uint8_t> pat_bytes;
    std::vector<uint8_t> pat_mask;
    std::string where;
};

struct CondNode
{
    NodeKind kind = NodeKind::Leaf;
    Leaf leaf;
    std::vector<CondNode> children;
};

struct Rule
{
    int schema_version = 1;
    std::string id;
    std::string name;
    std::string product_key;
    std::string vendor;
    std::string version;
    std::string description;
    std::string reference;
    bool heuristic = false;
    int confidence = 2;
    Category category = Category::Packer;
    CondNode root;
};

struct RuleSet
{
    std::vector<Rule> rules;
};

struct CompiledRule
{
    Rule rule;
};

struct CompiledRuleSet
{
    std::vector<CompiledRule> rules;
};

bool ParseRuleJson(const nlohmann::json& j, Rule* out, std::vector<Diagnostic>* out_diags, const std::string& source_name);
bool EvalRule(const CompiledRule& cr, const ScanFacts& facts, Match* out_match);
bool ExplainRule(const CompiledRule& cr, const ScanFacts& facts, std::vector<Diagnostic>* out_trace);
} // namespace kuara

