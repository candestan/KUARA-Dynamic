#include "kuara_internal.h"

#include <fstream>
#include <sstream>

namespace kuara
{
static bool ParseCategory(const std::string& s, Category* out)
{
    if (s == "packer") *out = Category::Packer;
    else if (s == "protector") *out = Category::Protector;
    else if (s == "compiler") *out = Category::Compiler;
    else if (s == "toolchain") *out = Category::Toolchain;
    else if (s == "dotnet_obfuscator" || s == "dotnet") *out = Category::DotNetObfuscator;
    else return false;
    return true;
}

static MatchMode ParseMode(const nlohmann::json& j)
{
    if (!j.contains("match") || !j["match"].is_string())
        return MatchMode::Exact;
    const std::string m = j["match"].get<std::string>();
    if (m == "contains") return MatchMode::Contains;
    if (m == "prefix") return MatchMode::Prefix;
    return MatchMode::Exact;
}

static bool ParseBytePattern(const std::string& text, std::vector<uint8_t>* out_bytes, std::vector<uint8_t>* out_mask)
{
    out_bytes->clear();
    out_mask->clear();
    std::istringstream iss(text);
    std::string tok;
    while (iss >> tok)
    {
        if (tok == "?" || tok == "??")
        {
            out_bytes->push_back(0);
            out_mask->push_back(0);
            continue;
        }
        if (tok.size() != 2)
            return false;
        char* end = nullptr;
        long v = strtol(tok.c_str(), &end, 16);
        if (!end || *end != 0 || v < 0 || v > 255)
            return false;
        out_bytes->push_back((uint8_t)v);
        out_mask->push_back(1);
    }
    return !out_bytes->empty();
}

static bool ParseCond(const nlohmann::json& j, CondNode* out, std::vector<Diagnostic>* diags, const std::string& src);

static bool ParseKids(const nlohmann::json& arr, NodeKind kind, CondNode* out, std::vector<Diagnostic>* diags, const std::string& src)
{
    if (!arr.is_array() || arr.empty())
    {
        diags->push_back({src, "logical condition must be non-empty array", true});
        return false;
    }
    out->kind = kind;
    for (const auto& kid : arr)
    {
        CondNode c{};
        if (!ParseCond(kid, &c, diags, src))
            return false;
        out->children.push_back(std::move(c));
    }
    return true;
}

static bool ParseLeaf(const nlohmann::json& j, CondNode* out, std::vector<Diagnostic>* diags, const std::string& src)
{
    Leaf leaf{};
    leaf.mode = ParseMode(j);
    leaf.weight = j.value("weight", 0);

    if (j.contains("section_name") && j["section_name"].is_string())
    {
        leaf.kind = LeafKind::SectionName;
        leaf.a = j["section_name"].get<std::string>();
    }
    else if (j.contains("section_count"))
    {
        leaf.kind = LeafKind::SectionCount;
        if (j["section_count"].is_number_integer())
            leaf.i0 = leaf.i1 = j["section_count"].get<int>();
        else if (j["section_count"].is_object())
        {
            leaf.i0 = j["section_count"].value("min", 0);
            leaf.i1 = j["section_count"].value("max", 0x7fffffff);
            if (j["section_count"].contains("eq"))
                leaf.i0 = leaf.i1 = j["section_count"]["eq"].get<int>();
        }
    }
    else if (j.contains("section_chars"))
    {
        leaf.kind = LeafKind::SectionChars;
        if (j["section_chars"].is_number_integer())
            leaf.i0 = j["section_chars"].get<int>();
        else if (j["section_chars"].is_object())
        {
            leaf.i0 = j["section_chars"].value("mask", 0);
            leaf.a = j["section_chars"].value("name", "");
        }
    }
    else if (j.contains("section_entropy") && j["section_entropy"].is_object())
    {
        leaf.kind = LeafKind::SectionEntropy;
        leaf.f0 = j["section_entropy"].value("min", 0.0);
        leaf.a = j["section_entropy"].value("name", "");
    }
    else if (j.contains("section_raw_size"))
    {
        leaf.kind = LeafKind::SectionRawSize;
        if (j["section_raw_size"].is_object())
        {
            leaf.a = j["section_raw_size"].value("name", "");
            leaf.i0 = j["section_raw_size"].value("min", 0);
            leaf.i1 = j["section_raw_size"].value("max", 0x7fffffff);
            if (j["section_raw_size"].contains("eq"))
                leaf.i0 = leaf.i1 = j["section_raw_size"]["eq"].get<int>();
        }
    }
    else if (j.contains("imported_dll") && j["imported_dll"].is_string())
    {
        leaf.kind = LeafKind::ImportedDll;
        leaf.a = j["imported_dll"].get<std::string>();
    }
    else if (j.contains("imported_function") && j["imported_function"].is_string())
    {
        leaf.kind = LeafKind::ImportedFn;
        leaf.a = j["imported_function"].get<std::string>();
        leaf.b = j.value("dll", "");
    }
    else if (j.contains("exported_function") && j["exported_function"].is_string())
    {
        leaf.kind = LeafKind::Exported;
        leaf.a = j["exported_function"].get<std::string>();
    }
    else if (j.contains("version_string") && j["version_string"].is_object())
    {
        leaf.kind = LeafKind::VersionString;
        leaf.a = j["version_string"].value("key", "");
        leaf.b = j["version_string"].value("contains", "");
    }
    else if (j.contains("resource_type") && j["resource_type"].is_string())
    {
        leaf.kind = LeafKind::ResourceType;
        leaf.a = j["resource_type"].get<std::string>();
    }
    else if (j.contains("resource_name") && j["resource_name"].is_string())
    {
        leaf.kind = LeafKind::ResourceName;
        leaf.a = j["resource_name"].get<std::string>();
    }
    else if (j.contains("string_contains") && j["string_contains"].is_string())
    {
        leaf.kind = LeafKind::StringContains;
        leaf.a = j["string_contains"].get<std::string>();
    }
    else if (j.contains("has_com") && j["has_com"].is_boolean())
    {
        leaf.kind = LeafKind::HasCom;
        leaf.i0 = j["has_com"].get<bool>() ? 1 : 0;
    }
    else if (j.contains("clr_stream") && j["clr_stream"].is_string())
    {
        leaf.kind = LeafKind::ClrStream;
        leaf.a = j["clr_stream"].get<std::string>();
    }
    else if (j.contains("assembly_ref") && j["assembly_ref"].is_string())
    {
        leaf.kind = LeafKind::AsmRef;
        leaf.a = j["assembly_ref"].get<std::string>();
    }
    else if (j.contains("type_name") && j["type_name"].is_string())
    {
        leaf.kind = LeafKind::TypeName;
        leaf.a = j["type_name"].get<std::string>();
    }
    else if (j.contains("namespace") && j["namespace"].is_string())
    {
        leaf.kind = LeafKind::Namespace;
        leaf.a = j["namespace"].get<std::string>();
    }
    else if (j.contains("linker_major"))
    {
        leaf.kind = LeafKind::LinkerMajor;
        leaf.i0 = j["linker_major"].get<int>();
    }
    else if (j.contains("linker_minor"))
    {
        leaf.kind = LeafKind::LinkerMinor;
        leaf.i0 = j["linker_minor"].get<int>();
    }
    else if (j.contains("rich_present") && j["rich_present"].is_boolean())
    {
        leaf.kind = LeafKind::RichPresent;
        leaf.i0 = j["rich_present"].get<bool>() ? 1 : 0;
    }
    else if (j.contains("rich_prod"))
    {
        leaf.kind = LeafKind::RichProd;
        leaf.i0 = j["rich_prod"].get<int>();
    }
    else if (j.contains("rich_build"))
    {
        leaf.kind = LeafKind::RichBuild;
        leaf.i0 = j["rich_build"].get<int>();
    }
    else if (j.contains("import_dll_count"))
    {
        leaf.kind = LeafKind::ImportDllCount;
        if (j["import_dll_count"].is_number_integer())
            leaf.i0 = leaf.i1 = j["import_dll_count"].get<int>();
        else if (j["import_dll_count"].is_object())
        {
            leaf.i0 = j["import_dll_count"].value("min", 0);
            leaf.i1 = j["import_dll_count"].value("max", 0x7fffffff);
            if (j["import_dll_count"].contains("eq"))
                leaf.i0 = leaf.i1 = j["import_dll_count"]["eq"].get<int>();
        }
    }
    else if (j.contains("writable_executable_section") && j["writable_executable_section"].is_boolean())
    {
        leaf.kind = LeafKind::WxSection;
        leaf.i0 = j["writable_executable_section"].get<bool>() ? 1 : 0;
    }
    else if (j.contains("overlay") && j["overlay"].is_boolean())
    {
        leaf.kind = LeafKind::Overlay;
        leaf.i0 = j["overlay"].get<bool>() ? 1 : 0;
    }
    else if (j.contains("overlay") && j["overlay"].is_object())
    {
        leaf.kind = LeafKind::Overlay;
        leaf.i0 = 1;
        leaf.i1 = j["overlay"].value("min_size", 1);
    }
    else if (j.contains("byte_pattern") && j["byte_pattern"].is_string())
    {
        leaf.kind = LeafKind::BytePattern;
        leaf.where = j.value("where", "file");
        if (!ParseBytePattern(j["byte_pattern"].get<std::string>(), &leaf.pat_bytes, &leaf.pat_mask))
        {
            diags->push_back({src, "invalid byte_pattern", true});
            return false;
        }
    }
    else if (j.contains("entry_point_bytes") && j["entry_point_bytes"].is_string())
    {
        leaf.kind = LeafKind::BytePattern;
        leaf.where = "entry";
        if (!ParseBytePattern(j["entry_point_bytes"].get<std::string>(), &leaf.pat_bytes, &leaf.pat_mask))
        {
            diags->push_back({src, "invalid entry_point_bytes", true});
            return false;
        }
    }
    else if (j.contains("tls") && j["tls"].is_boolean())
    {
        leaf.kind = LeafKind::Tls;
        leaf.i0 = j["tls"].get<bool>() ? 1 : 0;
    }
    else if (j.contains("tls_callbacks") && j["tls_callbacks"].is_boolean())
    {
        leaf.kind = LeafKind::TlsCallbacks;
        leaf.i0 = j["tls_callbacks"].get<bool>() ? 1 : 0;
    }
    else if (j.contains("virtual_only_before_entry") && j["virtual_only_before_entry"].is_object())
    {
        leaf.kind = LeafKind::VirtualOnlyBeforeEntry;
        leaf.i0 = j["virtual_only_before_entry"].value("min", 1);
    }
    else if (j.contains("entry_section_chars") && j["entry_section_chars"].is_object())
    {
        leaf.kind = LeafKind::EntrySectionChars;
        leaf.i0 = j["entry_section_chars"].value("mask", 0);
    }
    else if (j.contains("entry_section_raw_size") && j["entry_section_raw_size"].is_object())
    {
        leaf.kind = LeafKind::EntrySectionRawSize;
        leaf.i0 = j["entry_section_raw_size"].value("min", 0);
        leaf.i1 = j["entry_section_raw_size"].value("max", 0x7fffffff);
        if (j["entry_section_raw_size"].contains("eq"))
            leaf.i0 = leaf.i1 = j["entry_section_raw_size"]["eq"].get<int>();
    }
    else if (j.contains("entry_section_entropy") && j["entry_section_entropy"].is_object())
    {
        leaf.kind = LeafKind::EntrySectionEntropy;
        leaf.f0 = j["entry_section_entropy"].value("min", 0.0);
    }
    else
    {
        diags->push_back({src, "unsupported condition leaf", true});
        return false;
    }

    out->kind = NodeKind::Leaf;
    out->leaf = std::move(leaf);
    return true;
}

static bool ParseCond(const nlohmann::json& j, CondNode* out, std::vector<Diagnostic>* diags, const std::string& src)
{
    if (!j.is_object())
    {
        diags->push_back({src, "condition node must be object", true});
        return false;
    }
    if (j.contains("all"))
        return ParseKids(j["all"], NodeKind::All, out, diags, src);
    if (j.contains("any"))
        return ParseKids(j["any"], NodeKind::Any, out, diags, src);
    if (j.contains("not"))
    {
        out->kind = NodeKind::Not;
        CondNode c{};
        if (!ParseCond(j["not"], &c, diags, src))
            return false;
        out->children.push_back(std::move(c));
        return true;
    }
    return ParseLeaf(j, out, diags, src);
}

bool ParseRuleJson(const nlohmann::json& j, Rule* out, std::vector<Diagnostic>* out_diags, const std::string& src)
{
    if (!j.is_object())
    {
        out_diags->push_back({src, "root must be object", true});
        return false;
    }
    Rule r{};
    r.schema_version = j.value("schema_version", 0);
    r.id = j.value("id", "");
    r.name = j.value("name", "");
    r.product_key = j.value("product_key", r.id);
    r.vendor = j.value("vendor", "");
    r.version = j.value("version", "");
    r.description = j.value("description", "");
    r.reference = j.value("reference", "");
    r.heuristic = j.value("heuristic", false);
    const std::string conf = j.value("confidence", "high");
    if (conf == "low") r.confidence = 0;
    else if (conf == "medium") r.confidence = 1;
    else if (conf == "high") r.confidence = 2;
    else if (conf == "exact") r.confidence = 3;
    std::string cat = j.value("category", "");
    if (!ParseCategory(cat, &r.category))
    {
        out_diags->push_back({src, "invalid category: " + cat, true});
        return false;
    }
    if (!j.contains("conditions"))
    {
        out_diags->push_back({src, "missing conditions", true});
        return false;
    }
    if (!ParseCond(j["conditions"], &r.root, out_diags, src))
        return false;
    *out = std::move(r);
    return true;
}

bool LoadRuleSetFromFile(const std::string& path, RuleSet* out_rules, std::vector<Diagnostic>* out_diags)
{
    out_rules->rules.clear();
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        out_diags->push_back({path, "cannot open file", true});
        return false;
    }
    nlohmann::json j;
    try
    {
        f >> j;
    }
    catch (const std::exception& ex)
    {
        out_diags->push_back({path, std::string("json parse failed: ") + ex.what(), true});
        return false;
    }
    if (j.is_array())
    {
        for (size_t i = 0; i < j.size(); i++)
        {
            Rule r{};
            std::string src = path + "#" + std::to_string(i);
            if (!ParseRuleJson(j[i], &r, out_diags, src))
                return false;
            out_rules->rules.push_back(std::move(r));
        }
    }
    else
    {
        Rule r{};
        if (!ParseRuleJson(j, &r, out_diags, path))
            return false;
        out_rules->rules.push_back(std::move(r));
    }
    return true;
}
} // namespace kuara

