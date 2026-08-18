#include "kuara_internal.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

static bool LoadFacts(const std::string& path, kuara::ScanFacts* out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;
    nlohmann::json j;
    f >> j;
    out->has_com = j.value("has_com", false);
    out->overlay = j.value("overlay", false);
    out->tls = j.value("tls", false);
    out->tls_callbacks = j.value("tls_callbacks", false);
    out->linker_major = (uint16_t)j.value("linker_major", 0);
    out->linker_minor = (uint16_t)j.value("linker_minor", 0);
    out->entry_rva = (uint32_t)j.value("entry_rva", 0);
    out->import_dll_n = j.value("import_dll_n", 0);
    if (j.contains("import_dlls") && j["import_dlls"].is_array())
        for (const auto& v : j["import_dlls"]) out->import_dlls.push_back(v.get<std::string>());
    if (j.contains("import_fns") && j["import_fns"].is_array())
        for (const auto& v : j["import_fns"]) out->import_fns.push_back(v.get<std::string>());
    if (j.contains("exports") && j["exports"].is_array())
        for (const auto& v : j["exports"]) out->exports.push_back(v.get<std::string>());
    if (j.contains("resource_types") && j["resource_types"].is_array())
        for (const auto& v : j["resource_types"]) out->resource_types.push_back(v.get<std::string>());
    if (j.contains("resource_names") && j["resource_names"].is_array())
        for (const auto& v : j["resource_names"]) out->resource_names.push_back(v.get<std::string>());
    if (j.contains("strings") && j["strings"].is_array())
        for (const auto& v : j["strings"]) out->strings.push_back(v.get<std::string>());
    if (j.contains("clr_streams") && j["clr_streams"].is_array())
        for (const auto& v : j["clr_streams"]) out->clr_streams.push_back(v.get<std::string>());
    if (j.contains("clr_asm_refs") && j["clr_asm_refs"].is_array())
        for (const auto& v : j["clr_asm_refs"]) out->clr_asm_refs.push_back(v.get<std::string>());
    if (j.contains("clr_types") && j["clr_types"].is_array())
        for (const auto& v : j["clr_types"]) out->clr_types.push_back(v.get<std::string>());
    if (j.contains("clr_namespaces") && j["clr_namespaces"].is_array())
        for (const auto& v : j["clr_namespaces"]) out->clr_namespaces.push_back(v.get<std::string>());
    if (j.contains("sections") && j["sections"].is_array())
    {
        for (const auto& s : j["sections"])
        {
            kuara::SectionFact sf{};
            sf.name = s.value("name", "");
            sf.chars = (uint32_t)s.value("chars", 0);
            sf.vsize = (uint32_t)s.value("vsize", 0);
            sf.vaddr = (uint32_t)s.value("vaddr", 0);
            sf.rawsize = (uint32_t)s.value("rawsize", 0);
            sf.rawptr = (uint32_t)s.value("rawptr", 0);
            sf.entropy = s.value("entropy", 0.0);
            out->sections.push_back(std::move(sf));
        }
    }
    return true;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::cout << "KUARA CLI (" << kuara::EngineId() << ")\n";
        std::cout << "usage:\n";
        std::cout << "  kuara validate <rules.json>\n";
        std::cout << "  kuara scan <rules.json> <facts.json>\n";
        std::cout << "  kuara explain <rules.json> <facts.json> <rule_id>\n";
        return 1;
    }

    const std::string cmd = argv[1];
    kuara::RuleSet rules{};
    std::vector<kuara::Diagnostic> diags;
    if (!kuara::LoadRuleSetFromFile(argv[2], &rules, &diags))
    {
        for (const auto& d : diags) std::cout << "[error] " << d.source << ": " << d.message << "\n";
        return 2;
    }
    kuara::CompiledRuleSet compiled{};
    if (!kuara::CompileRuleSet(rules, &compiled, &diags))
    {
        for (const auto& d : diags) std::cout << "[error] " << d.source << ": " << d.message << "\n";
        return 3;
    }

    if (cmd == "validate")
    {
        std::cout << "OK: " << compiled.rules.size() << " rule(s)\n";
        return 0;
    }
    if (argc < 4)
        return 1;
    kuara::ScanFacts facts{};
    if (!LoadFacts(argv[3], &facts))
    {
        std::cout << "[error] cannot load facts: " << argv[3] << "\n";
        return 4;
    }
    if (cmd == "scan")
    {
        std::vector<kuara::Match> matches;
        kuara::Scan(compiled, facts, &matches);
        nlohmann::json out = nlohmann::json::array();
        for (const auto& m : matches)
        {
            nlohmann::json one;
            one["id"] = m.rule_id;
            one["product"] = m.product;
            one["product_key"] = m.product_key;
            one["score"] = m.score;
            one["confidence"] = m.confidence;
            one["evidence_count"] = m.evidence.size();
            out.push_back(one);
        }
        std::cout << out.dump(2) << "\n";
        return 0;
    }
    if (cmd == "explain")
    {
        if (argc < 5)
            return 1;
        std::vector<kuara::Diagnostic> trace;
        kuara::Explain(compiled, facts, argv[4], &trace);
        for (const auto& t : trace)
            std::cout << (t.error ? "[state] " : "[evidence] ") << t.source << ": " << t.message << "\n";
        return 0;
    }
    return 1;
}

