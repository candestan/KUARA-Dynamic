#include "kuara_internal.h"

#include <algorithm>
#include <string.h>

namespace kuara
{
static bool IContains(const std::string& a, const std::string& b)
{
    if (b.empty())
        return false;
    auto it = std::search(a.begin(), a.end(), b.begin(), b.end(), [](char x, char y) {
        return (char)tolower((unsigned char)x) == (char)tolower((unsigned char)y);
    });
    return it != a.end();
}

static bool SMatch(MatchMode m, const std::string& have, const std::string& want)
{
    if (m == MatchMode::Exact)
        return _stricmp(have.c_str(), want.c_str()) == 0;
    if (m == MatchMode::Prefix)
        return _strnicmp(have.c_str(), want.c_str(), (int)want.size()) == 0;
    return IContains(have, want);
}

static int EntrySectionIndex(const ScanFacts& facts)
{
    if (!facts.entry_rva)
        return -1;
    for (int i = 0; i < (int)facts.sections.size(); i++)
    {
        const SectionFact& s = facts.sections[(size_t)i];
        if (facts.entry_rva >= s.vaddr && facts.entry_rva < s.vaddr + s.vsize)
            return i;
    }
    return -1;
}

static bool EvalLeaf(const Leaf& c, const ScanFacts& facts, Evidence* ev)
{
    ev->condition = "unknown";
    ev->weight = c.weight;
    auto pat_at = [&](size_t off) -> bool {
        if (c.pat_bytes.empty() || !facts.bytes || off + c.pat_bytes.size() > facts.byte_n)
            return false;
        for (size_t i = 0; i < c.pat_bytes.size(); i++)
        {
            if (c.pat_mask[i] && facts.bytes[off + i] != c.pat_bytes[i])
                return false;
        }
        return true;
    };
    auto pat_scan = [&](size_t from, size_t to) -> bool {
        if (c.pat_bytes.empty() || !facts.bytes || to > facts.byte_n || to < from + c.pat_bytes.size())
            return false;
        size_t last = to - c.pat_bytes.size();
        for (size_t i = from; i <= last; i++)
        {
            if (pat_at(i))
                return true;
        }
        return false;
    };

    switch (c.kind)
    {
    case LeafKind::SectionName:
        for (const SectionFact& s : facts.sections)
            if (SMatch(c.mode, s.name, c.a)) { ev->condition = "section_name"; ev->detail = s.name; return true; }
        return false;
    case LeafKind::SectionCount:
        ev->condition = "section_count";
        ev->detail = std::to_string(facts.sections.size());
        return (int)facts.sections.size() >= c.i0 && (int)facts.sections.size() <= c.i1;
    case LeafKind::SectionChars:
        for (const SectionFact& s : facts.sections)
        {
            if (!c.a.empty() && _stricmp(s.name.c_str(), c.a.c_str()) != 0)
                continue;
            if ((s.chars & (uint32_t)c.i0) == (uint32_t)c.i0) { ev->condition = "section_chars"; ev->detail = s.name; return true; }
        }
        return false;
    case LeafKind::SectionEntropy:
        for (const SectionFact& s : facts.sections)
        {
            if (!c.a.empty() && !SMatch(MatchMode::Contains, s.name, c.a))
                continue;
            if (s.entropy >= c.f0) { ev->condition = "section_entropy"; ev->detail = s.name; return true; }
        }
        return false;
    case LeafKind::SectionRawSize:
        for (const SectionFact& s : facts.sections)
        {
            if (!c.a.empty() && _stricmp(s.name.c_str(), c.a.c_str()) != 0)
                continue;
            if ((int)s.rawsize >= c.i0 && (int)s.rawsize <= c.i1) { ev->condition = "section_raw_size"; ev->detail = s.name; return true; }
        }
        return false;
    case LeafKind::ImportedDll:
        for (const std::string& d : facts.import_dlls)
            if (SMatch(c.mode, d, c.a)) { ev->condition = "imported_dll"; ev->detail = d; return true; }
        return false;
    case LeafKind::ImportedFn:
        for (const std::string& fn : facts.import_fns)
            if (SMatch(c.mode, fn, c.a)) { ev->condition = "imported_function"; ev->detail = fn; return true; }
        return false;
    case LeafKind::Exported:
        for (const std::string& fn : facts.exports)
            if (SMatch(c.mode, fn, c.a)) { ev->condition = "exported_function"; ev->detail = fn; return true; }
        return false;
    case LeafKind::VersionString:
        for (const std::string& kv : facts.version_kv)
        {
            const bool key_ok = c.a.empty() || IContains(kv, c.a);
            const bool val_ok = c.b.empty() || IContains(kv, c.b);
            if (key_ok && val_ok) { ev->condition = "version_string"; ev->detail = kv; return true; }
        }
        return false;
    case LeafKind::ResourceType:
        for (const std::string& t : facts.resource_types)
            if (SMatch(c.mode, t, c.a)) { ev->condition = "resource_type"; ev->detail = t; return true; }
        return false;
    case LeafKind::ResourceName:
        for (const std::string& t : facts.resource_names)
            if (SMatch(c.mode, t, c.a)) { ev->condition = "resource_name"; ev->detail = t; return true; }
        return false;
    case LeafKind::StringContains:
        for (const std::string& s : facts.strings)
            if (IContains(s, c.a)) { ev->condition = "string_contains"; ev->detail = c.a; return true; }
        return false;
    case LeafKind::HasCom: ev->condition = "has_com"; return facts.has_com == (c.i0 != 0);
    case LeafKind::ClrStream:
        for (const std::string& s : facts.clr_streams)
            if (SMatch(c.mode, s, c.a)) { ev->condition = "clr_stream"; ev->detail = s; return true; }
        return false;
    case LeafKind::AsmRef:
        for (const std::string& s : facts.clr_asm_refs)
            if (SMatch(c.mode, s, c.a)) { ev->condition = "assembly_ref"; ev->detail = s; return true; }
        return false;
    case LeafKind::TypeName:
        for (const std::string& s : facts.clr_types)
            if (SMatch(c.mode, s, c.a)) { ev->condition = "type_name"; ev->detail = s; return true; }
        return false;
    case LeafKind::Namespace:
        for (const std::string& s : facts.clr_namespaces)
            if (SMatch(c.mode, s, c.a)) { ev->condition = "namespace"; ev->detail = s; return true; }
        return false;
    case LeafKind::LinkerMajor: ev->condition = "linker_major"; return facts.linker_major == c.i0;
    case LeafKind::LinkerMinor: ev->condition = "linker_minor"; return facts.linker_minor == c.i0;
    case LeafKind::RichPresent:
        ev->condition = "rich_present";
        return (!facts.rich_prod.empty()) == (c.i0 != 0);
    case LeafKind::RichProd:
        ev->condition = "rich_prod";
        for (uint16_t p : facts.rich_prod)
            if (p == (uint16_t)c.i0) return true;
        return false;
    case LeafKind::RichBuild:
        ev->condition = "rich_build";
        for (uint16_t b : facts.rich_build)
            if (b == (uint16_t)c.i0) return true;
        return false;
    case LeafKind::ImportDllCount: ev->condition = "import_dll_count"; return facts.import_dll_n >= c.i0 && facts.import_dll_n <= c.i1;
    case LeafKind::WxSection:
    {
        bool wx = false;
        for (const SectionFact& s : facts.sections)
            if ((s.chars & 0x20000000u) && (s.chars & 0x80000000u)) { wx = true; break; }
        ev->condition = "writable_executable_section";
        return wx == (c.i0 != 0);
    }
    case LeafKind::Overlay:
        ev->condition = "overlay";
        if (c.i0 == 0)
            return !facts.overlay;
        if (!facts.overlay)
            return false;
        return c.i1 <= 0 || (int)facts.overlay_size >= c.i1;
    case LeafKind::BytePattern:
    {
        ev->condition = "byte_pattern";
        const std::string where = c.where.empty() ? "file" : c.where;
        if (where == "entry")
            return pat_at((size_t)facts.entry_off);
        if (where == "overlay")
            return facts.overlay && pat_scan((size_t)facts.overlay_off, (size_t)(facts.overlay_off + facts.overlay_size));
        return pat_scan(0, facts.byte_n);
    }
    case LeafKind::Tls: ev->condition = "tls"; return facts.tls == (c.i0 != 0);
    case LeafKind::TlsCallbacks: ev->condition = "tls_callbacks"; return facts.tls_callbacks == (c.i0 != 0);
    case LeafKind::VirtualOnlyBeforeEntry:
    {
        const int ep = EntrySectionIndex(facts);
        if (ep < 1)
            return false;
        int packed = 0;
        for (int i = 0; i < ep; i++)
        {
            const SectionFact& s = facts.sections[(size_t)i];
            if (s.rawsize == 0 && s.rawptr == 0 && (s.chars & 0x00000080u) == 0)
                packed++;
        }
        ev->condition = "virtual_only_before_entry";
        ev->detail = std::to_string(packed);
        return packed >= c.i0;
    }
    case LeafKind::EntrySectionChars:
    {
        const int ep = EntrySectionIndex(facts);
        if (ep < 0) return false;
        ev->condition = "entry_section_chars";
        return (facts.sections[(size_t)ep].chars & (uint32_t)c.i0) == (uint32_t)c.i0;
    }
    case LeafKind::EntrySectionRawSize:
    {
        const int ep = EntrySectionIndex(facts);
        if (ep < 0) return false;
        ev->condition = "entry_section_raw_size";
        int rs = (int)facts.sections[(size_t)ep].rawsize;
        return rs >= c.i0 && rs <= c.i1;
    }
    case LeafKind::EntrySectionEntropy:
    {
        const int ep = EntrySectionIndex(facts);
        if (ep < 0) return false;
        ev->condition = "entry_section_entropy";
        return facts.sections[(size_t)ep].entropy >= c.f0;
    }
    default:
        return false;
    }
}

static bool EvalNode(const CondNode& n, const ScanFacts& facts, std::vector<Evidence>* out_evidence)
{
    if (n.kind == NodeKind::Leaf)
    {
        Evidence e{};
        bool ok = EvalLeaf(n.leaf, facts, &e);
        if (ok)
            out_evidence->push_back(std::move(e));
        return ok;
    }
    if (n.kind == NodeKind::All)
    {
        for (const CondNode& c : n.children)
            if (!EvalNode(c, facts, out_evidence))
                return false;
        return true;
    }
    if (n.kind == NodeKind::Any)
    {
        std::vector<Evidence> branch_best;
        for (const CondNode& c : n.children)
        {
            std::vector<Evidence> tmp;
            if (EvalNode(c, facts, &tmp))
            {
                if (tmp.size() > branch_best.size())
                    branch_best = std::move(tmp);
            }
        }
        if (branch_best.empty())
            return false;
        out_evidence->insert(out_evidence->end(), branch_best.begin(), branch_best.end());
        return true;
    }
    if (n.kind == NodeKind::Not)
    {
        std::vector<Evidence> tmp;
        return n.children.empty() ? false : !EvalNode(n.children[0], facts, &tmp);
    }
    return false;
}

bool EvalRule(const CompiledRule& cr, const ScanFacts& facts, Match* out_match)
{
    std::vector<Evidence> ev;
    if (!EvalNode(cr.rule.root, facts, &ev))
        return false;
    Match m{};
    m.rule_id = cr.rule.id;
    m.product_key = cr.rule.product_key;
    m.product = cr.rule.name;
    m.vendor = cr.rule.vendor;
    m.version = cr.rule.version;
    m.description = cr.rule.description;
    m.reference = cr.rule.reference;
    m.category = cr.rule.category;
    m.heuristic = cr.rule.heuristic;
    m.confidence = cr.rule.confidence;
    m.evidence = std::move(ev);
    int score = 0;
    for (const Evidence& e : m.evidence)
        score += e.weight > 0 ? e.weight : 10;
    m.score = score;
    *out_match = std::move(m);
    return true;
}

bool Scan(const CompiledRuleSet& compiled, const ScanFacts& facts, std::vector<Match>* out_matches)
{
    out_matches->clear();
    for (const CompiledRule& cr : compiled.rules)
    {
        Match m{};
        if (EvalRule(cr, facts, &m))
            out_matches->push_back(std::move(m));
    }
    std::sort(out_matches->begin(), out_matches->end(), [](const Match& a, const Match& b) {
        if (a.score != b.score) return a.score > b.score;
        return a.rule_id < b.rule_id;
    });
    return true;
}

bool ExplainRule(const CompiledRule& cr, const ScanFacts& facts, std::vector<Diagnostic>* out_trace)
{
    Match m{};
    if (EvalRule(cr, facts, &m))
    {
        out_trace->push_back({cr.rule.id, "MATCHED", false});
        for (const Evidence& e : m.evidence)
            out_trace->push_back({cr.rule.id, e.condition + ": " + e.detail, false});
        return true;
    }
    out_trace->push_back({cr.rule.id, "NOT MATCHED", true});
    return false;
}
} // namespace kuara

